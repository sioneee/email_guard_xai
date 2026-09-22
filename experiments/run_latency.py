import argparse
import csv
import hashlib
import math
import random
import time
from pathlib import Path

import numpy as np

from adapters.knn295 import Knn295Detector
from explainers.proximity import build_explanation
from renderers.korean import render_explanation


DEFAULT_MANIFEST = Path(
    r"C:\email_guard_xai_data\manifests\manifest_pilot.csv"
)

DEFAULT_OUTPUT = Path(
    r"C:\email_guard_xai_data\results\latency_pilot.csv"
)


CLICK_RATES = [
    0.10,
    0.30,
    0.50,
    1.00,
]

VALID_VERDICTS = {
    "safe",
    "suspicious",
    "blocked",
}


def read_manifest(path):
    if not path.is_file():
        raise FileNotFoundError(
            f"manifest를 찾을 수 없습니다: {path}"
        )

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        rows = list(csv.DictReader(file))

    if not rows:
        raise RuntimeError("manifest에 데이터가 없습니다.")

    return rows


def load_samples(rows):
    """
    디스크 읽기 속도가 모델 실행시간에 섞이지 않도록
    실험 전에 파일을 메모리에 읽는다.
    """
    samples = []

    for row in rows:
        file_path = Path(row["path"])

        if not file_path.is_file():
            raise FileNotFoundError(
                f"파일을 찾을 수 없습니다: {file_path}"
            )

        file_bytes = file_path.read_bytes()

        samples.append({
            "sample_id": row["sample_id"],
            "path": str(file_path),
            "file_bytes": file_bytes,
            "sha256": hashlib.sha256(
                file_bytes
            ).hexdigest(),
        })

    return samples


def stable_click_order(sample_ids):
    """
    실행할 때마다 동일한 파일이 클릭 대상으로 선택되도록
    sample_id의 해시값을 기준으로 순서를 고정한다.
    """
    return sorted(
        sample_ids,
        key=lambda sample_id: hashlib.sha256(
            f"emailguard-click-{sample_id}".encode(
                "utf-8"
            )
        ).hexdigest(),
    )


def build_click_sets(suspicious_ids):
    ordered_ids = stable_click_order(
        suspicious_ids
    )

    click_sets = {}

    for rate in CLICK_RATES:
        if not ordered_ids:
            selected_count = 0
        else:
            selected_count = math.ceil(
                len(ordered_ids) * rate
            )

        click_sets[rate] = set(
            ordered_ids[:selected_count]
        )

    return click_sets


def should_explain(
    policy,
    sample_id,
    verdict,
    clicked_ids,
):
    if verdict not in VALID_VERDICTS:
        return False

    if policy == "explain_all":
        return True

    if policy == "explain_suspicious":
        return verdict == "suspicious"

    if policy == "click":
        return (
            verdict == "suspicious"
            and sample_id in clicked_ids
        )

    raise ValueError(f"알 수 없는 정책: {policy}")


def measure_policy(
    detector,
    samples,
    policy_name,
    policy_type,
    click_rate,
    clicked_ids,
    run_number,
    model_load_ms,
):
    detection_total_ms = 0.0
    explanation_total_ms = 0.0
    sample_total_times = []

    explanation_count = 0
    suspicious_count = 0
    error_count = 0

    wall_started = time.perf_counter()

    for sample in samples:
        sample_started = time.perf_counter()

        try:
            detection_started = time.perf_counter()

            analysis = detector.analyze(
                sample["file_bytes"]
            )

            detection_ms = (
                time.perf_counter()
                - detection_started
            ) * 1000

            detection_total_ms += detection_ms

            verdict = analysis.get("verdict", "")

            if verdict == "suspicious":
                suspicious_count += 1

            explain = should_explain(
                policy_type,
                sample["sample_id"],
                verdict,
                clicked_ids,
            )

            if explain:
                explanation_started = (
                    time.perf_counter()
                )

                technical = build_explanation(
                    detector,
                    sample["file_bytes"],
                )

                # 실제 서비스처럼 한국어 설명 생성까지 측정한다.
                render_explanation(technical)

                explanation_ms = (
                    time.perf_counter()
                    - explanation_started
                ) * 1000

                explanation_total_ms += (
                    explanation_ms
                )
                explanation_count += 1

            if verdict not in VALID_VERDICTS:
                error_count += 1

        except Exception:
            error_count += 1

        sample_total_ms = (
            time.perf_counter()
            - sample_started
        ) * 1000

        sample_total_times.append(
            sample_total_ms
        )

    total_ms = (
        time.perf_counter()
        - wall_started
    ) * 1000

    return {
        "run": run_number,
        "policy": policy_name,
        "click_rate": (
            ""
            if click_rate is None
            else click_rate
        ),
        "sample_count": len(samples),
        "suspicious_count": suspicious_count,
        "explanation_count": explanation_count,
        "model_load_ms": round(
            model_load_ms,
            3,
        ),
        "detection_total_ms": round(
            detection_total_ms,
            3,
        ),
        "explanation_total_ms": round(
            explanation_total_ms,
            3,
        ),
        "total_ms": round(
            total_ms,
            3,
        ),
        "mean_sample_ms": round(
            float(np.mean(sample_total_times)),
            3,
        ),
        "median_sample_ms": round(
            float(np.median(sample_total_times)),
            3,
        ),
        "p95_sample_ms": round(
            float(
                np.percentile(
                    sample_total_times,
                    95,
                )
            ),
            3,
        ),
        "error_count": error_count,
    }


def main():
    parser = argparse.ArgumentParser(
        description="EmailGuard XAI 정책별 지연시간 실험",
    )

    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="각 정책 반복 실행 횟수",
    )

    args = parser.parse_args()

    if args.runs < 1:
        raise ValueError(
            "--runs 값은 1 이상이어야 합니다."
        )

    rows = read_manifest(args.manifest)
    samples = load_samples(rows)

    # 모델 초기 로딩시간을 별도로 측정한다.
    load_started = time.perf_counter()
    detector = Knn295Detector()
    model_load_ms = (
        time.perf_counter()
        - load_started
    ) * 1000

    print(
        f"모델 초기 로딩시간: "
        f"{model_load_ms:.3f}ms"
    )

    # 클릭 대상 집합을 만들기 위해 판정을 한 번 확인한다.
    suspicious_ids = []

    for sample in samples:
        analysis = detector.analyze(
            sample["file_bytes"]
        )

        if analysis.get("verdict") == "suspicious":
            suspicious_ids.append(
                sample["sample_id"]
            )

    print(f"전체 파일: {len(samples)}개")
    print(
        f"의심 판정 파일: "
        f"{len(suspicious_ids)}개"
    )

    click_sets = build_click_sets(
        suspicious_ids
    )

    policies = [
        {
            "name": "explain_all",
            "type": "explain_all",
            "click_rate": None,
            "clicked_ids": set(),
        },
        {
            "name": "explain_suspicious",
            "type": "explain_suspicious",
            "click_rate": None,
            "clicked_ids": set(),
        },
    ]

    for rate in CLICK_RATES:
        policies.append({
            "name": f"click_{int(rate * 100)}",
            "type": "click",
            "click_rate": rate,
            "clicked_ids": click_sets[rate],
        })

    # 첫 실행에만 생길 수 있는 캐시 등의 영향을 줄이기 위한 준비 실행
    if samples:
        warmup_sample = samples[0]
        warmup_analysis = detector.analyze(
            warmup_sample["file_bytes"]
        )

        if (
            warmup_analysis.get("verdict")
            in VALID_VERDICTS
        ):
            technical = build_explanation(
                detector,
                warmup_sample["file_bytes"],
            )
            render_explanation(technical)

    results = []

    for run_number in range(1, args.runs + 1):
        print(
            f"\n반복 실행 "
            f"{run_number}/{args.runs}"
        )

        # 정책 실행 순서 때문에 특정 정책이 유리해지지 않도록
        # 반복마다 실행 순서를 고정 시드로 섞는다.
        run_policies = list(policies)

        random.Random(
            20260922 + run_number
        ).shuffle(run_policies)

        for policy in run_policies:
            print(
                f"  {policy['name']} 측정 중"
            )

            result = measure_policy(
                detector=detector,
                samples=samples,
                policy_name=policy["name"],
                policy_type=policy["type"],
                click_rate=policy["click_rate"],
                clicked_ids=policy["clicked_ids"],
                run_number=run_number,
                model_load_ms=model_load_ms,
            )

            results.append(result)

    args.output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with args.output.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=list(results[0].keys()),
        )
        writer.writeheader()
        writer.writerows(results)

    print()
    print("실험 완료")
    print(f"결과 파일: {args.output}")


if __name__ == "__main__":
    main()