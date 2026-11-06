import argparse
import csv
import hashlib
import itertools
from pathlib import Path
from project_paths import XAI_DATA_DIR

import numpy as np

from adapters.knn295 import Knn295Detector
from explainers.proximity import (
    FEATURE_GROUPS,
    calculate_group_impacts,
    malware_proximity,
)


DEFAULT_MANIFEST_PATH = XAI_DATA_DIR / "manifests/manifest_pilot.csv"

DEFAULT_OUTPUT_PATH = XAI_DATA_DIR / "results/faithfulness_pilot.csv"


GROUP_MAP = {
    group["id"]: group
    for group in FEATURE_GROUPS
}


def sha256_of(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()


def normal_reference_vector(detector):
    """
    현재 XAI 구현과 같은 정상 참조값을 반환한다.

    ben_pool에 포함된 StandardScaler의 mean_은
    각 원본 피처의 정상 기준 평균값이다.
    """
    scaler = detector.ben_pool[0]

    return np.asarray(
        scaler.mean_,
        dtype=np.float32,
    )


def evaluate_order(
    detector,
    vector,
    reference,
    group_order,
):
    """
    주어진 그룹 순서대로 피처를 정상 참조값으로 교체한다.

    각 단계에서:
    - 변경 후 악성 근접도
    - 원본 대비 악성 근접도 감소량

    을 계산한다.
    """
    original = malware_proximity(detector, vector)
    original_risk = original["malware_proximity"]

    changed_vector = vector.copy()

    step_risks = []
    cumulative_drops = []

    for group_id in group_order:
        group = GROUP_MAP[group_id]
        group_slice = group["slice"]

        changed_vector[group_slice] = reference[group_slice]

        changed = malware_proximity(
            detector,
            changed_vector,
        )

        changed_risk = changed["malware_proximity"]
        cumulative_drop = original_risk - changed_risk

        step_risks.append(float(changed_risk))
        cumulative_drops.append(float(cumulative_drop))

    # AOPC:
    # 그룹을 하나씩 제거했을 때 발생한 누적 점수 감소량의 평균.
    # 값이 클수록 중요한 그룹을 앞에서 잘 선택했다는 의미다.
    aopc = float(np.mean(cumulative_drops))

    return {
        "step_risks": step_risks,
        "cumulative_drops": cumulative_drops,
        "aopc": aopc,
    }


def format_order(group_order):
    return ">".join(group_order)


def run_one_sample(detector, row):
    file_path = Path(row["path"])

    result = {
        "sample_id": row["sample_id"],
        "path": str(file_path),
        "true_label": row.get("true_label", ""),
        "source": row.get("source", ""),
        "sha256": "",
        "verdict": "",
        "original_risk": "",
        "xai_order": "",
        "reverse_order": "",
        "best_order": "",
        "top_group": "",
        "general_impact": "",
        "sections_impact": "",
        "datadirectories_impact": "",
        "xai_step1_risk": "",
        "xai_step2_risk": "",
        "xai_step3_risk": "",
        "xai_step1_drop": "",
        "xai_step2_drop": "",
        "xai_step3_drop": "",
        "xai_aopc": "",
        "reverse_aopc": "",
        "permutation_mean_aopc": "",
        "best_aopc": "",
        "xai_order_rank": "",
        "xai_beats_reverse": "",
        "xai_beats_permutation_mean": "",
        "status": "",
        "error": "",
    }

    try:
        if not file_path.is_file():
            raise FileNotFoundError(
                f"파일을 찾을 수 없습니다: {file_path}"
            )

        file_bytes = file_path.read_bytes()
        result["sha256"] = sha256_of(file_bytes)

        _, vector = detector.extract(file_bytes)
        model_result = detector.score_vector(vector)

        verdict = model_result["verdict"]
        result["verdict"] = verdict

        # XAI는 의심 파일만 설명하므로,
        # 다른 판정 파일은 실험 대상에서 제외한다.
        if verdict != "suspicious":
            result["status"] = "skipped_non_suspicious"
            return result

        original = malware_proximity(detector, vector)
        original_risk = original["malware_proximity"]

        result["original_risk"] = round(
            original_risk,
            8,
        )

        reference = normal_reference_vector(detector)

        # 현재 XAI 방식으로 그룹별 개별 영향도를 계산한다.
        group_impacts = calculate_group_impacts(
            detector,
            vector,
        )

        impact_by_id = {
            item["id"]: item["impact"]
            for item in group_impacts
        }

        result["general_impact"] = impact_by_id["general"]
        result["sections_impact"] = impact_by_id["sections"]
        result["datadirectories_impact"] = (
            impact_by_id["datadirectories"]
        )

        # 영향도가 큰 그룹부터 정렬된 XAI 순서
        xai_order = [
            item["id"]
            for item in group_impacts
        ]

        reverse_order = list(reversed(xai_order))

        result["xai_order"] = format_order(xai_order)
        result["reverse_order"] = format_order(reverse_order)
        result["top_group"] = xai_order[0]

        # XAI 순서 평가
        xai_evaluation = evaluate_order(
            detector,
            vector,
            reference,
            xai_order,
        )

        # 역순 평가
        reverse_evaluation = evaluate_order(
            detector,
            vector,
            reference,
            reverse_order,
        )

        result["xai_step1_risk"] = round(
            xai_evaluation["step_risks"][0],
            8,
        )
        result["xai_step2_risk"] = round(
            xai_evaluation["step_risks"][1],
            8,
        )
        result["xai_step3_risk"] = round(
            xai_evaluation["step_risks"][2],
            8,
        )

        result["xai_step1_drop"] = round(
            xai_evaluation["cumulative_drops"][0],
            8,
        )
        result["xai_step2_drop"] = round(
            xai_evaluation["cumulative_drops"][1],
            8,
        )
        result["xai_step3_drop"] = round(
            xai_evaluation["cumulative_drops"][2],
            8,
        )

        result["xai_aopc"] = round(
            xai_evaluation["aopc"],
            8,
        )
        result["reverse_aopc"] = round(
            reverse_evaluation["aopc"],
            8,
        )

        # 세 그룹의 가능한 모든 순서 6개를 평가한다.
        group_ids = list(GROUP_MAP.keys())
        permutation_results = []

        for order_tuple in itertools.permutations(group_ids):
            order = list(order_tuple)

            evaluation = evaluate_order(
                detector,
                vector,
                reference,
                order,
            )

            permutation_results.append({
                "order": order,
                "aopc": evaluation["aopc"],
            })

        # AOPC가 큰 순서부터 정렬
        permutation_results.sort(
            key=lambda item: item["aopc"],
            reverse=True,
        )

        best = permutation_results[0]

        mean_aopc = float(np.mean([
            item["aopc"]
            for item in permutation_results
        ]))

        result["best_order"] = format_order(best["order"])
        result["best_aopc"] = round(best["aopc"], 8)
        result["permutation_mean_aopc"] = round(
            mean_aopc,
            8,
        )

        # XAI 순서가 6개 순서 중 몇 등인지 계산
        xai_order_text = format_order(xai_order)

        for rank, item in enumerate(
            permutation_results,
            start=1,
        ):
            if format_order(item["order"]) == xai_order_text:
                result["xai_order_rank"] = rank
                break

        result["xai_beats_reverse"] = (
            xai_evaluation["aopc"]
            > reverse_evaluation["aopc"]
        )

        result["xai_beats_permutation_mean"] = (
            xai_evaluation["aopc"]
            > mean_aopc
        )

        result["status"] = "ok"

    except Exception as error:
        result["status"] = "error"
        result["error"] = (
            f"{type(error).__name__}: {error}"
        )

    return result


def main():
    parser = argparse.ArgumentParser(
        description="EmailGuard XAI 설명 충실도 실험",
    )

    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
    )

    args = parser.parse_args()

    if not args.manifest.is_file():
        raise FileNotFoundError(
            f"manifest를 찾을 수 없습니다: {args.manifest}"
        )

    with args.manifest.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        rows = list(csv.DictReader(file))

    if not rows:
        raise RuntimeError("manifest에 데이터가 없습니다.")

    detector = Knn295Detector()
    results = []

    print(f"입력 파일 수: {len(rows)}")

    for number, row in enumerate(rows, start=1):
        print(
            f"[{number}/{len(rows)}] "
            f"{row['sample_id']} 충실도 분석 중"
        )

        result = run_one_sample(detector, row)
        results.append(result)

        print(
            f"  verdict={result['verdict']} "
            f"status={result['status']}"
        )

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

    analyzed = [
        row
        for row in results
        if row["status"] == "ok"
    ]

    skipped = [
        row
        for row in results
        if row["status"] == "skipped_non_suspicious"
    ]

    errors = [
        row
        for row in results
        if row["status"] == "error"
    ]

    beat_reverse_count = sum(
        row["xai_beats_reverse"] is True
        for row in analyzed
    )

    beat_mean_count = sum(
        row["xai_beats_permutation_mean"] is True
        for row in analyzed
    )

    print()
    print(f"전체 파일: {len(results)}개")
    print(f"의심 파일 분석: {len(analyzed)}개")
    print(f"의심 외 판정 제외: {len(skipped)}개")
    print(f"분석 오류: {len(errors)}개")

    if analyzed:
        print(
            "XAI 순서가 역순보다 우수: "
            f"{beat_reverse_count}/{len(analyzed)}개"
        )
        print(
            "XAI 순서가 전체 순서 평균보다 우수: "
            f"{beat_mean_count}/{len(analyzed)}개"
        )

    print(f"결과 파일: {args.output}")


if __name__ == "__main__":
    main()