import csv
import hashlib
import time
import argparse
from pathlib import Path
from project_paths import XAI_DATA_DIR

from adapters.knn295 import Knn295Detector
from explainers.proximity import build_explanation
from renderers.korean import render_explanation

DATA_DIR = XAI_DATA_DIR

DEFAULT_MANIFEST_PATH = DATA_DIR / "manifests" / "manifest_xai.csv"
DEFAULT_RESULTS_PATH = DATA_DIR / "results" / "xai_results.csv"

def sha256_of(data):
    return hashlib.sha256(data).hexdigest()


def run_one_sample(detector, row):
    file_path = Path(row["path"])

    result = {
        "sample_id": row["sample_id"],
        "path": str(file_path),
        "true_label": row["true_label"],
        "source": row["source"],
        "overlap_status": row["overlap_status"],
        "purpose": row["purpose"],
        "sha256": "",
        "verdict": "",
        "ratio": "",
        "malware_proximity": "",
        "d_mal": "",
        "d_ben": "",
        "analysis_ms": "",
        "xai_ms": "",
        "total_ms": "",
        "top_group": "",
        "top_group_impact": "",
        "summary": "",
        "static_observations": "",
        "status": "ok",
        "error": "",
    }

    started = time.perf_counter()

    try:
        if not file_path.exists():
            raise FileNotFoundError(f"파일을 찾을 수 없습니다: {file_path}")

        file_bytes = file_path.read_bytes()
        result["sha256"] = sha256_of(file_bytes)

        # 1. 기존 kNN과 같은 판정
        analysis_started = time.perf_counter()
        analysis = detector.analyze(file_bytes)
        result["analysis_ms"] = round(
            (time.perf_counter() - analysis_started) * 1000,
            2,
        )

        result["verdict"] = analysis.get("verdict", "")
        result["ratio"] = analysis.get("ratio", "")
        result["malware_proximity"] = analysis.get(
            "malware_proximity",
            "",
        )
        result["d_mal"] = analysis.get("d_mal", "")
        result["d_ben"] = analysis.get("d_ben", "")

        # 2. XAI 설명 생성
        if result["verdict"] == "suspicious":
            xai_started = time.perf_counter()

            technical = build_explanation(detector, file_bytes)
            explanation = render_explanation(technical)

            result["xai_ms"] = round(
                (time.perf_counter() - xai_started) * 1000,
                2,
            )

            group_impacts = technical["group_impacts"]

            if group_impacts:
                result["top_group"] = group_impacts[0]["name"]
                result["top_group_impact"] = group_impacts[0]["impact"]

            result["summary"] = explanation["summary"]
            result["static_observations"] = " | ".join(
                explanation["static_observations"]
            )

        elif result["verdict"] not in {"safe", "blocked"}:
                result["status"] = "analysis_failed"
                result["error"] = analysis.get(
                    "message",
                    "알 수 없는 오류",
                )
    except Exception as error:
        result["status"] = "error"
        result["error"] = f"{type(error).__name__}: {error}"

    finally:
        result["total_ms"] = round(
            (time.perf_counter() - started) * 1000,
            2,
        )

    return result


def main():
    parser = argparse.ArgumentParser(
        description="EmailGuard XAI 배치 실험",
    )

    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help="입력 manifest CSV 경로",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_RESULTS_PATH,
        help="결과 CSV 저장 경로",
    )

    args = parser.parse_args()

    manifest_path = args.manifest
    results_path = args.output
    results_dir = results_path.parent

    if not manifest_path.exists():
        raise FileNotFoundError(
            f"manifest 파일을 찾을 수 없습니다: {manifest_path}"
        )

    results_dir.mkdir(parents=True, exist_ok=True)

    with manifest_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        rows = list(csv.DictReader(file))

    if not rows:
        raise RuntimeError(
            f"{manifest_path.name}에 실험 파일이 없습니다."
        )

    detector = Knn295Detector()

    print(f"입력 manifest: {manifest_path}")
    print(f"실험 파일 수: {len(rows)}")

    results = []

    for index, row in enumerate(rows, start=1):
        print(f"[{index}/{len(rows)}] {row['sample_id']} 분석 중")

        result = run_one_sample(detector, row)
        results.append(result)

        print(
            f"  verdict={result['verdict']} "
            f"status={result['status']} "
            f"total={result['total_ms']}ms"
        )

    fieldnames = list(results[0].keys())

    with results_path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(results)

    success_count = sum(
        1 for result in results
        if result["status"] == "ok"
    )

    print()
    print(f"완료: {success_count}/{len(results)}개 성공")
    print(f"결과 파일: {results_path}")


if __name__ == "__main__":
    main()