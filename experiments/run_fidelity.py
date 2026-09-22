import argparse
import csv
import importlib.util
from pathlib import Path

import joblib
import numpy as np

from adapters.knn295 import Knn295Detector
from config import INDEX_PATH


DEFAULT_MANIFEST_PATH = Path(
    r"C:\email_guard_xai_data\manifests\manifest_xai.csv"
)

DEFAULT_RESULT_PATH = Path(
    r"C:\email_guard_xai_data\results\fidelity_results.csv"
)

TRIAGE_PATH = Path(
    r"C:\workspace_Email\email_guard\ml\triage.py"
)


def load_original_triage():
    """기존 프로젝트의 triage.py를 읽기 전용으로 불러온다."""
    spec = importlib.util.spec_from_file_location(
        "original_triage",
        TRIAGE_PATH,
    )

    if spec is None or spec.loader is None:
        raise ImportError(
            f"triage.py를 불러올 수 없습니다: {TRIAGE_PATH}"
        )

    triage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(triage)

    return triage


def korean_to_english_verdict(verdict):
    mapping = {
        "통과": "safe",
        "의심": "suspicious",
        "차단": "blocked",
    }
    return mapping.get(verdict, "unknown")


def main():
    parser = argparse.ArgumentParser(
        description="기존 triage와 XAI 어댑터의 판정 일치 검증",
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
        default=DEFAULT_RESULT_PATH,
        help="결과 CSV 저장 경로",
    )

    args = parser.parse_args()

    manifest_path = args.manifest
    result_path = args.output

    if not manifest_path.exists():
        raise FileNotFoundError(
            f"manifest 파일을 찾을 수 없습니다: {manifest_path}"
        )

    if not TRIAGE_PATH.exists():
        raise FileNotFoundError(
            f"원본 triage.py를 찾을 수 없습니다: {TRIAGE_PATH}"
        )

    with manifest_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as manifest_file:
        rows = list(csv.DictReader(manifest_file))

    if not rows:
        raise RuntimeError(
            f"{manifest_path.name}에 실험 파일이 없습니다."
        )

    triage = load_original_triage()
    detector = Knn295Detector()
    bundle = joblib.load(INDEX_PATH)

    groups = {
        "mal": bundle["mal"],
        "ben_big": bundle["ben_big"],
        "ben_pool": bundle["ben_pool"],
    }

    print(f"입력 manifest: {manifest_path}")
    print(f"실험 파일 수: {len(rows)}")

    results = []

    for index, row in enumerate(rows, start=1):
        sample_id = row["sample_id"]
        file_path = Path(row["path"])

        print(f"[{index}/{len(rows)}] {sample_id} 비교 중")

        try:
            file_bytes = file_path.read_bytes()

            # 기존 pe_features.py를 통해 동일한 295차원 벡터 추출
            _, vector = detector.extract(file_bytes)

            # 1) 기존 팀 triage.py의 원본 판정
            original_ratio, original_d_mal, original_d_ben = (
                triage.ratios(groups, vector)
            )

            original_ratio = float(
                np.asarray(original_ratio).reshape(-1)[0]
            )
            original_d_mal = float(
                np.asarray(original_d_mal).reshape(-1)[0]
            )
            original_d_ben = float(
                np.asarray(original_d_ben).reshape(-1)[0]
            )

            original_ko = triage.verdict(
                original_ratio,
                bundle["t_low"],
                bundle["t_high"],
            )

            original_verdict = korean_to_english_verdict(
                original_ko
            )

            # 2) XAI 어댑터의 재현 판정
            xai_result = detector.score_vector(vector)
            xai_verdict = xai_result["verdict"]
            xai_ratio = xai_result["ratio"]

            ratio_delta = abs(original_ratio - xai_ratio)

            results.append({
                "sample_id": sample_id,
                "true_label": row.get("true_label", ""),
                "original_verdict": original_verdict,
                "xai_verdict": xai_verdict,
                "same_verdict": original_verdict == xai_verdict,
                "original_ratio": round(original_ratio, 6),
                "xai_ratio": xai_ratio,
                "ratio_delta": round(ratio_delta, 6),
                "original_d_mal": round(original_d_mal, 6),
                "original_d_ben": round(original_d_ben, 6),
                "status": "ok",
                "error": "",
            })

        except Exception as error:
            results.append({
                "sample_id": sample_id,
                "true_label": row.get("true_label", ""),
                "original_verdict": "",
                "xai_verdict": "",
                "same_verdict": False,
                "original_ratio": "",
                "xai_ratio": "",
                "ratio_delta": "",
                "original_d_mal": "",
                "original_d_ben": "",
                "status": "error",
                "error": f"{type(error).__name__}: {error}",
            })

    result_path.parent.mkdir(parents=True, exist_ok=True)

    with result_path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as result_file:
        writer = csv.DictWriter(
            result_file,
            fieldnames=results[0].keys(),
        )
        writer.writeheader()
        writer.writerows(results)

    success_count = sum(
        row["status"] == "ok"
        for row in results
    )

    same_count = sum(
        row["same_verdict"] is True
        for row in results
    )

    print()
    print(f"완료: {success_count}/{len(results)}개 분석 성공")
    print(f"판정 일치: {same_count}/{len(results)}개")
    print(f"결과 파일: {result_path}")


if __name__ == "__main__":
    main()