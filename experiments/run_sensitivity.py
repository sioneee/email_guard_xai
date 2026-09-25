import argparse
import csv
import hashlib
from pathlib import Path
from project_paths import XAI_DATA_DIR

import numpy as np

from adapters.knn295 import Knn295Detector
from explainers.proximity import (
    FEATURE_GROUPS,
    malware_proximity,
)


DEFAULT_TARGET_MANIFEST = XAI_DATA_DIR / "manifests/manifest_pilot.csv"

DEFAULT_REFERENCE_MANIFEST = XAI_DATA_DIR / "manifests/manifest_reference.csv"

DEFAULT_OUTPUT = XAI_DATA_DIR / "results/sensitivity_pilot.csv"

DEFAULT_REFERENCE_OUTPUT = XAI_DATA_DIR / 'results/sensitivity_reference_validation.csv'


def sha256_of(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()


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
        raise RuntimeError(
            f"manifest에 데이터가 없습니다: {path}"
        )

    return rows


def impact_sign(value, tolerance=1e-9):
    """
    아주 작은 부동소수점 오차는 0으로 처리한다.
    """
    if value > tolerance:
        return 1

    if value < -tolerance:
        return -1

    return 0


def calculate_impacts_with_reference(
    detector,
    vector,
    reference,
):
    """
    지정된 정상 참조 벡터를 이용해
    세 피처 그룹의 영향도를 계산한다.
    """
    original = malware_proximity(detector, vector)
    original_risk = original["malware_proximity"]

    impacts = []

    for group in FEATURE_GROUPS:
        changed_vector = vector.copy()
        group_slice = group["slice"]

        changed_vector[group_slice] = reference[group_slice]

        changed = malware_proximity(
            detector,
            changed_vector,
        )

        changed_risk = changed["malware_proximity"]
        impact = original_risk - changed_risk

        impacts.append({
            "id": group["id"],
            "impact": float(impact),
        })

    impacts.sort(
        key=lambda item: item["impact"],
        reverse=True,
    )

    return {
        "original_risk": float(original_risk),
        "impacts": impacts,
    }


def impacts_to_dict(calculation):
    return {
        item["id"]: item["impact"]
        for item in calculation["impacts"]
    }


def rank_order(calculation):
    return ">".join(
        item["id"]
        for item in calculation["impacts"]
    )


def validate_reference_files(
    detector,
    reference_rows,
):
    """
    참조 파일을 분석하고 정상 판정된 파일만
    정상 참조 벡터로 사용한다.
    """
    accepted = []
    validation_results = []

    for number, row in enumerate(
        reference_rows,
        start=1,
    ):
        sample_id = row["sample_id"]
        file_path = Path(row["path"])

        validation = {
            "sample_id": sample_id,
            "path": str(file_path),
            "sha256": "",
            "model_verdict": "",
            "accepted_as_reference": False,
            "status": "",
            "error": "",
        }

        print(
            f"[참조 {number}/{len(reference_rows)}] "
            f"{sample_id} 검사 중"
        )

        try:
            if not file_path.is_file():
                raise FileNotFoundError(
                    f"파일을 찾을 수 없습니다: {file_path}"
                )

            file_bytes = file_path.read_bytes()
            validation["sha256"] = sha256_of(file_bytes)

            _, vector = detector.extract(file_bytes)
            model_result = detector.score_vector(vector)

            verdict = model_result["verdict"]
            validation["model_verdict"] = verdict
            validation["status"] = "ok"

            # 디지털 서명 정상 파일 중에서도
            # 모델이 safe로 판정한 파일만 정상 참조로 사용한다.
            if verdict == "safe":
                validation["accepted_as_reference"] = True

                accepted.append({
                    "sample_id": sample_id,
                    "path": str(file_path),
                    "vector": np.asarray(
                        vector,
                        dtype=np.float32,
                    ),
                })

        except Exception as error:
            validation["status"] = "error"
            validation["error"] = (
                f"{type(error).__name__}: {error}"
            )

        validation_results.append(validation)

    return accepted, validation_results


def build_reference_methods(
    detector,
    accepted_references,
):
    reference_matrix = np.stack([
        item["vector"]
        for item in accepted_references
    ])

    model_mean = np.asarray(
        detector.ben_pool[0].mean_,
        dtype=np.float32,
    )

    external_mean = np.mean(
        reference_matrix,
        axis=0,
    ).astype(np.float32)

    external_median = np.median(
        reference_matrix,
        axis=0,
    ).astype(np.float32)

    methods = [
        {
            "method": "model_mean",
            "reference_id": "ben_pool_mean",
            "vector": model_mean,
        },
        {
            "method": "external_mean",
            "reference_id": "reference_mean",
            "vector": external_mean,
        },
        {
            "method": "external_median",
            "reference_id": "reference_median",
            "vector": external_median,
        },
    ]

    # 각 정상 파일의 실제 벡터도 하나씩 기준으로 사용한다.
    for item in accepted_references:
        methods.append({
            "method": "individual",
            "reference_id": item["sample_id"],
            "vector": item["vector"],
        })

    return methods


def build_result_row(
    target_row,
    target_sha256,
    verdict,
    reference_method,
    calculation,
    baseline_calculation,
):
    impacts = impacts_to_dict(calculation)
    baseline_impacts = impacts_to_dict(
        baseline_calculation
    )

    top_group = calculation["impacts"][0]["id"]
    baseline_top_group = (
        baseline_calculation["impacts"][0]["id"]
    )

    current_rank = rank_order(calculation)
    baseline_rank = rank_order(
        baseline_calculation
    )

    return {
        "sample_id": target_row["sample_id"],
        "path": target_row["path"],
        "true_label": target_row.get(
            "true_label",
            "",
        ),
        "sha256": target_sha256,
        "verdict": verdict,
        "reference_method": (
            reference_method["method"]
        ),
        "reference_id": (
            reference_method["reference_id"]
        ),
        "original_risk": round(
            calculation["original_risk"],
            8,
        ),
        "baseline_top_group": baseline_top_group,
        "top_group": top_group,
        "top_group_matches_baseline": (
            top_group == baseline_top_group
        ),
        "baseline_rank_order": baseline_rank,
        "rank_order": current_rank,
        "full_rank_matches_baseline": (
            current_rank == baseline_rank
        ),
        "general_impact": round(
            impacts["general"],
            8,
        ),
        "sections_impact": round(
            impacts["sections"],
            8,
        ),
        "datadirectories_impact": round(
            impacts["datadirectories"],
            8,
        ),
        "general_sign_matches_baseline": (
            impact_sign(impacts["general"])
            == impact_sign(baseline_impacts["general"])
        ),
        "sections_sign_matches_baseline": (
            impact_sign(impacts["sections"])
            == impact_sign(baseline_impacts["sections"])
        ),
        "datadirectories_sign_matches_baseline": (
            impact_sign(impacts["datadirectories"])
            == impact_sign(
                baseline_impacts["datadirectories"]
            )
        ),
        "status": "ok",
        "error": "",
    }


def main():
    parser = argparse.ArgumentParser(
        description="EmailGuard XAI 정상 기준값 민감도 실험",
    )

    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_TARGET_MANIFEST,
        help="설명 대상 파일 manifest",
    )

    parser.add_argument(
        "--reference-manifest",
        type=Path,
        default=DEFAULT_REFERENCE_MANIFEST,
        help="정상 참조 파일 manifest",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="민감도 결과 CSV",
    )

    parser.add_argument(
        "--reference-output",
        type=Path,
        default=DEFAULT_REFERENCE_OUTPUT,
        help="정상 참조 파일 검증 결과 CSV",
    )

    args = parser.parse_args()

    target_rows = read_manifest(args.manifest)
    reference_rows = read_manifest(
        args.reference_manifest
    )

    detector = Knn295Detector()

    accepted_references, validation_results = (
        validate_reference_files(
            detector,
            reference_rows,
        )
    )

    args.reference_output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with args.reference_output.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=list(
                validation_results[0].keys()
            ),
        )
        writer.writeheader()
        writer.writerows(validation_results)

    print()
    print(
        "정상 참조로 사용 가능한 파일: "
        f"{len(accepted_references)}"
        f"/{len(reference_rows)}개"
    )

    if len(accepted_references) < 5:
        raise RuntimeError(
            "safe 판정 정상 참조 파일이 5개 미만입니다. "
            "정상 참조 파일을 더 준비하세요."
        )

    reference_methods = build_reference_methods(
        detector,
        accepted_references,
    )

    results = []

    for number, target_row in enumerate(
        target_rows,
        start=1,
    ):
        sample_id = target_row["sample_id"]
        file_path = Path(target_row["path"])

        print(
            f"[대상 {number}/{len(target_rows)}] "
            f"{sample_id} 분석 중"
        )

        try:
            if not file_path.is_file():
                raise FileNotFoundError(
                    f"파일을 찾을 수 없습니다: {file_path}"
                )

            file_bytes = file_path.read_bytes()
            target_sha256 = sha256_of(file_bytes)

            _, vector = detector.extract(file_bytes)
            model_result = detector.score_vector(vector)
            verdict = model_result["verdict"]

            if verdict != "suspicious":
                results.append({
                    "sample_id": sample_id,
                    "path": str(file_path),
                    "true_label": target_row.get(
                        "true_label",
                        "",
                    ),
                    "sha256": target_sha256,
                    "verdict": verdict,
                    "reference_method": "",
                    "reference_id": "",
                    "original_risk": "",
                    "baseline_top_group": "",
                    "top_group": "",
                    "top_group_matches_baseline": "",
                    "baseline_rank_order": "",
                    "rank_order": "",
                    "full_rank_matches_baseline": "",
                    "general_impact": "",
                    "sections_impact": "",
                    "datadirectories_impact": "",
                    "general_sign_matches_baseline": "",
                    "sections_sign_matches_baseline": "",
                    "datadirectories_sign_matches_baseline": "",
                    "status": "skipped_non_suspicious",
                    "error": "",
                })
                continue

            # model_mean을 비교 기준으로 먼저 계산한다.
            model_mean_method = reference_methods[0]

            baseline_calculation = (
                calculate_impacts_with_reference(
                    detector,
                    vector,
                    model_mean_method["vector"],
                )
            )

            for method in reference_methods:
                calculation = (
                    calculate_impacts_with_reference(
                        detector,
                        vector,
                        method["vector"],
                    )
                )

                results.append(
                    build_result_row(
                        target_row,
                        target_sha256,
                        verdict,
                        method,
                        calculation,
                        baseline_calculation,
                    )
                )

        except Exception as error:
            results.append({
                "sample_id": sample_id,
                "path": str(file_path),
                "true_label": target_row.get(
                    "true_label",
                    "",
                ),
                "sha256": "",
                "verdict": "",
                "reference_method": "",
                "reference_id": "",
                "original_risk": "",
                "baseline_top_group": "",
                "top_group": "",
                "top_group_matches_baseline": "",
                "baseline_rank_order": "",
                "rank_order": "",
                "full_rank_matches_baseline": "",
                "general_impact": "",
                "sections_impact": "",
                "datadirectories_impact": "",
                "general_sign_matches_baseline": "",
                "sections_sign_matches_baseline": "",
                "datadirectories_sign_matches_baseline": "",
                "status": "error",
                "error": (
                    f"{type(error).__name__}: {error}"
                ),
            })

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

    valid_results = [
        row
        for row in results
        if (
            row["status"] == "ok"
            and row["reference_method"]
            != "model_mean"
        )
    ]

    top_matches = sum(
        row["top_group_matches_baseline"] is True
        for row in valid_results
    )

    full_rank_matches = sum(
        row["full_rank_matches_baseline"] is True
        for row in valid_results
    )

    errors = [
        row
        for row in results
        if row["status"] == "error"
    ]

    print()
    print(f"민감도 비교 행: {len(valid_results)}개")
    print(
        "최상위 그룹 일치: "
        f"{top_matches}/{len(valid_results)}개"
    )
    print(
        "전체 순위 일치: "
        f"{full_rank_matches}/{len(valid_results)}개"
    )
    print(f"오류: {len(errors)}개")
    print(f"결과 파일: {args.output}")
    print(
        "참조 검증 파일: "
        f"{args.reference_output}"
    )


if __name__ == "__main__":
    main()
