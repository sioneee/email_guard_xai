import argparse
import csv
import hashlib
import json
from pathlib import Path

from adapters.knn295 import Knn295Detector
from explainers.proximity import build_explanation
from renderers.korean import render_explanation


DEFAULT_MANIFEST = Path(
    r"C:\email_guard_xai_data\manifests\manifest_pilot.csv"
)

DEFAULT_OUTPUT = Path(
    r"C:\email_guard_xai_data\results\content_audit_pilot.csv"
)

DEFAULT_MANUAL_OUTPUT = Path(
    r"C:\email_guard_xai_data\results\content_manual_review.csv"
)


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
        raise RuntimeError("manifest에 데이터가 없습니다.")

    return rows


def expected_static_signal_count(observations):
    count = 0

    if not observations["has_signature"]:
        count += 1

    if observations["rwx_sections"]:
        count += 1

    if observations["high_entropy_sections"]:
        count += 1

    if (
        observations.get("packing_score") is not None
        and observations["packing_score"] >= 2
    ):
        count += 1

    if 0 < observations["import_count"] <= 20:
        count += 1

    return count


def build_manual_rows(
    sample_id,
    explanation,
    technical,
):
    rows = []

    model_result = technical["model_result"]
    observations = technical["observations"]
    group_impacts = technical["group_impacts"]

    top_positive_group = next(
        (
            group
            for group in group_impacts
            if group["impact"] > 0
        ),
        None,
    )

    summary_evidence = {
        "verdict": model_result["verdict"],
        "ratio": model_result["ratio"],
        "top_positive_group": top_positive_group,
        "rwx_sections": observations["rwx_sections"],
        "high_entropy_sections": (
            observations["high_entropy_sections"]
        ),
    }

    rows.append({
        "sample_id": sample_id,
        "statement_id": f"{sample_id}_summary",
        "statement_type": "summary",
        "statement": explanation["summary"],
        "evidence": json.dumps(
            summary_evidence,
            ensure_ascii=False,
        ),
        "judgment": "",
        "reviewer": "",
        "note": "",
    })

    impact_by_name = {
        item["name"]: item
        for item in group_impacts
    }

    for number, factor in enumerate(
        explanation["risk_factors"],
        start=1,
    ):
        evidence = impact_by_name.get(
            factor["title"],
            {},
        )

        rows.append({
            "sample_id": sample_id,
            "statement_id": (
                f"{sample_id}_factor_{number}"
            ),
            "statement_type": "risk_factor",
            "statement": (
                f"{factor['title']}: "
                f"{factor['detail']}"
            ),
            "evidence": json.dumps(
                evidence,
                ensure_ascii=False,
            ),
            "judgment": "",
            "reviewer": "",
            "note": "",
        })

    observation_evidence = json.dumps(
        observations,
        ensure_ascii=False,
    )

    for number, statement in enumerate(
        explanation["static_observations"],
        start=1,
    ):
        rows.append({
            "sample_id": sample_id,
            "statement_id": (
                f"{sample_id}_observation_{number}"
            ),
            "statement_type": "static_observation",
            "statement": statement,
            "evidence": observation_evidence,
            "judgment": "",
            "reviewer": "",
            "note": "",
        })

    return rows


def run_one_sample(detector, row):
    file_path = Path(row["path"])

    result = {
        "sample_id": row["sample_id"],
        "path": str(file_path),
        "true_label": row.get("true_label", ""),
        "sha256": "",
        "verdict": "",
        "ratio": "",
        "expected_factor_count": "",
        "actual_factor_count": "",
        "factor_titles_match": "",
        "expected_static_count": "",
        "actual_static_count": "",
        "static_count_matches": "",
        "summary_present": "",
        "disclaimer_present": "",
        "probability_word_found": "",
        "automatic_check_passed": "",
        "status": "",
        "error": "",
    }

    manual_rows = []

    try:
        if not file_path.is_file():
            raise FileNotFoundError(
                f"파일을 찾을 수 없습니다: {file_path}"
            )

        file_bytes = file_path.read_bytes()
        result["sha256"] = sha256_of(file_bytes)

        analysis = detector.analyze(file_bytes)
        verdict = analysis["verdict"]

        result["verdict"] = verdict
        result["ratio"] = analysis.get("ratio", "")

        if verdict != "suspicious":
            result["status"] = "skipped_non_suspicious"
            return result, manual_rows

        technical = build_explanation(
            detector,
            file_bytes,
        )

        explanation = render_explanation(
            technical,
        )

        positive_groups = [
            group
            for group in technical["group_impacts"][:3]
            if group["impact"] > 0
        ]

        expected_titles = [
            group["name"]
            for group in positive_groups
        ]

        actual_titles = [
            factor["title"]
            for factor in explanation["risk_factors"]
        ]

        observations = technical["observations"]

        expected_static_count = (
            expected_static_signal_count(
                observations
            )
        )

        actual_static_count = len(
            explanation["static_observations"]
        )

        summary_present = bool(
            explanation.get("summary", "").strip()
        )

        disclaimer_present = bool(
            explanation.get("disclaimer", "").strip()
        )

        rendered_text = json.dumps(
            explanation,
            ensure_ascii=False,
        )

        # 거리 기반 점수를 확률이라고 잘못 표현하는지 검사
        probability_word_found = (
            "확률" in rendered_text
        )

        factor_titles_match = (
            expected_titles == actual_titles
        )

        static_count_matches = (
            expected_static_count
            == actual_static_count
        )

        automatic_check_passed = all([
            factor_titles_match,
            static_count_matches,
            summary_present,
            disclaimer_present,
            not probability_word_found,
        ])

        result.update({
            "expected_factor_count": len(
                expected_titles
            ),
            "actual_factor_count": len(
                actual_titles
            ),
            "factor_titles_match": (
                factor_titles_match
            ),
            "expected_static_count": (
                expected_static_count
            ),
            "actual_static_count": (
                actual_static_count
            ),
            "static_count_matches": (
                static_count_matches
            ),
            "summary_present": summary_present,
            "disclaimer_present": (
                disclaimer_present
            ),
            "probability_word_found": (
                probability_word_found
            ),
            "automatic_check_passed": (
                automatic_check_passed
            ),
            "status": "ok",
        })

        manual_rows = build_manual_rows(
            row["sample_id"],
            explanation,
            technical,
        )

    except Exception as error:
        result["status"] = "error"
        result["error"] = (
            f"{type(error).__name__}: {error}"
        )

    return result, manual_rows


def main():
    parser = argparse.ArgumentParser(
        description="EmailGuard XAI 설명 문장 정확성 검사",
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
        "--manual-output",
        type=Path,
        default=DEFAULT_MANUAL_OUTPUT,
    )

    args = parser.parse_args()

    rows = read_manifest(args.manifest)
    detector = Knn295Detector()

    results = []
    manual_rows = []

    for number, row in enumerate(rows, start=1):
        print(
            f"[{number}/{len(rows)}] "
            f"{row['sample_id']} 검사 중"
        )

        result, sample_manual_rows = (
            run_one_sample(detector, row)
        )

        results.append(result)
        manual_rows.extend(sample_manual_rows)

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

    if manual_rows:
        with args.manual_output.open(
            "w",
            encoding="utf-8-sig",
            newline="",
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=list(
                    manual_rows[0].keys()
                ),
            )
            writer.writeheader()
            writer.writerows(manual_rows)

    analyzed = [
        row
        for row in results
        if row["status"] == "ok"
    ]

    passed = [
        row
        for row in analyzed
        if row["automatic_check_passed"] is True
    ]

    errors = [
        row
        for row in results
        if row["status"] == "error"
    ]

    print()
    print(f"전체 파일: {len(results)}개")
    print(f"의심 파일 자동 검사: {len(analyzed)}개")
    print(
        "자동 검사 통과: "
        f"{len(passed)}/{len(analyzed)}개"
    )
    print(f"오류: {len(errors)}개")
    print(f"자동 검사 결과: {args.output}")
    print(f"사람 검토 파일: {args.manual_output}")


if __name__ == "__main__":
    main()