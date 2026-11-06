"""Calculate reproducible metrics from validation_results.csv."""

from __future__ import annotations

import argparse
import csv
import math
import os
import pathlib
import statistics
import shutil
from datetime import datetime



FIELDS = ("metric", "value", "unit", "numerator", "denominator", "scope", "definition")


def percentage(numerator: int, denominator: int) -> str:
    if not denominator:
        return ""
    return f"{numerator / denominator * 100:.2f}"


def percentile_linear(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def latency_value(values, function):
    return f'{function(values):.3f}' if values else ''


def metric(name, value, unit, numerator="", denominator="", scope="", definition=""):
    return {
        "metric": name,
        "value": value,
        "unit": unit,
        "numerator": numerator,
        "denominator": denominator,
        "scope": scope,
        "definition": definition,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, default=None)
    args = parser.parse_args()

    input_path = args.input.resolve()
    output_path = (
        args.out or input_path.with_name("validation_metrics.csv")
    ).resolve()

    with input_path.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        raise SystemExit('results CSV is empty')

    evaluated = [row for row in rows if row["predicted_verdict"]]
    malware = [row for row in evaluated if row["expected_class"] == "malware"]
    benign = [row for row in evaluated if row["expected_class"] == "benign"]
    excluded = [row for row in rows if row["evaluation_status"] == "excluded"]
    errors = [row for row in rows if row["evaluation_status"] == "error"]

    mal_block = sum(row["predicted_verdict"] == "차단" for row in malware)
    mal_suspect = sum(row["predicted_verdict"] == "의심" for row in malware)
    mal_pass = sum(row["predicted_verdict"] == "통과" for row in malware)
    ben_block = sum(row["predicted_verdict"] == "차단" for row in benign)
    ben_suspect = sum(row["predicted_verdict"] == "의심" for row in benign)
    ben_pass = sum(row["predicted_verdict"] == "통과" for row in benign)
    strict_correct = sum(row["correct_strict"] == "True" for row in evaluated)

    latencies = [float(row["latency_ms"]) for row in evaluated]
    after_first = latencies[1:]

    metrics = [
        metric("manifest_total", len(rows), "files", scope="all", definition="manifest 전체 행"),
        metric("evaluated_total", len(evaluated), "files", scope="all", definition="판정이 생성된 표본"),
        metric("excluded_total", len(excluded), "files", scope="all", definition="사전 제외된 표본"),
        metric("error_total", len(errors), "files", scope="all", definition="평가 중 오류가 발생한 표본"),
        metric("malware_evaluated", len(malware), "files", scope="malware"),
        metric("malware_block_rate", percentage(mal_block, len(malware)), "percent", mal_block, len(malware), "malware", "악성 중 차단"),
        metric("malware_review_capture_rate", percentage(mal_block + mal_suspect, len(malware)), "percent", mal_block + mal_suspect, len(malware), "malware", "악성 중 차단 또는 의심"),
        metric("malware_pass_rate", percentage(mal_pass, len(malware)), "percent", mal_pass, len(malware), "malware", "악성 중 통과"),
        metric("benign_evaluated", len(benign), "files", scope="benign"),
        metric("benign_pass_rate", percentage(ben_pass, len(benign)), "percent", ben_pass, len(benign), "benign", "정상 중 통과"),
        metric("benign_suspect_rate", percentage(ben_suspect, len(benign)), "percent", ben_suspect, len(benign), "benign", "정상 중 의심"),
        metric("benign_false_block_rate", percentage(ben_block, len(benign)), "percent", ben_block, len(benign), "benign", "정상 중 차단"),
        metric("processing_error_rate", percentage(len(errors), len(evaluated) + len(errors)), "percent", len(errors), len(evaluated) + len(errors), "eligible", "파일 읽기·해시·특징 추출·판정 오류를 모두 포함; 특징 추출만의 실패율은 아님"),
        metric("strict_correct_rate", percentage(strict_correct, len(evaluated)), "percent", strict_correct, len(evaluated), "evaluated", "악성 차단 또는 정상 통과만 정답으로 보는 엄격 지표"),
        metric("latency_mean", latency_value(latencies, statistics.fmean), "ms", scope="evaluated", definition="읽기·압축 해제·해시·특징 추출·판정 포함; 모델 로드는 제외"),
        metric("latency_median", latency_value(latencies, statistics.median), "ms", scope="evaluated"),
        metric("latency_p95_linear", latency_value(latencies, lambda v: percentile_linear(v, 0.95)), "ms", scope="evaluated", definition="선형 보간 95백분위; 첫 표본 포함"),
        metric("latency_max", latency_value(latencies, max), "ms", scope="evaluated"),
        metric("first_sample_latency", latency_value(latencies, lambda v: v[0]), "ms", scope="first evaluated sample", definition="첫 표본 실측값; 지연 원인을 예열로 확정하지 않음"),
        metric("post_first_latency_mean", latency_value(after_first, statistics.fmean), "ms", scope="evaluated excluding first", definition="첫 평가 표본 제외 평균; 별도 warm benchmark가 아님"),
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path == input_path:
        raise SystemExit('output must differ from input')
    if output_path.exists():
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        shutil.copy2(output_path, output_path.with_name(f'{output_path.stem}_before_{stamp}.csv'))
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(metrics)
    os.replace(temporary, output_path)

    print(f"metrics={output_path}")
    print(f"rows={len(metrics)}")
    for row in metrics:
        if row["metric"] in {
            "malware_block_rate",
            "malware_review_capture_rate",
            "malware_pass_rate",
            "benign_pass_rate",
            "benign_suspect_rate",
            "benign_false_block_rate",
            "processing_error_rate",
        }:
            print(f"{row['metric']}={row['value']}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
