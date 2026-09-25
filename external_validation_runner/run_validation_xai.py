"""Generate XAI explanations for suspicious external-validation samples.

The script uses only the frozen EmailGuard runtime. Encrypted malware members are
read in memory through run_validation.load_sample and are never extracted to disk.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import pathlib
import shutil
import sys
import time
from datetime import datetime

import joblib

try:
    from .run_validation import load_sample, read_manifest, verify_runtime
except ImportError:
    from run_validation import load_sample, read_manifest, verify_runtime


XAI_PROJECT = pathlib.Path(__file__).resolve().parent.parent
RATIO_TOLERANCE = 0.0001

FIELDS = (
    "expected_class",
    "container_name",
    "sample_name",
    "sample_sha256",
    "validation_verdict",
    "xai_verdict",
    "validation_ratio",
    "xai_ratio",
    "ratio_delta",
    "fidelity_ok",
    "malware_proximity",
    "d_mal",
    "d_ben",
    "top_group",
    "top_group_impact",
    "general_impact",
    "sections_impact",
    "datadirectories_impact",
    "summary",
    "static_observations",
    "raw_observations_json",
    "xai_ms",
    "status",
    "error",
)


class FrozenDetector:
    """Minimal detector interface required by the existing XAI explainer."""

    def __init__(self, pe_features, triage, bundle):
        self.pf = pe_features
        self.triage = triage
        self.bundle = bundle
        self.t_low = bundle["t_low"]
        self.t_high = bundle["t_high"]
        self.mal = bundle["mal"]
        self.ben_big = bundle["ben_big"]
        self.ben_pool = bundle["ben_pool"]

    def _kdist(self, index, vector):
        return float(self.triage.kdist(index, vector)[0])

    def extract(self, file_bytes):
        raw_features = self.pf.raw_features(file_bytes)
        vector = self.pf.process(raw_features)
        if vector.shape != (295,):
            raise ValueError(f"특징 벡터 모양이 (295,)가 아닙니다: {vector.shape}")
        return raw_features, vector

    def score_vector(self, vector):
        ratios, mal_distances, ben_distances = self.triage.ratios(
            self.bundle, vector
        )
        ratio = float(ratios[0])
        d_mal = float(mal_distances[0])
        d_ben = float(ben_distances[0])
        korean = self.triage.verdict(ratio, self.t_low, self.t_high)
        verdict = {"통과": "safe", "의심": "suspicious", "차단": "blocked"}[korean]
        return {
            "verdict": verdict,
            "ratio": round(ratio, 4),
            "malware_proximity": round(1 - ratio, 4),
            "d_mal": round(d_mal, 4),
            "d_ben": round(d_ben, 4),
        }


def read_validation_results(path: pathlib.Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    suspicious = [row for row in rows if row["predicted_verdict"] == "의심"]
    return suspicious


def base_result(validation_row):
    return {
        "expected_class": validation_row["expected_class"],
        "container_name": validation_row["container_name"],
        "sample_name": validation_row["sample_name"],
        "sample_sha256": validation_row["sample_sha256"],
        "validation_verdict": validation_row["predicted_verdict"],
        "xai_verdict": "",
        "validation_ratio": validation_row["ratio"],
        "xai_ratio": "",
        "ratio_delta": "",
        "fidelity_ok": "",
        "malware_proximity": "",
        "d_mal": "",
        "d_ben": "",
        "top_group": "",
        "top_group_impact": "",
        "general_impact": "",
        "sections_impact": "",
        "datadirectories_impact": "",
        "summary": "",
        "static_observations": "",
        "raw_observations_json": "",
        "xai_ms": "",
        "status": "",
        "error": "",
    }


def analyze_one(root, validation_row, manifest_row, detector, build_explanation, render):
    result = base_result(validation_row)
    started = time.perf_counter()
    try:
        if manifest_row['excluded_reason']:
            raise ValueError('manifest excludes this sample')
        if manifest_row['expected_class'] != validation_row['expected_class']:
            raise ValueError('validation label does not match manifest')
        raw = load_sample(root, manifest_row)
        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash != validation_row["sample_sha256"].lower():
            raise ValueError("검증 결과와 현재 표본 SHA-256이 다릅니다")

        technical = build_explanation(detector, raw)
        rendered = render(technical)
        model = technical["model_result"]
        xai_ratio = float(model["ratio"])
        validation_ratio = float(validation_row["ratio"])
        ratio_delta = abs(validation_ratio - xai_ratio)
        fidelity_ok = (
            model["verdict"] == "suspicious"
            and ratio_delta <= RATIO_TOLERANCE
        )
        if not fidelity_ok:
            raise ValueError(
                "XAI 재계산 판정이 검증 결과와 일치하지 않습니다: "
                f"verdict={model['verdict']}, ratio_delta={ratio_delta:.10f}"
            )

        impacts = {item["id"]: item for item in technical["group_impacts"]}
        positive = [item for item in technical["group_impacts"] if item["impact"] > 0]
        top = positive[0] if positive else None

        result.update(
            xai_verdict=model["verdict"],
            xai_ratio=f"{xai_ratio:.4f}",
            ratio_delta=f"{ratio_delta:.10f}",
            fidelity_ok="True",
            malware_proximity=f"{float(model['malware_proximity']):.4f}",
            d_mal=f"{float(model['d_mal']):.4f}",
            d_ben=f"{float(model['d_ben']):.4f}",
            top_group=top["name"] if top else "",
            top_group_impact=f"{top['impact']:.4f}" if top else "",
            general_impact=f"{impacts['general']['impact']:.4f}",
            sections_impact=f"{impacts['sections']['impact']:.4f}",
            datadirectories_impact=f"{impacts['datadirectories']['impact']:.4f}",
            summary=rendered["summary"],
            static_observations=" | ".join(rendered["static_observations"]),
            raw_observations_json=json.dumps(
                technical["observations"], ensure_ascii=False, sort_keys=True
            ),
            status="ok",
            error="",
        )
    except Exception as exc:
        result.update(status="error", error=f"{type(exc).__name__}: {exc}")
    finally:
        result["xai_ms"] = f"{(time.perf_counter() - started) * 1000:.3f}"
    return result


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--xai-project", type=pathlib.Path, default=XAI_PROJECT)
    parser.add_argument("--out", type=pathlib.Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    runtime = root / "frozen_runtime"
    output = (
        args.out or root / "results" / "suspicious_xai_results.csv"
    ).resolve()

    verify_runtime(runtime)
    manifest_rows = read_manifest(root / "manifest.csv")
    manifest_by_container = {(row['expected_class'], row['container_name']): row for row in manifest_rows}
    suspicious = read_validation_results(root / "results" / "validation_results.csv")

    sys.path.insert(0, str(runtime))
    import pe_features
    import triage

    bundle = triage.check_bundle(joblib.load(runtime / "eg_index.joblib"))
    detector = FrozenDetector(pe_features, triage, bundle)

    xai_project = args.xai_project.resolve()
    sys.path.insert(0, str(xai_project))
    from explainers.proximity import build_explanation
    from renderers.korean import render_explanation

    results = []
    for validation_row in suspicious:
        container_name = validation_row["container_name"]
        manifest_row = manifest_by_container.get((validation_row['expected_class'], container_name))
        if manifest_row is None:
            result = base_result(validation_row)
            result.update(status="error", error="manifest 행을 찾을 수 없습니다")
        else:
            result = analyze_one(
                root,
                validation_row,
                manifest_row,
                detector,
                build_explanation,
                render_explanation,
            )
        results.append(result)
        print(
            f"{container_name}: status={result['status']} "
            f"top_group={result['top_group']}"
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    if output.exists():
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = output.with_name(f"{output.stem}_before_{stamp}{output.suffix}")
        shutil.copy2(output, backup)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(results)
    os.replace(temporary, output)

    errors = sum(row["status"] != "ok" for row in results)
    fidelity = sum(row["fidelity_ok"] == "True" for row in results)
    print(f"results={output}")
    if backup:
        print(f"backup={backup}")
    print(f"rows={len(results)}")
    print(f"fidelity_ok={fidelity}")
    print(f"errors={errors}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
