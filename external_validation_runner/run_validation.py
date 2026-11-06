"""Run the frozen EmailGuard triage model against the external validation set.

This runner deliberately does not import the backend application or make network
requests. Malware ZIP members are read into memory and are never extracted to disk.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import os
import pathlib
import shutil
import sys
import time
from collections import Counter
from datetime import datetime

import joblib
import pyzipper


MAX_SAMPLE_BYTES = 256 * 1024 * 1024

EXPECTED_RUNTIME_HASHES = {
    "pe_features.py": "c4dd47167c28a00c8412e08a0edf8738cdab4c4f1a153a8e9125a66fb8576076",
    "triage.py": "96fe806b6081ab5606b8104e6695b8f9eee289910ae51f5074cadf2f45dbacac",
    "eg_index.joblib": "ba02f65543b6b1114aee0da47cc0b840fad2c0716b31300b1e874e30240534cd",
}

RESULT_FIELDS = (
    "expected_class",
    "container_name",
    "sample_name",
    "sample_sha256",
    "size_bytes",
    "pe_valid",
    "predicted_verdict",
    "ratio",
    "d_mal",
    "d_ben",
    "latency_ms",
    "evaluation_status",
    "correct_strict",
    "caught_for_review",
    "source",
    "vt_used",
    "excluded_reason",
    "error",
)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_runtime(runtime: pathlib.Path) -> None:
    for name, expected in EXPECTED_RUNTIME_HASHES.items():
        path = runtime / name
        if not path.is_file():
            raise SystemExit(f"고정 런타임 파일이 없습니다: {path}")
        actual = sha256_file(path)
        if actual != expected:
            raise SystemExit(
                f"고정 런타임 해시 불일치: {name}\n"
                f"expected={expected}\nactual={actual}"
            )


def read_manifest(path: pathlib.Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        raise SystemExit(f"manifest가 비어 있습니다: {path}")
    required = {
        "expected_class",
        "container_name",
        "sample_name",
        "sample_sha256",
        "sample_size",
        "sample_is_pe",
        "excluded_reason",
        "error",
    }
    missing = sorted(required - set(rows[0]))
    if missing:
        raise SystemExit(f"manifest 필수 열이 없습니다: {missing}")
    seen = set()
    for row in rows:
        if row['expected_class'] not in {'benign', 'malware'}:
            raise SystemExit('manifest contains an unknown class')
        name = row['container_name']
        if not name or name in {'.', '..'} or any(c in name for c in '/\\:'):
            raise SystemExit('container_name must be a filename, not a path')
        key = (row['expected_class'], name)
        if key in seen:
            raise SystemExit(f'duplicate manifest entry: {key}')
        seen.add(key)
    return rows


def read_single_member(zip_path: pathlib.Path, expected_name: str) -> bytes:
    with pyzipper.AESZipFile(zip_path) as archive:
        archive.setpassword(b"infected")
        members = [info for info in archive.infolist() if not info.is_dir()]
        if len(members) != 1:
            raise ValueError(f"ZIP 내부 파일 수가 1이 아닙니다: {len(members)}")
        member = members[0]
        if member.filename != expected_name:
            raise ValueError(
                f"manifest 내부 파일명 불일치: {member.filename!r} != {expected_name!r}"
            )
        if member.file_size > MAX_SAMPLE_BYTES:
            raise ValueError(f"압축 해제 크기 제한 초과: {member.file_size}")
        raw = archive.read(member)
    if len(raw) != member.file_size:
        raise ValueError(
            f"압축 해제 크기 불일치: {len(raw)} != {member.file_size}"
        )
    return raw


def load_sample(root: pathlib.Path, row: dict[str, str]) -> bytes:
    expected_class = row["expected_class"]
    if expected_class == "benign":
        if (root / 'benign' / row['container_name']).stat().st_size > MAX_SAMPLE_BYTES:
            raise ValueError('sample size limit exceeded')
        raw = (root / "benign" / row["container_name"]).read_bytes()
    elif expected_class == "malware":
        raw = read_single_member(
            root / "malware" / row["container_name"], row["sample_name"]
        )
    else:
        raise ValueError(f"알 수 없는 expected_class: {expected_class!r}")

    if len(raw) > MAX_SAMPLE_BYTES:
        raise ValueError(f"표본 크기 제한 초과: {len(raw)}")
    actual_hash = hashlib.sha256(raw).hexdigest()
    if actual_hash != row["sample_sha256"].lower():
        raise ValueError(
            f"표본 SHA-256 불일치: {actual_hash} != {row['sample_sha256']}"
        )
    if row["sample_size"] and len(raw) != int(row["sample_size"]):
        raise ValueError(
            f"표본 크기 불일치: {len(raw)} != {row['sample_size']}"
        )
    if raw[:2] != b"MZ":
        raise ValueError("PE MZ 헤더가 없습니다")
    return raw


def empty_result(row: dict[str, str]) -> dict[str, object]:
    return {
        "expected_class": row["expected_class"],
        "container_name": row["container_name"],
        "sample_name": row["sample_name"],
        "sample_sha256": row["sample_sha256"],
        "size_bytes": row["sample_size"],
        "pe_valid": "",
        "predicted_verdict": "",
        "ratio": "",
        "d_mal": "",
        "d_ben": "",
        "latency_ms": "",
        "evaluation_status": "",
        "correct_strict": "",
        "caught_for_review": "",
        "source": "offline_triage",
        "vt_used": "False",
        "excluded_reason": row["excluded_reason"],
        "error": row["error"],
    }


def evaluate_row(root, row, bundle, pe_features, triage):
    result = empty_result(row)
    if row["excluded_reason"]:
        result["evaluation_status"] = "excluded"
        return result

    started = time.perf_counter()
    try:
        raw = load_sample(root, row)
        vector = pe_features.process(pe_features.raw_features(raw))
        if getattr(vector, "shape", None) != (295,):
            raise ValueError(f"특징 벡터 모양이 (295,)가 아닙니다: {vector.shape}")
        ratios, mal_distances, ben_distances = triage.ratios(bundle, vector)
        ratio = float(ratios[0])
        d_mal = float(mal_distances[0])
        d_ben = float(ben_distances[0])
        verdict = triage.verdict(ratio, bundle["t_low"], bundle["t_high"])

        strict_correct = (
            row["expected_class"] == "malware" and verdict == "차단"
        ) or (row["expected_class"] == "benign" and verdict == "통과")
        caught_for_review = (
            row["expected_class"] == "malware" and verdict in {"차단", "의심"}
        )
        if strict_correct:
            status = "correct"
        elif verdict == "의심":
            status = "review"
        else:
            status = "incorrect"

        result.update(
            size_bytes=len(raw),
            pe_valid="True",
            predicted_verdict=verdict,
            ratio=f"{ratio:.10f}" if math.isfinite(ratio) else "",
            d_mal=f"{d_mal:.10f}",
            d_ben=f"{d_ben:.10f}",
            evaluation_status=status,
            correct_strict=str(strict_correct),
            caught_for_review=(
                str(caught_for_review) if row["expected_class"] == "malware" else ""
            ),
            excluded_reason="",
            error="",
        )
    except Exception as exc:
        result.update(
            pe_valid="False",
            evaluation_status="error",
            error=f"{type(exc).__name__}: {exc}",
        )
    finally:
        result["latency_ms"] = f"{(time.perf_counter() - started) * 1000:.3f}"
    return result


def write_results(path: pathlib.Path, rows: list[dict[str, object]]) -> pathlib.Path | None:
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    if path.exists():
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = path.with_name(f"{path.stem}_before_{stamp}{path.suffix}")
        shutil.copy2(path, backup)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=RESULT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)
    return backup


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=pathlib.Path, required=True,
        help="manifest.csv와 데이터 폴더가 있는 외부 검증 루트",
    )
    parser.add_argument(
        "--out", type=pathlib.Path, default=None,
        help="결과 CSV 경로(기본: <root>/results/validation_results.csv)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    runtime = root / "frozen_runtime"
    output = (args.out or root / "results" / "validation_results.csv").resolve()

    verify_runtime(runtime)
    manifest_rows = read_manifest(root / "manifest.csv")

    sys.path.insert(0, str(runtime))
    import pe_features
    import triage

    bundle = triage.check_bundle(joblib.load(runtime / "eg_index.joblib"))
    if bundle["k"] != 10:
        raise SystemExit(f"고정 색인 k 불일치: {bundle['k']}")
    if bundle["meta"].get("dim") != 295:
        raise SystemExit(f"고정 색인 dim 불일치: {bundle['meta'].get('dim')}")
    if not math.isclose(bundle["t_low"], 0.010302916771992252, rel_tol=0, abs_tol=1e-15):
        raise SystemExit(f"고정 색인 t_low 불일치: {bundle['t_low']}")
    if not math.isclose(bundle["t_high"], 0.31328331566416295, rel_tol=0, abs_tol=1e-15):
        raise SystemExit(f"고정 색인 t_high 불일치: {bundle['t_high']}")

    results = [
        evaluate_row(root, row, bundle, pe_features, triage)
        for row in manifest_rows
    ]
    backup = write_results(output, results)

    statuses = Counter(str(row["evaluation_status"]) for row in results)
    verdicts = Counter(
        str(row["predicted_verdict"])
        for row in results
        if row["predicted_verdict"]
    )
    print(f"results={output}")
    if backup:
        print(f"backup={backup}")
    print(f"rows={len(results)}")
    print(f"statuses={dict(statuses)}")
    print(f"verdicts={dict(verdicts)}")
    return 1 if statuses.get("error", 0) else 0


if __name__ == "__main__":
    raise SystemExit(main())
