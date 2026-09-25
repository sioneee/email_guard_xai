import csv
import hashlib
from datetime import date
from pathlib import Path
from project_paths import XAI_DATA_DIR, WINDOWS_DIR


OUTPUT_PATH = XAI_DATA_DIR / "manifests/manifest_controls.csv"

SYSTEM32_DIR = WINDOWS_DIR / "System32"

NON_PE_PATHS = [
    WINDOWS_DIR / "win.ini",
    WINDOWS_DIR / "System32/drivers/etc/hosts",
    WINDOWS_DIR / "System32/drivers/etc/protocol",
    WINDOWS_DIR / "System32/drivers/etc/services",
]


def sha256_of(file_path):
    digest = hashlib.sha256()

    with file_path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)

    return digest.hexdigest()


def is_pe(file_path):
    try:
        with file_path.open("rb") as file:
            return file.read(2) == b"MZ"
    except OSError:
        return False


def main():
    records = []
    seen_hashes = set()

    # 정상 Windows PE 파일 최대 100개
    for file_path in sorted(SYSTEM32_DIR.iterdir()):
        if len([
            row for row in records
            if row["true_label"] == "benign"
        ]) >= 100:
            break

        if not file_path.is_file() or not is_pe(file_path):
            continue

        try:
            sha256 = sha256_of(file_path)
        except OSError:
            continue

        if sha256 in seen_hashes:
            continue

        seen_hashes.add(sha256)

        records.append({
            "sample_id": f"benign_{len(records) + 1:04d}",
            "path": str(file_path),
            "sha256": sha256,
            "true_label": "benign",
            "source": "Windows_System32",
            "overlap_status": "unknown",
            "purpose": "xai_control_validation",
            "manifested_at": date.today().isoformat(),
        })

    # 비PE 파일
    non_pe_number = 1

    for file_path in NON_PE_PATHS:
        if not file_path.exists() or not file_path.is_file():
            continue

        records.append({
            "sample_id": f"nonpe_{non_pe_number:04d}",
            "path": str(file_path),
            "sha256": sha256_of(file_path),
            "true_label": "non_pe",
            "source": "Windows_configuration",
            "overlap_status": "not_applicable",
            "purpose": "robustness_validation",
            "manifested_at": date.today().isoformat(),
        })

        non_pe_number += 1

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=records[0].keys(),
        )
        writer.writeheader()
        writer.writerows(records)

    benign_count = sum(
        row["true_label"] == "benign"
        for row in records
    )

    non_pe_count = sum(
        row["true_label"] == "non_pe"
        for row in records
    )

    print(f"정상 PE: {benign_count}개")
    print(f"비PE: {non_pe_count}개")
    print(f"결과 파일: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()