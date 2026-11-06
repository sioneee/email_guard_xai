from pathlib import Path
from project_paths import DATASET_DIR

from adapters.knn295 import Knn295Detector


DATASET_DIR = DATASET_DIR / "extracted_temp"
MAX_FILES = 100


def main():
    detector = Knn295Detector()

    files = sorted(DATASET_DIR.glob("*.vir"))[:MAX_FILES]

    if not files:
        print(f".vir 파일을 찾지 못했습니다: {DATASET_DIR}")
        return

    print(f"검사 대상: 최대 {len(files)}개")

    for number, file_path in enumerate(files, start=1):
        try:
            file_bytes = file_path.read_bytes()
            _, vector = detector.extract(file_bytes)
            result = detector.score_vector(vector)

            verdict = result["verdict"]
            ratio = result["ratio"]

            if number % 10 == 0:
                print(f"{number}/{len(files)} 검사 중...")

            if verdict == "suspicious":
                print("\n의심 파일을 찾았습니다.")
                print(f"파일 경로: {file_path}")
                print(f"판정: {verdict}")
                print(f"ratio: {ratio}")
                return

        except Exception as error:
            print(f"건너뜀: {file_path.name} ({type(error).__name__})")

    print("\n처음 검사한 파일에서는 suspicious 판정이 없었습니다.")
    print("MAX_FILES 값을 200 또는 500으로 늘려 다시 실행하세요.")


if __name__ == "__main__":
    main()