import os
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()


pe_features_path = os.getenv("EMAIL_GUARD_PE_FEATURES")
index_path = os.getenv("EMAIL_GUARD_INDEX")

if not pe_features_path:
    raise RuntimeError(
        ".env 파일에 EMAIL_GUARD_PE_FEATURES 경로가 없습니다."
    )

if not index_path:
    raise RuntimeError(
        ".env 파일에 EMAIL_GUARD_INDEX 경로가 없습니다."
    )


PE_FEATURES_PATH = Path(pe_features_path)
INDEX_PATH = Path(index_path)


def check_backend_files():
    missing = []

    if not PE_FEATURES_PATH.is_file():
        missing.append(str(PE_FEATURES_PATH))

    if not INDEX_PATH.is_file():
        missing.append(str(INDEX_PATH))

    if missing:
        raise FileNotFoundError(
            "필요한 기존 프로젝트 파일을 찾을 수 없습니다:\n"
            + "\n".join(missing)
        )