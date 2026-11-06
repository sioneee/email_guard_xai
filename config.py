from project_paths import configured_path

PE_FEATURES_PATH = configured_path('EMAIL_GUARD_PE_FEATURES', '../email_guard/ml/pe_features.py')
INDEX_PATH = configured_path('EMAIL_GUARD_INDEX', '../email_guard/backend/eg_index.joblib')
TRIAGE_PATH = configured_path('EMAIL_GUARD_TRIAGE', str(PE_FEATURES_PATH.parent / 'triage.py'))


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
