"""Shared locations; relative environment values are relative to this repository."""
import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / '.env', override=False)


def configured_path(name, default):
    path = Path(os.environ.get(name) or default).expanduser()
    return (PROJECT_ROOT / path).resolve() if not path.is_absolute() else path.resolve()


XAI_DATA_DIR = configured_path('EMAIL_GUARD_XAI_DATA_DIR', '../email_guard_xai_data')
DATASET_DIR = configured_path('EMAIL_GUARD_DATASET_DIR', '../email_guard_dataset')
WINDOWS_DIR = configured_path('EMAIL_GUARD_WINDOWS_DIR', os.getenv('SystemRoot', '../windows-reference'))
