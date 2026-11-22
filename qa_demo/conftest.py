import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch, tmp_path):
    """Every test gets its own data dir and NO network keys.

    backend/.env (loaded by python-dotenv) may hold real API keys; setting these variables
    explicitly (even to "") stops dotenv from overriding them, so tests never call real services.
    """
    from app.config import get_settings

    for key, value in {
        "AEGIS_DATA_DIR": str(tmp_path / "data"),
        "AEGIS_MB_AUTH_KEY": "",
        "AEGIS_VT_API_KEY": "",
        "AEGIS_INTEL_OFFLINE": "true",
        "AEGIS_VAULT_PASSPHRASE": "test-vault-passphrase",
        "AEGIS_HMAC_SECRET": "test-hmac-secret",
        "AEGIS_DEMO_MODE": "true",
        "AEGIS_WATCH_USB": "false",
        "AEGIS_LOCAL_IOC_PATH": str(ROOT / "local_ioc.txt"),
        "AEGIS_REDACT_FILENAMES": "false",
    }.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(scope="session")
def drive(tmp_path_factory):
    """Fresh copy of the demo drive in a temp dir."""
    import generate_payloads as gp

    dest = tmp_path_factory.mktemp("usb")
    gp.generate(dest)
    return dest
