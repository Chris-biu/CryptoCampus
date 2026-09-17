from collections.abc import Generator
from pathlib import Path
import sys

import pytest
import yaml
from fastapi.testclient import TestClient


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SERVER_ROOT = PROJECT_ROOT / "server"
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

from app.main import create_app  # noqa: E402


@pytest.fixture(scope="session")
def canonical_openapi() -> dict:
    with (PROJECT_ROOT / "docs" / "api" / "openapi.yaml").open(encoding="utf-8") as source:
        document = yaml.safe_load(source)
    assert isinstance(document, dict)
    return document


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app) -> Generator[TestClient, None, None]:
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
