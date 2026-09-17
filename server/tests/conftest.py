from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app.db.session import create_db_engine, create_session_factory, init_database
from app.main import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


@pytest.fixture
def db_engine(tmp_path) -> Generator[Engine, None, None]:
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'test.db').as_posix()}"
    engine = create_db_engine(database_url)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Generator[Session, None, None]:
    init_database(db_engine)
    session_factory = create_session_factory(db_engine)

    with session_factory() as session:
        yield session
