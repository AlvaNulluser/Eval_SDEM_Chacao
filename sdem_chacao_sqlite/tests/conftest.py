"""Configuración de los tests.

Los tests corren contra un archivo SQLite temporal para no tocar la base real.
La aplicación usa `DATABASE_URL` cuando está definida.
"""

import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

_TMP_DIR = Path(tempfile.mkdtemp(prefix="sdem-chacao-tests-"))
atexit.register(lambda: shutil.rmtree(_TMP_DIR, ignore_errors=True))
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DIR / 'test.db'}"

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database import Base, engine, init_db


@pytest.fixture(autouse=True)
def fresh_database():
    """Recrea el esquema y los usuarios de prueba antes de cada test."""
    Base.metadata.drop_all(bind=engine)
    init_db()
    yield


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def auth(client, username, password):
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}
