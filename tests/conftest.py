"""Configuração dos testes de banco: tudo roda em transação revertida (ver sandbox.py)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from sandbox import rls_sandbox

ROOT = Path(__file__).resolve().parent.parent


def _load_env_local() -> None:
    path = ROOT / ".env.local"
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_env_local()


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--apply",
        action="append",
        default=[],
        help="Arquivo SQL (relativo à raiz do projeto) aplicado dentro da sandbox; repetível.",
    )


@pytest.fixture
def require_db() -> None:
    if not os.environ.get("DATABASE_URL"):
        pytest.skip("DATABASE_URL não definida (crie o .env.local)")


@pytest.fixture
def sandbox(request: pytest.FixtureRequest, require_db: None):
    files = [ROOT / name for name in request.config.getoption("--apply")]
    with rls_sandbox(files) as sb:
        yield sb
