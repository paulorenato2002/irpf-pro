"""Matriz de permissões do RLS (desenho: docs/superpowers/specs/2026-11-23-hardening-banco-design.md).

Roda contra o estado atual do banco; use --apply <arquivo.sql> para ensaiar SQL novo
(aplicado só dentro da transação, que sempre é revertida).
"""
from __future__ import annotations

import itertools
import os
from pathlib import Path

import psycopg
import pytest

from sandbox import APP_TABLES, OPS, PROFILES, rls_sandbox

ROOT = Path(__file__).resolve().parent.parent

W = {"select", "insert", "update", "delete"}
RW = {"select", "insert", "update"}
SEL = {"select"}
EXPECTED: dict[str, dict[str, set[str]]] = {
    "manager": {"team_members": SEL, "clients": W, "client_private": W, "documents": W,
                "contact_log": W, "declaration_checkpoints": W, "daily_snapshots": RW},
    "reviewer": {"team_members": SEL, "clients": W, "client_private": RW, "documents": W,
                 "contact_log": W, "declaration_checkpoints": W, "daily_snapshots": RW},
    "preparer": {"team_members": SEL, "clients": RW, "client_private": SEL, "documents": W,
                 "contact_log": RW, "declaration_checkpoints": RW, "daily_snapshots": RW},
    "read_only": {**{t: SEL for t in APP_TABLES}, "daily_snapshots": RW},
    "inactive": {},
    "outsider": {},
    "anon": {},
}
EXPECTED["status_only"] = EXPECTED["preparer"]

PROFILE_NAMES = [*PROFILES, "anon"]


@pytest.fixture(scope="module")
def matrix_results(request: pytest.FixtureRequest):
    if not os.environ.get("DATABASE_URL"):
        pytest.skip("DATABASE_URL não definida (crie o .env.local)")
    files = [ROOT / name for name in request.config.getoption("--apply")]
    with rls_sandbox(files) as sandbox:  # transação curta, desfeita ao sair
        return sandbox.matrix_results()


@pytest.mark.parametrize("profile,table,op", list(itertools.product(PROFILE_NAMES, APP_TABLES, OPS)))
def test_matrix(matrix_results, profile, table, op):
    expected = op in EXPECTED[profile].get(table, set())
    assert matrix_results[(profile, table, op)] == expected, (
        f"{profile} {'deveria poder' if expected else 'não deveria poder'} {op} em {table}"
    )


def test_deactivated_member_loses_access_immediately(sandbox):
    count_sql = r"select count(*) from public.clients where normalized_name like '\_\_teste\_\_%'"
    with sandbox.as_profile("preparer") as cur:
        cur.execute(count_sql)
        assert cur.fetchone()[0] == 4  # controle positivo: membro ativo enxerga os clientes de teste
    with sandbox.admin() as cur:
        cur.execute("update public.team_members set active = false where name = '__teste__preparer'")
    with sandbox.as_profile("preparer") as cur:
        cur.execute(count_sql)
        assert cur.fetchone()[0] == 0


def test_upserts_used_by_app(sandbox):
    cid, bare = sandbox.fake_client_id, sandbox.bare_client_id
    checkpoint = (
        "insert into public.declaration_checkpoints (client_id, step_key, step_label, completed) "
        "values (%s, 'novo', 'Novo', true) on conflict (client_id, step_key) do update "
        "set completed = excluded.completed"
    )
    snapshot = (
        "insert into public.daily_snapshots (reference_date) values ('1999-02-02') "
        "on conflict (reference_date) do update set updated_at = now()"
    )
    private = (
        "insert into public.client_private (client_id, cpf) values (%s, '000.000.000-00') "
        "on conflict (client_id) do update set cpf = excluded.cpf"
    )
    with sandbox.as_profile("status_only") as cur:
        cur.execute(checkpoint, (cid,))  # caminho de insert
        cur.execute(checkpoint, (cid,))  # caminho de update (conflito)
    with sandbox.as_profile("read_only") as cur:
        cur.execute(snapshot)
        cur.execute(snapshot)
    with sandbox.as_profile("manager") as cur:
        cur.execute(private, (bare,))  # insert
        cur.execute(private, (cid,))  # update
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with sandbox.as_profile("preparer") as cur:
            cur.execute(private, (cid,))


def test_has_sector_tolerates_spaces(sandbox):
    with sandbox.admin() as cur:
        cur.execute(
            "update public.team_members set allowed_sectors = 'Comercial, Revisão, Cadastros' "
            "where name = '__teste__reviewer'"
        )
    with sandbox.as_profile("reviewer") as cur:
        cur.execute("delete from public.client_private where client_id = %s", (sandbox.fake_client_ids[2],))
        assert cur.rowcount == 1  # com Cadastros (mesmo com espaço depois da vírgula), pode
    with sandbox.admin() as cur:
        cur.execute(
            "update public.team_members set allowed_sectors = 'Comercial, Revisão' "
            "where name = '__teste__reviewer'"
        )
    with sandbox.as_profile("reviewer") as cur:
        cur.execute("delete from public.client_private where client_id = %s", (sandbox.fake_client_ids[1],))
        assert cur.rowcount == 0  # sem Cadastros, não pode


def test_backfill_is_case_insensitive(sandbox):
    with sandbox.admin() as cur:
        cur.execute(
            "update public.team_members set auth_user_id = null, email = 'Preparer@Example.Test' "
            "where name = '__teste__preparer'"
        )
        cur.execute("select private.backfill_auth_user_ids()")
        assert cur.fetchone()[0] >= 1
        cur.execute("select auth_user_id::text from public.team_members where name = '__teste__preparer'")
        assert cur.fetchone()[0] == sandbox.uids["preparer"]
