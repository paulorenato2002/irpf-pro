"""Fase 1b: senha gov.br cifrada, acessada só por funções com auditoria.

Antes de aplicar o SQL, estes testes devem falhar (funções inexistentes). Para ensaiar:
  python -m pytest tests/test_gov_password.py --apply supabase_gov_password.sql
  python -m pytest tests/test_gov_password.py --apply supabase_gov_password.sql --apply supabase_gov_password_finalize.sql
Nunca comparam nem imprimem senhas reais: só os valores fictícios abaixo.
"""
from __future__ import annotations

import psycopg
import pytest


def _plain_column_exists(sandbox) -> bool:
    with sandbox.admin() as cur:
        cur.execute(
            "select 1 from information_schema.columns where table_schema = 'public' "
            "and table_name = 'client_private' and column_name = 'gov_password'"
        )
        return cur.fetchone() is not None


def _set(sandbox, profile: str, client_id: int, value: str) -> None:
    with sandbox.as_profile(profile) as cur:
        cur.execute("select public.set_gov_password(%s, %s)", (client_id, value))


def _reveal(sandbox, profile: str, client_id: int):
    with sandbox.as_profile(profile) as cur:
        cur.execute("select public.reveal_gov_password(%s)", (client_id,))
        return cur.fetchone()[0]


def test_reveal_returns_plaintext_and_writes_audit(sandbox):
    cid = sandbox.fake_client_id
    _set(sandbox, "manager", cid, "senha-teste-1")
    assert _reveal(sandbox, "preparer", cid) == "senha-teste-1"
    with sandbox.admin() as cur:
        cur.execute(
            "select actor::text, actor_email, action from public.audit_log "
            "where client_id = %s order by id",
            (cid,),
        )
        rows = cur.fetchall()
    assert rows == [
        (sandbox.uids["manager"], "manager@example.test", "set_gov_password"),
        (sandbox.uids["preparer"], "preparer@example.test", "reveal_gov_password"),
    ]


def test_read_only_member_with_sector_can_reveal(sandbox):
    cid = sandbox.fake_client_id
    _set(sandbox, "manager", cid, "senha-teste-2")
    assert _reveal(sandbox, "read_only", cid) == "senha-teste-2"


def test_set_requires_can_manage(sandbox):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        _set(sandbox, "preparer", sandbox.fake_client_id, "senha-teste-3")


@pytest.mark.parametrize("profile", ["outsider", "inactive", "anon"])
def test_reveal_denied_for_non_members(sandbox, profile):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        _reveal(sandbox, profile, sandbox.fake_client_id)


def test_ciphertext_is_not_plaintext(sandbox):
    cid = sandbox.fake_client_id
    _set(sandbox, "manager", cid, "senha-teste-1")
    with sandbox.admin() as cur:
        cur.execute("select gov_password_enc from public.client_secrets where client_id = %s", (cid,))
        stored = bytes(cur.fetchone()[0])
    assert b"senha-teste-1" not in stored


def test_audit_log_and_secrets_unreadable_by_members(sandbox):
    for statement in (
        "select count(*) from public.audit_log",
        "insert into public.audit_log (action) values ('x')",
        "select count(*) from public.client_secrets",
        "insert into public.client_secrets (client_id, gov_password_enc) values (1, '\\x00')",
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with sandbox.as_profile("manager") as cur:
                cur.execute(statement)


def test_has_flag_follows_set_and_clear(sandbox):
    cid = sandbox.fake_client_id
    flag_sql = "select has_gov_password from public.client_private where client_id = %s"
    _set(sandbox, "manager", cid, "senha-teste-1")
    with sandbox.as_profile("preparer") as cur:
        cur.execute(flag_sql, (cid,))
        assert cur.fetchone()[0] is True
    _set(sandbox, "manager", cid, "")  # valor em branco limpa a senha
    with sandbox.as_profile("preparer") as cur:
        cur.execute(flag_sql, (cid,))
        assert cur.fetchone()[0] is False
    assert _reveal(sandbox, "preparer", cid) is None


def test_missing_key_fails_loudly(sandbox):
    with sandbox.admin() as cur:
        cur.execute("delete from vault.secrets where name = 'gov_password_key'")
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        _set(sandbox, "manager", sandbox.fake_client_id, "senha-teste-4")


def test_plaintext_write_by_old_app_is_encrypted(sandbox):
    if not _plain_column_exists(sandbox):
        pytest.skip("coluna de texto puro já removida (finalize aplicado)")
    cid = sandbox.fake_client_id
    # o seed grava 'senha-ficticia-1' em texto puro, como faria o app antigo
    assert _reveal(sandbox, "preparer", cid) == "senha-ficticia-1"
    with sandbox.as_profile("manager") as cur:
        cur.execute("update public.client_private set gov_password = 'nova-senha-x' where client_id = %s", (cid,))
    assert _reveal(sandbox, "preparer", cid) == "nova-senha-x"


def test_set_clears_plaintext_column(sandbox):
    if not _plain_column_exists(sandbox):
        pytest.skip("coluna de texto puro já removida (finalize aplicado)")
    cid = sandbox.fake_client_id
    _set(sandbox, "manager", cid, "senha-teste-5")
    with sandbox.admin() as cur:
        cur.execute("select gov_password from public.client_private where client_id = %s", (cid,))
        assert cur.fetchone()[0] is None


def test_plaintext_column_is_gone_after_finalize(sandbox):
    if _plain_column_exists(sandbox):
        pytest.skip("finalize ainda não aplicado")
    with sandbox.as_profile("manager") as cur:
        cur.execute("select count(*) from public.client_private")
        assert cur.fetchone()[0] >= 3
    with pytest.raises(psycopg.errors.UndefinedColumn):
        with sandbox.as_profile("manager") as cur:
            cur.execute("select gov_password from public.client_private")
