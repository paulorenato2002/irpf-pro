from __future__ import annotations

import pytest

from sandbox import residue_snapshot, rls_sandbox


def test_profiles_resolve_to_fake_uid(sandbox):
    with sandbox.as_profile("manager") as cur:
        cur.execute("select auth.uid()::text, current_user")
        uid, user = cur.fetchone()
    assert uid == sandbox.uids["manager"]
    assert user == "authenticated"


def test_anon_has_no_uid(sandbox):
    with sandbox.as_profile("anon") as cur:
        cur.execute("select auth.uid(), current_user")
        uid, user = cur.fetchone()
    assert uid is None
    assert user == "anon"


def test_sandbox_refuses_sql_with_commit(require_db, tmp_path):
    risky = tmp_path / "risky.sql"
    risky.write_text("insert into public.clients (normalized_name, full_name) values ('x', 'x');\ncommit;\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="begin/commit"):
        with rls_sandbox([risky]):
            pass


def test_sandbox_leaves_no_residue(require_db):
    before = residue_snapshot()
    with rls_sandbox() as sb:
        with sb.admin() as cur:
            cur.execute("select count(*) from public.clients where normalized_name like '\\_\\_teste\\_\\_%'")
            assert cur.fetchone()[0] >= 3
    assert residue_snapshot() == before
    assert before["clients_fake"] == 0
