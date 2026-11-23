"""Sandbox de testes de RLS.

Tudo roda numa transação que SEMPRE termina em rollback: usuários e clientes fictícios
são criados dentro dela, o SQL novo pode ser aplicado dentro dela (DDL do Postgres é
transacional) e nada permanece no banco depois. Não há autocommit em lugar nenhum.

A transação fica aberta o mínimo possível (segura locks de DDL): a matriz de permissões
roda inteira num único bloco DO, em poucos segundos.
"""
from __future__ import annotations

import json
import os
import re
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Sequence

import psycopg

APP_TABLES = [
    "team_members",
    "clients",
    "client_private",
    "documents",
    "contact_log",
    "declaration_checkpoints",
    "daily_snapshots",
]
OPS = ["select", "insert", "update", "delete"]


def _team(sectors: str, manage: bool, level: str, active: bool = True) -> dict:
    return {
        "allowed_sectors": sectors,
        "can_manage_records": manage,
        "permission_level": level,
        "active": active,
    }


PROFILES: dict[str, dict] = {
    "manager": {"team": _team("Comercial,Preenchimento,Revisão,Cadastros", True, "full")},
    "reviewer": {"team": _team("Revisão", True, "full")},
    "preparer": {"team": _team("Preenchimento", False, "full")},
    "status_only": {"team": _team("Preenchimento", False, "status_only")},
    "read_only": {"team": _team("Revisão", False, "read_only")},
    "inactive": {"team": _team("Preenchimento", False, "full", active=False)},
    "outsider": {"team": None},
}

FAKE_CLIENT_NAMES = [f"__teste__cliente_{n}" for n in (1, 2, 3)]
BARE_CLIENT_NAME = "__teste__cliente_4"  # sem linha em client_private: alvo dos inserts/deletes


_TRANSACTION_CONTROL = re.compile(r"(?im)^\s*(commit|start\s+transaction|begin(\s+(work|transaction))?)\s*;")


def profile_email(profile: str) -> str:
    return f"{profile}@example.test"


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        raise RuntimeError("DATABASE_URL não definida (crie o .env.local)")
    return url


def _lit(value: object) -> str:
    """Literal SQL para valores internos e constantes do próprio teste."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return "'" + str(value).replace("'", "''") + "'"


def _claims(profile: str, uid: str | None) -> dict:
    if profile == "anon":
        return {"role": "anon"}
    return {"sub": uid, "role": "authenticated", "email": profile_email(profile)}


class Sandbox:
    def __init__(self, conn: psycopg.Connection) -> None:
        self.conn = conn
        self.uids: dict[str, str] = {}
        self.fake_client_ids: list[int] = []
        self.bare_client_id: int = 0

    @property
    def fake_client_id(self) -> int:
        return self.fake_client_ids[0]

    @contextmanager
    def admin(self) -> Iterator[psycopg.Cursor]:
        """Cursor da sessão do dono (sem RLS)."""
        cur = self.conn.cursor()
        try:
            yield cur
        finally:
            cur.close()

    @contextmanager
    def as_profile(self, profile: str) -> Iterator[psycopg.Cursor]:
        """Cursor com o papel e o JWT do perfil. Em erro, volta ao savepoint e relança."""
        cur = self.conn.cursor()
        cur.execute("savepoint as_profile")
        try:
            cur.execute("set local role anon" if profile == "anon" else "set local role authenticated")
            claims = _claims(profile, self.uids.get(profile))
            cur.execute("select set_config('request.jwt.claims', %s, true)", (json.dumps(claims),))
            yield cur
        except BaseException:
            cur.execute("rollback to savepoint as_profile")
            cur.execute("release savepoint as_profile")
            cur.close()
            raise
        else:
            cur.execute("reset role")
            cur.execute("select set_config('request.jwt.claims', '', true)")
            cur.execute("release savepoint as_profile")
            cur.close()

    # ------------------------------------------------------------------ setup
    def _setup(self, apply: Sequence[Path]) -> None:
        with self.admin() as cur:
            if any("gov_password" in Path(p).name for p in apply):
                # chave de teste, só dentro da transação (em produção ela é criada à mão, uma vez)
                cur.execute(
                    "select vault.create_secret(encode(extensions.gen_random_bytes(32), 'hex'), 'gov_password_key') "
                    "where not exists (select 1 from vault.secrets where name = 'gov_password_key')"
                )
            for path in apply:
                text = Path(path).read_text(encoding="utf-8")
                if _TRANSACTION_CONTROL.search(text):
                    raise RuntimeError(f"{path} contém begin/commit: recusado (quebraria o rollback da sandbox)")
                cur.execute(text)
            cur.execute(
                "select table_name, column_name from information_schema.columns "
                "where table_schema = 'public' and "
                "((table_name = 'team_members' and column_name = 'auth_user_id') "
                "or (table_name = 'client_private' and column_name = 'gov_password'))"
            )
            present = {(t, c) for t, c in cur.fetchall()}
            has_auth_col = ("team_members", "auth_user_id") in present
            has_plain_password = ("client_private", "gov_password") in present

            statements: list[str] = []
            for key, spec in PROFILES.items():
                uid = str(uuid.uuid4())
                self.uids[key] = uid
                email = profile_email(key)
                statements.append(
                    "insert into auth.users (id, aud, role, email) values "
                    f"({_lit(uid)}, 'authenticated', 'authenticated', {_lit(email)})"
                )
                team = spec["team"]
                if team is None:
                    continue
                columns = ["name", "display_name", "email", "role", "allowed_sectors",
                           "can_manage_records", "permission_level", "active"]
                values: list = [f"__teste__{key}", f"__teste__{key}", email, "teste",
                                team["allowed_sectors"], team["can_manage_records"],
                                team["permission_level"], team["active"]]
                if has_auth_col:
                    columns.append("auth_user_id")
                    values.append(uid)
                statements.append(
                    f"insert into public.team_members ({', '.join(columns)}) "
                    f"values ({', '.join(_lit(v) for v in values)})"
                )

            all_names = FAKE_CLIENT_NAMES + [BARE_CLIENT_NAME]
            statements.append(
                "insert into public.clients (normalized_name, full_name) values "
                + ", ".join(f"({_lit(n)}, {_lit(n.upper())})" for n in all_names)
            )
            fake_in = ", ".join(_lit(n) for n in FAKE_CLIENT_NAMES)
            private_cols = "client_id, cpf, phone" + (", gov_password" if has_plain_password else "")
            private_vals = "id, '000.000.000-0' || right(normalized_name, 1), '00000000000'" + (
                ", 'senha-ficticia-' || right(normalized_name, 1)" if has_plain_password else ""
            )
            statements += [
                f"insert into public.client_private ({private_cols}) "
                f"select {private_vals} from public.clients where normalized_name in ({fake_in})",
                "insert into public.documents (client_id, document_type, institution, status, control_key) "
                f"select id, 'TESTE', 'TESTE', 'PENDENTE', normalized_name from public.clients where normalized_name in ({fake_in})",
                "insert into public.declaration_checkpoints (client_id, step_key, step_label) "
                f"select id, 'teste', 'Teste' from public.clients where normalized_name in ({fake_in})",
                "insert into public.contact_log (client_id, contact_date) "
                f"select id, now() from public.clients where normalized_name in ({fake_in})",
                "insert into public.daily_snapshots (reference_date) values ('1999-01-01')",
            ]
            cur.execute(";\n".join(statements))

            cur.execute(
                "select id, normalized_name from public.clients where normalized_name like %s order by normalized_name",
                (r"\_\_teste\_\_cliente\_%",),
            )
            ids = {name: cid for cid, name in cur.fetchall()}
            self.fake_client_ids = [ids[n] for n in FAKE_CLIENT_NAMES]
            self.bare_client_id = ids[BARE_CLIENT_NAME]

    # ----------------------------------------------------------------- matrix
    def _table_specs(self) -> dict[str, dict[str, str]]:
        cid, bare = self.fake_client_ids[0], self.bare_client_id
        return {
            "team_members": {
                "pred": "name = '__teste__preparer'",
                "insert": "insert into public.team_members (name, display_name, email, role, allowed_sectors, "
                          "can_manage_records, permission_level, active) values "
                          "('__teste__novo', 'x', 'novo@example.test', 'x', '', false, 'read_only', true)",
                "update": "update public.team_members set display_name = display_name where name = '__teste__preparer'",
            },
            "clients": {
                "pred": f"id = {cid}",
                "insert": "insert into public.clients (normalized_name, full_name) values ('__teste__novo', '__TESTE__ NOVO')",
                "update": f"update public.clients set full_name = full_name where id = {cid}",
            },
            "client_private": {
                "pred": f"client_id = {cid}",
                "insert": f"insert into public.client_private (client_id) values ({bare})",
                "update": f"update public.client_private set cpf = cpf where client_id = {cid}",
            },
            "documents": {
                "pred": f"client_id = {cid}",
                "insert": f"insert into public.documents (client_id, document_type, institution, status) values ({cid}, 'T', 'T', 'PENDENTE')",
                "update": f"update public.documents set status = status where client_id = {cid}",
            },
            "contact_log": {
                "pred": f"client_id = {cid}",
                "insert": f"insert into public.contact_log (client_id, contact_date) values ({cid}, now())",
                "update": f"update public.contact_log set channel = channel where client_id = {cid}",
            },
            "declaration_checkpoints": {
                "pred": f"client_id = {cid}",
                "insert": f"insert into public.declaration_checkpoints (client_id, step_key, step_label) values ({cid}, 'novo', 'Novo')",
                "update": f"update public.declaration_checkpoints set note = note where client_id = {cid}",
            },
            "daily_snapshots": {
                "pred": "reference_date = '1999-01-01'",
                "insert": "insert into public.daily_snapshots (reference_date) values ('1999-01-02')",
                "update": "update public.daily_snapshots set declaracoes = declaracoes where reference_date = '1999-01-01'",
            },
        }

    def matrix_results(self) -> dict[tuple[str, str, str], bool]:
        """Roda perfil x tabela x operação num único bloco DO e devolve se cada uma surtiu efeito.

        Cada operação roda numa subtransação que é desfeita ao fim (exceção planejada RLS01),
        então uma não interfere na outra. Negada = erro 42501 ou nenhuma linha afetada/visível.
        """
        specs = self._table_specs()
        blocks: list[str] = []
        for profile in [*PROFILES, "anon"]:
            role = "anon" if profile == "anon" else "authenticated"
            claims = json.dumps(_claims(profile, self.uids.get(profile)))
            for table in APP_TABLES:
                spec = specs[table]
                for op in OPS:
                    key = f"{profile}|{table}|{op}"
                    if op == "select":
                        action = f"select count(*) into c from public.{table} where {spec['pred']};"
                    elif op == "delete":
                        action = f"with r as (delete from public.{table} where {spec['pred']} returning 1) select count(*) into c from r;"
                    else:
                        action = f"with r as ({spec[op]} returning 1) select count(*) into c from r;"
                    blocks.append(
                        "  begin\n"
                        f"    set local role {role};\n"
                        f"    perform set_config('request.jwt.claims', {_lit(claims)}, true);\n"
                        f"    {action}\n"
                        f"    res := res || jsonb_build_object({_lit(key)}, c > 0);\n"
                        "    raise exception 'rls_rollback' using errcode = 'RLS01';\n"
                        "  exception\n"
                        f"    when insufficient_privilege then res := res || jsonb_build_object({_lit(key)}, false);\n"
                        "    when sqlstate 'RLS01' then null;\n"
                        "  end;\n"
                    )
        script = (
            "do $rls$\ndeclare c bigint; res jsonb := '{}'::jsonb;\nbegin\n"
            + "".join(blocks)
            + "  perform set_config('rls.results', res::text, true);\nend $rls$"
        )
        with self.admin() as cur:
            cur.execute(script)
            cur.execute("select current_setting('rls.results')")
            raw = json.loads(cur.fetchone()[0])
        return {tuple(k.split("|")): v for k, v in raw.items()}  # type: ignore[misc]

    def op_succeeds(self, profile: str, table: str, op: str) -> bool:
        if not hasattr(self, "_matrix_cache"):
            self._matrix_cache = self.matrix_results()
        return self._matrix_cache[(profile, table, op)]


@contextmanager
def rls_sandbox(apply: Sequence[Path] = ()) -> Iterator[Sandbox]:
    """Abre a transação, aplica os SQLs, cria os dados fictícios e SEMPRE desfaz tudo."""
    conn = psycopg.connect(_database_url(), autocommit=False, connect_timeout=20)
    try:
        sandbox = Sandbox(conn)
        sandbox._setup(apply)
        yield sandbox
    finally:
        try:
            conn.rollback()
        finally:
            conn.close()


def residue_snapshot() -> dict[str, int]:
    """Conta só o que seria resíduo de teste, numa conexão própria e somente leitura."""
    queries = {
        "clients_fake": r"select count(*) from public.clients where normalized_name like '\_\_teste\_\_%'",
        "team_fake": r"select count(*) from public.team_members where email like '%@example.test'",
        "auth_fake": r"select count(*) from auth.users where email like '%@example.test'",
        "policies": "select count(*) from pg_policies where schemaname = 'public'",
        "private_schema": "select count(*) from information_schema.schemata where schema_name = 'private'",
    }
    with psycopg.connect(_database_url(), connect_timeout=20) as conn:
        conn.read_only = True
        cur = conn.cursor()
        result = {}
        for name, query in queries.items():
            cur.execute(query)
            result[name] = cur.fetchone()[0]
        return result
