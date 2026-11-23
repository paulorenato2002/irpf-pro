"""Checagem SOMENTE LEITURA do acesso anonimo e do signup do Supabase de produção.

Usa SUPABASE_URL e SUPABASE_ANON_KEY (ambiente ou .env.local). Nunca cria conta nem grava dados.
Sai com código 1 se algum item falhar.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TABLES = [
    "team_members",
    "clients",
    "client_private",
    "documents",
    "contact_log",
    "declaration_checkpoints",
    "daily_snapshots",
]


def load_env_local() -> None:
    path = ROOT / ".env.local"
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def get_json(url: str, anon_key: str) -> tuple[int, object]:
    request = urllib.request.Request(
        url, headers={"apikey": anon_key, "Authorization": f"Bearer {anon_key}"}
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.loads(response.read().decode("utf-8") or "null")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, body


def main() -> int:
    load_env_local()
    url = os.environ.get("SUPABASE_URL", "").rstrip("/")
    anon_key = os.environ.get("SUPABASE_ANON_KEY", "")
    if not url or not anon_key:
        print("FALTAM SUPABASE_URL e SUPABASE_ANON_KEY (ambiente ou .env.local)")
        return 2

    failures = 0
    for table in TABLES:
        status, body = get_json(f"{url}/rest/v1/{table}?select=*&limit=1", anon_key)
        leaked = status == 200 and isinstance(body, list) and len(body) > 0
        if leaked:
            print(f"FAIL anon lê dados de {table}")
            failures += 1
        else:
            print(f"ok   anon sem dados em {table} (HTTP {status})")

    status, settings = get_json(f"{url}/auth/v1/settings", anon_key)
    if status == 200 and isinstance(settings, dict) and settings.get("disable_signup") is True:
        print("ok   cadastro público desligado (disable_signup = true)")
    else:
        print("FAIL cadastro público ligado ou não verificado (desligue 'Allow new users to sign up')")
        failures += 1

    print("OK" if failures == 0 else f"FAIL ({failures} problema(s))")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
