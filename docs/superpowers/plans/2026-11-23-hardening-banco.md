# Hardening do banco (Fase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fazer o banco Supabase do IRPF aplicar sozinho as permissões da equipe e tirar a senha gov.br da leitura em massa.

**Architecture:** RLS v2 com funções auxiliares em schema `private` que resolvem o perfil por `auth.uid()` -> `team_members`; o app Streamlit segue igual na Fase 1a. Na Fase 1b a senha gov.br fica criptografada (pgcrypto, chave no Vault) e só sai por RPC com auditoria. Não há staging: tudo é testado no próprio banco, dentro de uma transação que termina sempre em ROLLBACK (Postgres desfaz DDL), com usuários e clientes fictícios criados dentro dela. Só depois do ensaio verde o Paulo aplica o SQL de verdade.

**Tech Stack:** Postgres/Supabase (RLS, SQL functions, pgcrypto, Vault), Python 3.12, supabase-py 2.x, psycopg 3, pytest, Streamlit.

**Spec:** `docs/superpowers/specs/2026-11-23-hardening-banco-design.md`

## Global Constraints

- Nenhum teste grava de forma permanente: toda a suíte roda numa transação que termina em `rollback`, sem autocommit; os dados de teste são fictícios (`__teste__`, `@example.test`) e criados dentro da transação. Os testes nunca imprimem nem comparam valores reais de CPF, telefone ou senha.
- Arquivos SQL do repositório nunca contêm `begin` nem `commit` (rodariam a transação do ensaio ou do SQL Editor pelo meio); a sandbox recusa arquivo que tenha. Também não reabilitam RLS (já está ligado e o `alter table` seguraria lock pesado).
- Os testes só rodam com `DATABASE_URL` definida (ambiente ou `.env.local`, já coberto pelo `.gitignore`) e fora do horário de uso, porque o DDL segura locks por alguns segundos.
- Funções auxiliares: `security definer`, `set search_path = ''`, `execute` revogado de `public` e `anon`, concedido a `authenticated`.
- Perfil resolvido por `auth.uid()` via `team_members.auth_user_id`, não pelo e-mail do JWT.
- `revoke all` de `anon` em tabelas, sequences e functions do schema `public`.
- O app só usa `SUPABASE_URL` e `SUPABASE_ANON_KEY` (variável de ambiente ou `st.secrets`); nenhum arquivo de credenciais no fluxo.
- Fase 1a não muda telas nem comportamento para quem tem permissão.
- Aplicar SQL na produção (COMMIT de verdade) é sempre ato do Paulo, no SQL Editor, depois de backup e de ensaio verde; o agente nunca faz.
- Commits só quando o Paulo autorizar: perguntar uma vez no início da execução e, se autorizado, commitar por tarefa. Nunca commitar `.env.local`, backups ou arquivos de `data/`.
- Módulos novos não podem colidir com os diretórios vazios `config/`, `core/`, `clients/`, `documents/`, `accounts/` (restos do Django); por isso `supabase_config.py` e `ui_errors.py`.

## Review Focus

1. Setor com espaço ou acento na lista (`"Comercial, Revisão"`): quem tem o setor deve ser reconhecido. Teste na Tarefa 2 (`test_has_sector_tolerates_spaces`).
2. E-mail em caixa diferente entre `team_members` e Auth: o vínculo `auth_user_id` deve ser preenchido mesmo assim. Teste na Tarefa 2 (`test_backfill_is_case_insensitive`).
3. Membro desativado com sessão ainda válida: perde o acesso na próxima requisição. Teste na Tarefa 2 (`test_deactivated_member_loses_access_immediately`).
4. `upsert` (usado em checkpoints, `client_private` e `daily_snapshots`) exige as policies de INSERT, UPDATE e SELECT juntas: um perfil pode passar no insert e falhar no upsert. Teste na Tarefa 2 (`test_upserts_used_by_app`).
5. Negação por RLS aparece ao usuário como "sem permissão", não como erro genérico, para ele saber que não é falha do sistema. Teste na Tarefa 4 (`test_show_error_maps_permission_denied`).

---

## File Structure

- Create `supabase_rls_v2.sql`, `supabase_rls_v1_rollback.sql`: RLS v2 e volta para o estado atual. `supabase_rls.sql` não muda (registro da v1).
- Create `supabase_gov_password.sql`, `supabase_gov_password_finalize.sql`: Fase 1b.
- Create `scripts/check_prod_access.py`: checagem somente leitura da produção.
- Create `ui_errors.py`, `supabase_config.py`, `gov_password.py`: um módulo por responsabilidade.
- Create `tests/` (`conftest.py`, `sandbox.py` e os `test_*.py` de cada tarefa), `requirements-dev.txt`.
- Modify `supabase_schema.sql` (coluna `auth_user_id`), `app.py`, `comercial.py`, `preenchimento.py`, `revisao.py`, `pos_envio.py`, `setup_supabase.py`, `README.md`, `DEPLOY_CHECKLIST.md`.

---

### Task 0: Ações do Paulo no painel do Supabase (manual, cerca de 15 min)

**Files:** nenhum.

- [ ] **Step 1: Segredos.** Gerar nova `service_role` key; trocar a senha do Postgres; guardar a nova connection string só em `.env.local`, na linha `DATABASE_URL=...`; apagar `data/supabase-credentials.txt`.
- [ ] **Step 2: Acesso.** Desligar "Allow new users to sign up"; trocar a senha dos 8 usuários e apagar `data/supabase-users.txt`; ligar MFA (TOTP) para Paulo, Heverton e Renato.
- [ ] **Step 3: Verificar.** No painel, confirmar que o toggle de signup está desligado. A checagem automática vem na Tarefa 6.

### Task 1: Harness de transação revertida

**Files:**
- Create: `requirements-dev.txt` (`pytest>=8`, `psycopg[binary]>=3.2`), `tests/conftest.py`, `tests/sandbox.py`, `tests/test_sandbox_smoke.py`

**Interfaces:**
- Produces `tests/sandbox.py`: `PROFILES: dict[str, dict]` com as chaves `manager`, `reviewer`, `preparer`, `status_only`, `read_only`, `inactive`, `outsider`; e-mail `f"{key}@example.test"`. Linha em `team_members` (nome `__teste__<chave>`):

| Perfil | `allowed_sectors` | `can_manage_records` | `permission_level` | `active` |
|---|---|---|---|---|
| manager | `Comercial,Preenchimento,Revisão,Cadastros` | true | full | true |
| reviewer | `Revisão` | true | full | true |
| preparer | `Preenchimento` | false | full | true |
| status_only | `Preenchimento` | false | status_only | true |
| read_only | `Revisão` | false | read_only | true |
| inactive | `Preenchimento` | false | full | false |
| outsider | sem linha em `team_members` | | | |

- Produces `rls_sandbox(apply: Sequence[Path] = ()) -> ContextManager[Sandbox]`: conecta com `DATABASE_URL` sem autocommit, aplica os arquivos SQL na ordem (execução simples, sem parâmetros), cria um usuário em `auth.users` por perfil (`id` novo, e-mail `@example.test`), as linhas de `team_members` (preenchendo `auth_user_id` só se a coluna existir), 3 clientes `__teste__cliente_1..3` com `client_private` (cpf `000.000.000-01..03`, gov_password `senha-ficticia-1..3`), 1 documento e 1 checkpoint cada; no `finally` faz SEMPRE `rollback` e fecha.
- Produces em `Sandbox`: `uids: dict[str, str]` (perfil -> uuid), `fake_client_id: int`, `admin() -> ContextManager[Cursor]` (sessão do dono, sem RLS), `as_profile(profile: str) -> ContextManager[Cursor]` (dentro de um savepoint: `set local role authenticated`, ou `anon` para `"anon"`, e `set_config('request.jwt.claims', '{"sub": <uid>, "role": "authenticated", "email": <email>}', true)`; ao sair, `reset role` e volta ao savepoint).
- Produces `residue_snapshot() -> dict[str, int]`: em conexão própria, conta só o que seria resíduo de teste: `clients_fake` (clientes `__teste__%`), `team_fake` e `auth_fake` (e-mails `%@example.test`), `policies` (linhas de `pg_policies` do schema `public`) e `private_schema` (0 ou 1). Não conta totais das tabelas, porque o app em uso muda esses números.
- Produces `tests/conftest.py`: opção `--apply` (repetível) com caminhos de SQL; fixture `sandbox` (por teste) que usa `rls_sandbox` com esses arquivos; carrega `.env.local`; sem `DATABASE_URL`, só os testes que usam banco são pulados, com mensagem.

- [ ] **Step 1: Escrever os testes** em `tests/test_sandbox_smoke.py`: `test_profiles_resolve_to_fake_uid` (em `as_profile("manager")`, `select auth.uid()` é `uids["manager"]` e `select current_user` é `authenticated`), `test_anon_has_no_uid` (`auth.uid()` é nulo e `current_user` é `anon`), `test_sandbox_leaves_no_residue` (`residue_snapshot()` antes e depois de uma sandbox que insere um cliente são iguais).
- [ ] **Step 2: Rodar e ver falhar:** `python -m pytest tests/test_sandbox_smoke.py -v`. Esperado: ERROR por módulo inexistente (ou skip se `DATABASE_URL` não estiver definida).
- [ ] **Step 3: Implementar** `sandbox.py` e o `conftest.py`.
- [ ] **Step 4: Rodar de novo, fora do horário de uso.** Esperado: 3 passed.
- [ ] **Step 5: Commit** `feat: harness de testes de RLS em transação revertida`.

### Task 2: Matriz de permissões (falha contra o banco atual)

**Files:**
- Create: `tests/test_rls_matrix.py`
- Modify: `tests/sandbox.py` (acrescentar `matrix_results`)

**Interfaces:**
- Consumes: `Sandbox` da Tarefa 1.
- Produces `Sandbox.matrix_results() -> dict[tuple[str, str, str], bool]` (chave `(perfil, tabela, op)`, `op` em `select|insert|update|delete`): roda a matriz inteira num único bloco `DO` (transação curta, para não segurar lock de DDL), cada operação numa subtransação desfeita ao fim, contra linhas fictícias criadas na mesma transação. `False` se levantar `InsufficientPrivilege` (42501) ou se não afetar nenhuma linha. Para `team_members`, a linha-alvo é a do `preparer`.

- [ ] **Step 1: Escrever a matriz** (valores exatos do desenho):

```python
W = {"select", "insert", "update", "delete"}
RW = {"select", "insert", "update"}
SEL = {"select"}
EXPECTED = {
    "manager":  {"team_members": SEL, "clients": W, "client_private": W, "documents": W,
                 "contact_log": W, "declaration_checkpoints": W, "daily_snapshots": RW},
    "reviewer": {"team_members": SEL, "clients": W, "client_private": RW, "documents": W,
                 "contact_log": W, "declaration_checkpoints": W, "daily_snapshots": RW},
    "preparer": {"team_members": SEL, "clients": RW, "client_private": SEL, "documents": W,
                 "contact_log": RW, "declaration_checkpoints": RW, "daily_snapshots": RW},
    "read_only": {t: SEL for t in TABLES} | {"daily_snapshots": RW},
    "inactive": {}, "outsider": {}, "anon": {},
}
EXPECTED["status_only"] = EXPECTED["preparer"]
```

  Teste: `test_matrix(matrix_results, profile, table, op)` parametrizado sobre o produto dos três, com `matrix_results` calculado uma vez por módulo; `assert matrix_results[(profile, table, op)] == (op in EXPECTED[profile].get(table, set()))`.
- [ ] **Step 2: Testes do Review Focus**, no mesmo arquivo (tudo em SQL dentro da sandbox):
  - `test_deactivated_member_loses_access_immediately`: `admin()` põe `team_members.active=false` no `preparer`; `as_profile("preparer")` lê `clients` e não vê linha nenhuma.
  - `test_upserts_used_by_app`: `status_only` faz `insert ... on conflict (client_id, step_key) do update` em `declaration_checkpoints` duas vezes com sucesso; `read_only` faz o equivalente em `daily_snapshots` (`on conflict (reference_date)`) com sucesso; `manager` faz em `client_private` (`on conflict (client_id)`) com sucesso e `preparer` falha com 42501.
  - `test_has_sector_tolerates_spaces`: `admin()` põe `allowed_sectors='Comercial, Revisão, Cadastros'` no `reviewer`; ele consegue deletar uma linha fictícia de `client_private`. Com `'Comercial, Revisão'` (sem Cadastros) não consegue (0 linhas).
  - `test_backfill_is_case_insensitive`: `admin()` zera `auth_user_id` do `preparer` e grava o e-mail `Preparer@Example.Test`; `select private.backfill_auth_user_ids()` devolve mais que 0 e `as_profile("preparer")` lê `clients`.
- [ ] **Step 3: Rodar contra o banco atual:** `python -m pytest tests/test_rls_matrix.py -v` (sem `--apply`). Esperado: FALHA nas linhas de escrita de `read_only`, de `status_only` em `clients`/`delete`, de `preparer` em `client_private` e nas de `team_members` (isso também confirma o estado real do RLS de produção); `test_backfill_*` falha por a função não existir.
- [ ] **Step 4: Commit** `test: matriz de permissões do RLS`.

### Task 3: RLS v2 e rollback

**Files:**
- Create: `supabase_rls_v2.sql`, `supabase_rls_v1_rollback.sql`
- Modify: `supabase_schema.sql` (acrescentar `auth_user_id`)

**Interfaces:**
- Produces, no banco: coluna `public.team_members.auth_user_id uuid unique references auth.users(id) on delete set null`; schema `private` com `private.is_member() returns boolean`, `private.has_sector(sector text) returns boolean`, `private.can_write() returns boolean`, `private.can_manage() returns boolean`, `private.backfill_auth_user_ids() returns integer`; policies `<tabela>_select|_insert|_update|_delete` conforme a matriz da Tarefa 2.

- [ ] **Step 1: Implementar `supabase_rls_v2.sql`**, idempotente (aplicar duas vezes termina sem erro). Regras:
  - Tudo `SQL stable security definer set search_path = ''`; `grant usage on schema private` e `execute` só para `authenticated`.
  - `is_member()`: existe `team_members` com `auth_user_id = auth.uid()`, `active` e `allowed_sectors` não vazio. `can_write()`: `permission_level in ('full','status_only')`. `can_manage()`: `can_manage_records`. Todas exigem `is_member()`.
  - `has_sector(s)`: divide `allowed_sectors` por vírgula, faz trim de cada item e compara exato, com acento e caixa (a UI usa `Revisão`).
  - `backfill_auth_user_ids()`: preenche `auth_user_id` casando `lower(auth.users.email) = lower(team_members.email)` e retorna quantas linhas mudou.
  - Dropar as policies v1 (`<tabela>_authenticated_*`) e criar as v2 com estes predicados:

| Tabela | SELECT | INSERT / UPDATE | DELETE |
|---|---|---|---|
| `team_members` | `is_member()` | nenhuma policy | nenhuma policy |
| `clients` | `is_member()` | `can_write()` | `can_manage()` |
| `client_private` | `is_member()` | `can_manage()` | `can_manage() and has_sector('Cadastros')` |
| `documents` | `is_member()` | `can_write()` | `can_write()` |
| `contact_log`, `declaration_checkpoints` | `is_member()` | `can_write()` | `can_manage()` |
| `daily_snapshots` | `is_member()` | `is_member()` | nenhuma policy |

  - Fechar o `anon`: `revoke all` em tabelas, sequences e functions do schema `public`, mais `alter default privileges in schema public revoke all on tables from anon`.
  - Terminar chamando `private.backfill_auth_user_ids()`.
- [ ] **Step 2: Espelhar a coluna** `auth_user_id` em `supabase_schema.sql` para instalações novas.
- [ ] **Step 3: Escrever `supabase_rls_v1_rollback.sql`:** dropa as policies v2 e recria as policies v1 com o texto de `supabase_rls.sql`, sem apagar a coluna nem as funções.
- [ ] **Step 4: Ensaiar a v2 (rollback automático):** `python -m pytest tests --apply supabase_rls_v2.sql -v`. Esperado: todos passam. Repetir com `--apply supabase_rls_v2.sql --apply supabase_rls_v2.sql`. Esperado: passam (idempotência).
- [ ] **Step 5: Provar o rollback:** `python -m pytest tests/test_rls_matrix.py --apply supabase_rls_v2.sql --apply supabase_rls_v1_rollback.sql -k "read_only or outsider" -v`. Esperado: volta a falhar. Depois `python -m pytest tests/test_sandbox_smoke.py -v`. Esperado: passa (nada ficou no banco).
- [ ] **Step 6: Commit** `feat: RLS por perfil com rollback`.

### Task 4: Erros sem vazamento (23 pontos)

**Files:**
- Create: `ui_errors.py`, `tests/test_ui_errors.py`, `tests/test_no_raw_exceptions.py`
- Modify: `app.py` (linhas 1531, 2492, 2584, 2604), `comercial.py` (128, 216, 275, 289, 477, 514), `pos_envio.py` (275), `preenchimento.py` (385, 505, 559, 590, 636, 651, 839), `revisao.py` (465, 528, 580, 631, 668)

**Interfaces:**
- Produces `show_error(user_message: str, exc: BaseException | None = None) -> None`: registra no logger `irpf` com `exc_info`; chama `st.error` com `user_message`, ou com `"Você não tem permissão para realizar esta ação."` quando `getattr(exc, "code", None) == "42501"`; nunca inclui `str(exc)`.

- [ ] **Step 1: Escrever os testes.** `test_show_error_hides_exception_text` (com `RuntimeError("key=abc123")`, o texto passado a `st.error` não contém `abc123`); `test_show_error_maps_permission_denied` (exceção com `code="42501"` vira a mensagem de permissão); `test_no_raw_exception_in_st_error` (regex sobre os 5 arquivos `.py`: nenhum `st.error(f"...{exc}...")`). Estes testes não usam banco.
- [ ] **Step 2: Rodar.** Esperado: FAIL, com os 23 pontos listados.
- [ ] **Step 3: Implementar `ui_errors.py`** e trocar cada ponto pela regra `st.error(f"X: {exc}")` -> `show_error("X.", exc)`. O login (`app.py:1531`) vira `show_error("Falha no login. Confira e-mail e senha.", exc)`.
- [ ] **Step 4: Rodar** `python -m pytest tests/test_ui_errors.py tests/test_no_raw_exceptions.py -v` e `python -m py_compile app.py comercial.py preenchimento.py revisao.py pos_envio.py`. Esperado: passam, sem saída de erro.
- [ ] **Step 5: Commit** `fix: não mostrar exceção crua ao usuário`.

### Task 5: Credenciais fora do fluxo do app

**Files:**
- Create: `supabase_config.py`, `tests/test_supabase_config.py`
- Modify: `app.py` (remover `SUPABASE_CREDS_PATH` na linha 228 e o fallback de arquivo em 597-657; conferir antes com Grep se `read_key_value_file` é usada em outro lugar), `setup_supabase.py` (linhas 343-350), `README.md`, `DEPLOY_CHECKLIST.md`

**Interfaces:**
- Produces `load_supabase_public_config(secrets: Mapping[str, Any] | None = None, env: Mapping[str, str] | None = None) -> dict[str, str]`: devolve `{}` ou `{"url", "anon_key"}`. Ordem: ambiente (`SUPABASE_URL`/`NEXT_PUBLIC_SUPABASE_URL`, `SUPABASE_ANON_KEY`/`NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`), depois `secrets` (chaves soltas e seção `supabase`). Nunca lê arquivo.
- Produces `database_url_from_env(env: Mapping[str, str] | None = None) -> str`: lê `DATABASE_URL`; sem ela, `SystemExit` com mensagem em português.
- `app.py` mantém `load_supabase_public_config()` sem argumentos como wrapper fino que passa `dict(st.secrets)` (com `try/except`), para não mexer nos chamadores.

- [ ] **Step 1: Escrever os testes:** `test_ignores_credentials_file` (arquivo `data/supabase-credentials.txt` fictício num `tmp_path` com `chdir`; sem env nem secrets, retorna `{}`), `test_env_wins_over_secrets`, `test_reads_supabase_section_of_secrets`, `test_database_url_from_env_missing_exits`.
- [ ] **Step 2: Rodar.** Esperado: FAIL (módulo inexistente).
- [ ] **Step 3: Implementar** o módulo, o wrapper no `app.py` e `setup_supabase.py` (remove `--creds` e `read_credentials` se ficarem sem uso, usa `database_url_from_env()`).
- [ ] **Step 4: Atualizar** `README.md` (ordem de leitura: variável de ambiente, `st.secrets`; scripts usam `DATABASE_URL`) e `DEPLOY_CHECKLIST.md`.
- [ ] **Step 5: Rodar** `python -m pytest tests/test_supabase_config.py -v` e `python -m py_compile app.py setup_supabase.py`. Esperado: passam.
- [ ] **Step 6: Commit** `refactor: credenciais só por ambiente ou secrets`.

### Task 6: Aplicar a Fase 1a em produção

**Files:**
- Create: `scripts/check_prod_access.py`
- Modify: `DEPLOY_CHECKLIST.md`, `README.md` (seção Segurança operacional)

**Interfaces:**
- Produces `scripts/check_prod_access.py`: usa `SUPABASE_URL` e `SUPABASE_ANON_KEY`; para cada uma das 7 tabelas, `select` anônimo volta vazio ou levanta erro; `GET {SUPABASE_URL}/auth/v1/settings` deve devolver `disable_signup: true` (só leitura; o script nunca tenta criar conta). Lê as variáveis do ambiente ou do `.env.local`. Imprime `OK` ou `FAIL <o quê>` e sai com código 1 se houver qualquer FAIL. Somente leitura.

- [ ] **Step 1: Implementar e rodar uma vez** com as variáveis de produção. Esperado: `OK`; `FAIL signup` indica que o signup ainda está aberto (voltar à Tarefa 0).
- [ ] **Step 2: Ensaio final, fora do horário de uso:** `python -m pytest tests --apply supabase_rls_v2.sql -v`. Esperado: todos passam e `test_sandbox_leaves_no_residue` confirma que nada ficou.
- [ ] **Step 3: Backup (opcional na v2, obrigatório antes do finalize da Fase 1b).** A v2 só mexe em policies e numa coluna nova que começa nula, e o rollback restaura o estado anterior. `pg_dump --data-only "$DATABASE_URL" > data/backup-AAAAMMDD.sql` (`data/` já está no `.gitignore`). Sem `pg_dump`, usar o export XLSX do app e guardar em `data/` (ele contém a coluna `Senha Gov` até a Fase 1b).
- [ ] **Step 4: Paulo aplica `supabase_rls_v2.sql` no SQL Editor da produção.**
- [ ] **Step 5: Conferir o vínculo:** `select name from public.team_members where active and auth_user_id is null;`. Esperado: só `Erlane` (tem e-mail, mas ainda não tem conta no Auth). Se aparecer outro nome, corrigir e-mail ou usuário no Auth e rodar `select private.backfill_auth_user_ids();`. Em seguida, no painel (Authentication > Users), apagar a conta `teste@irpf.local`, que não pertence à equipe e já ficou sem acesso com a v2.
- [ ] **Step 6: Rodar** `python scripts/check_prod_access.py` com as variáveis de produção. Esperado: `OK`, código de saída 0.
- [ ] **Step 7: Smoke test** no app, um usuário de cada perfil, pelo roteiro do `DEPLOY_CHECKLIST.md` (Comercial, Preenchimento, Revisão, Cadastros e Pós-envio). Para os testes de escrita, criar o cliente `TESTE - NAO USAR` em Cadastros e apagá-lo no fim; não editar clientes reais.
- [ ] **Step 8: Se algo quebrar:** aplicar `supabase_rls_v1_rollback.sql` no SQL Editor, anotar o fluxo que falhou, reproduzir no ensaio com um teste novo e corrigir antes de tentar de novo.
- [ ] **Step 9: Commit** `docs: roteiro de aplicação do RLS v2`.

### Task 7: Senha gov.br cifrada, SQL (Fase 1b)

**Status (2026-11-23):** feita e ensaiada em transação revertida (239 testes verdes e 2 pulados), incluindo o finalize rodando sobre as 96 senhas reais, com a checagem de decifrar e comparar passando. Ainda não aplicada em produção. Sem commit.

**Files:**
- Create: `supabase_gov_password.sql`, `supabase_gov_password_finalize.sql`, `tests/test_gov_password.py`
- Modify: `tests/sandbox.py` (cria o segredo `gov_password_key` do Vault dentro da transação, antes de aplicar qualquer arquivo `gov_password`)

**Decisão de desenho (mudou em relação ao desenho inicial):** a senha cifrada fica numa tabela própria, `public.client_secrets`, sem nenhum grant para a API, e não numa coluna de `client_private`. Motivo: revogar o `select` de uma coluna obriga a trocar o grant da tabela por grants de coluna, e o PostgREST devolve todas as colunas em `insert`/`upsert` com `return=representation`, o que quebraria os `upsert` do app com "permission denied for column".

**Interfaces:**
- Consumes: funções `private.*` da Tarefa 3.
- Produces, no banco: `public.audit_log (id, actor uuid, actor_email, action, client_id, created_at)` e `public.client_secrets (client_id bigint pk references clients on delete cascade, gov_password_enc bytea not null, updated_at)`, as duas com RLS ligado, sem policy e com `revoke all` de `anon` e `authenticated`; `client_private.has_gov_password boolean not null default false` (indicador não sensível); `private.gov_key() returns text` (lê o segredo `gov_password_key` do Vault e levanta erro `55000` se faltar, nunca grava "null" no lugar da senha); trigger `client_private_encrypt_gov_password` (transição: se o app antigo gravar `gov_password` em texto puro, é cifrado na hora); `public.set_gov_password(p_client_id bigint, p_value text) returns void` (exige `private.can_manage()`; valor em branco apaga a senha; zera a coluna de texto puro enquanto ela existir; grava `audit_log` com `action='set_gov_password'`); `public.reveal_gov_password(p_client_id bigint) returns text` (exige setor Comercial, Preenchimento ou Revisão; grava `audit_log` com `action='reveal_gov_password'`).
- O finalize confere que toda senha em texto puro tem versão cifrada que decifra para o mesmo valor (senão aborta), dropa o trigger, a função do trigger e a coluna `gov_password`.

- [x] **Step 1: Testes** em `tests/test_gov_password.py` (reveal e auditoria, `set` exige gerência, não membros negados, texto cifrado não contém a senha, `audit_log` e `client_secrets` ilegíveis, indicador acompanha set e limpeza, chave ausente falha alto, texto puro do app antigo é cifrado, `set` zera o texto puro, coluna some após o finalize).
- [x] **Step 2: Falharam** contra o banco sem o SQL (12 falhas, 1 pulado).
- [x] **Step 3 e 4: SQL** da parte 1 e do finalize escritos.
- [x] **Step 5: Ensaios.** `python -m pytest tests/test_gov_password.py tests/test_rls_matrix.py --apply supabase_gov_password.sql` (240 passam, 1 pulado) e o mesmo com `--apply supabase_gov_password_finalize.sql` (239 passam, 2 pulados). Banco ao vivo intacto depois.
- [ ] **Step 6: Commit** `feat: senha gov.br cifrada com funções e auditoria` (aguardando o Paulo).

### Task 8: App usa as funções e exporta sem a senha (Fase 1b)

**Status (2026-11-23):** feita. Os 5 testes sem banco passam, o teste do export falha se a proteção for removida (checado), e o app inicia sem exceção (AppTest). Ainda não testada com login real (isso é o smoke test da Tarefa 9). Sem commit.

**Files:**
- Create: `gov_password.py`, `pytest.ini` (`pythonpath = . tests`), `tests/test_gov_password_wrapper.py`, `tests/test_export_columns.py`
- Modify: `app.py`, `pos_envio.py`, `preenchimento.py`, `comercial.py`, `revisao.py` (arquivos em CRLF: editar preservando CRLF)

**Interfaces (como construído):**
- `gov_password.reveal_gov_password(client: Client, client_id: int) -> str` e `gov_password.set_gov_password(client: Client, client_id: int, value: str) -> None` (valor em branco não faz nada), ambos via `client.rpc(...)`.
- `gov_password.gov_password_input(label: str, client_id: int) -> str`: campo de senha para formulários, vazio por padrão; em branco mantém a senha atual; a chave do widget inclui um contador que sobe depois de salvar, para o campo voltar vazio.
- `gov_password.render_gov_password_reveal(client: Client | None, client_id: int, has_password: bool, key: str) -> None`: mostra "Cadastrada" ou "Não informada" e, se houver senha, o botão "Mostrar senha", que revela o valor por uma execução. Fica fora dos formulários, porque `st.button` não funciona dentro de `st.form`.
- `app.py`: o bundle seleciona `has_gov_password` (com fallback se a coluna ainda não existir, para o app novo não quebrar se for publicado antes do SQL); `people_df` ganha `Senha Gov Cadastrada` (bool) e `Senha Gov` fica sempre vazia (as demais referências continuam funcionando); `save_client_record` e `save_post_filing_update` gravam a senha só por `set_gov_password`; a comparação da importação nunca mostra senha ("cadastrar" ou "substituir pela da planilha"); `SENSITIVE_EXPORT_COLUMNS = ("Senha Gov",)` sai do XLSX.

**Mudanças de comportamento que o Paulo precisa saber:** em branco, o campo de senha mantém a atual (antes, apagar o campo apagava a senha); ver a senha agora exige clicar em "Mostrar senha" e fica registrado em `audit_log`.

- [x] **Step 1: Testes** (wrapper com cliente falso e export sem `Senha Gov`).
- [x] **Step 2 e 3: Implementação** por script que confere cada trecho e preserva CRLF.
- [x] **Step 4:** `python -m py_compile` nos 6 arquivos e `python -m pytest tests/test_gov_password_wrapper.py tests/test_export_columns.py -q` (5 passam).
- [ ] **Step 5: Commit** `feat: telas leem a senha gov.br só sob demanda` (aguardando o Paulo).

### Task 9: Aplicar a Fase 1b em produção

**Files:** nenhum novo; atualizar `DEPLOY_CHECKLIST.md`.

- [ ] **Step 1: Ensaio da migração sobre os dados reais, rollback automático:** `python -m pytest tests --apply supabase_gov_password.sql --apply supabase_gov_password_finalize.sql -v`. Esperado: todos passam, incluindo a checagem de contagem do finalize.
- [ ] **Step 2: Produção, preparação.** Paulo cria a chave do Vault (comando da Tarefa 7, Step 3) e aplica `supabase_gov_password.sql` no SQL Editor.
- [ ] **Step 3: Publicar o app novo** (push com autorização do Paulo) e repetir o smoke test por perfil com o cliente `TESTE - NAO USAR`. Confirmar: a senha só aparece após "Mostrar senha"; o XLSX não tem `Senha Gov`; `audit_log` registra os acessos.
- [ ] **Step 4: Esperar 1 a 2 dias de uso.** Até aqui o rollback é só republicar o app antigo, sem perda de dados, porque a coluna de texto puro ainda existe.
- [ ] **Step 5: Backup** (como na Tarefa 6, Step 3) e Paulo aplica `supabase_gov_password_finalize.sql` em produção. Depois disso o rollback é só pelo backup.
- [ ] **Step 6: Rodar** `python scripts/check_prod_access.py`. Esperado: `OK`. Atualizar o `DEPLOY_CHECKLIST.md`.
