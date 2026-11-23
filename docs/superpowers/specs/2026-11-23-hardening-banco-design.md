# Hardening do banco (Fase 1) - IRPF

Data: 2026-11-23
Status: rascunho aguardando aprovacao do Paulo
Escolha do Paulo: "Banco primeiro", depois migrar para a Vercel (Fase 2).

## Intencao e porque

O app interno de IRPF (Streamlit + Supabase) guarda dados sensiveis de clientes: CPF, telefone e a senha gov.br em texto puro. Hoje a autorizacao existe so na interface. O banco libera tudo para qualquer usuario logado. Migrar o front para a Vercel nao corrige isso, porque a regra de acesso continua fora do banco.

Objetivo: o banco passa a ser a barreira real. Qualquer front (Streamlit hoje, Next.js na Vercel depois) herda a seguranca sem refazer a regra.

## Metas

- Quem nao esta cadastrado, esta inativo ou nao tem setor nao acessa nenhuma tabela.
- Ninguem altera o proprio perfil (`team_members`) pela API.
- As permissoes do banco espelham as da interface: `permission_level`, `can_manage_records`, `allowed_sectors`.
- O app Streamlit atual segue funcionando para os 9 usuarios, sem mudar telas na Fase 1a.
- Segredos rotacionados e fora do fluxo do app.
- Senha gov.br deixa de ser legivel em massa (Fase 1b).

## Nao-metas

- Migrar para a Vercel / Next.js (Fase 2).
- Reescrever telas ou fluxos.
- Restringir por coluna dentro de `clients` (o `status_only` continua podendo atualizar a linha; trava por coluna fica para depois, via trigger).
- Criptografia de disco das maquinas locais e adequacao formal a LGPD.

## Anti-metas (seria falha mesmo que "funcione")

- Travar a equipe fora do app por policy estrita demais, sem teste.
- Teste que grave de forma permanente no banco real. Todo teste roda numa transacao que termina em rollback.
- Deixar a `service_role` key ou a senha do Postgres em arquivo plano sem rotacao.

## Estado atual (fatos lidos no codigo)

- `supabase_rls.sql`: toda policy das 7 tabelas e `using (true)` / `with check (true)` para `authenticated`, inclusive `team_members` e `client_private`.
- `team_members` guarda `allowed_sectors`, `can_manage_records` e `permission_level`. Qualquer logado pode dar `update` nela, entao pode se promover.
- `app.py:866-870` carrega `gov_password`, `cpf` e `phone` de todos os clientes para qualquer usuario logado. A senha aparece em `pos_envio.py:197` e `preenchimento.py:404`, e e editavel em `comercial.py:429` e `revisao.py:541`.
- O export "banco completo" (`app.py:2398-2410`) copia o `people_df` inteiro. `prepare_export_sheet` so formata valores, entao a coluna `Senha Gov` vai no XLSX.
- A area Cadastros (import, export, delete em massa) e travada por e-mail fixo no codigo (`app.py:2423`: Paulo e Heverton).
- 23 pontos mostram `{exc}` cru em `st.error` (ex.: `app.py:1531`, `2492`, `2584`, `2604`; `comercial.py`, `preenchimento.py`, `revisao.py`, `pos_envio.py`).
- `data/supabase-credentials.txt` tem `service_role` e senha do Postgres; o proprio arquivo diz que ja foram compartilhadas. `data/supabase-users.txt` tem uma senha temporaria unica para os 8 usuarios.
- Historico git: a busca por padroes de chave nao achou segredo commitado. `data/` esta no `.gitignore`.

Nao verificado: o estado real do RLS e do signup no projeto IRPF. O conector Supabase da sessao so enxerga outro projeto (nome "DATABASE", hibernado, ref diferente do arquivo de credenciais do app), e nada foi executado nele. A unica fonte do RLS atual e o `supabase_rls.sql`.

Confirmado ao vivo em 2026-11-23 (via `DATABASE_URL`, consultas somente leitura e ensaios em transacao revertida): o banco do IRPF tem 199 clientes, 864 documentos, RLS ligado nas 7 tabelas e exatamente as 28 policies da v1, todas abertas; `pgcrypto` e `supabase_vault` estao habilitados; o schema `private` ainda nao existe. Em `team_members`, as 9 linhas estao com `permission_level = 'full'` e `can_manage_records = true` (o `TEAM_FALLBACK` do `app.py` diferencia Duda, Malu e Erlane, mas o banco nao), e Heverton, Paulo e Renato tem o setor Cadastros. Das 9 pessoas, 8 tem conta no Auth; Erlane tem e-mail mas nao tem conta. Existe uma conta do Auth sem linha em `team_members` (`teste@irpf.local`, criada e usada so em 2026-04-28), que hoje tem acesso total e perde o acesso com a v2. Consequencia pratica: a v2 fecha o banco para quem nao e da equipe, mas entre os 8 membros nada muda enquanto todos estiverem `full` e com `can_manage_records`; diferenciar Duda, Malu e Erlane e uma decisao de dados do Paulo.

Nao reproduzido: Paulo relatou ver "credenciais do banco" na tela; ainda nao se sabe onde. Os `{exc}` acima sao o candidato, mas nao ficou confirmado que carregam chave.

## Abordagens consideradas

A. **Banco primeiro (escolhida).** Endurecer o banco agora; vale para o Streamlit e para a Vercel. Risco fechado em horas.

B. **Migrar direto para Next.js.** Descartada: o risco fica aberto por semanas (reescrita de ~6,9 mil linhas e 5 telas) e o RLS teria que ser refeito de qualquer forma.

Dentro de A, onde aplicar a regra:

- **(i) RLS com funcoes auxiliares lendo o perfil em `team_members` (escolhida).** Nao muda o app, fecha o buraco hoje.
- (ii) Tudo via RPC `security definer` e acesso direto revogado. Mais forte, mas exige reescrever todas as chamadas do app. Vira parte da Fase 2.
- (iii) Perfil dentro do JWT (custom access token hook). Mais rapido por requisicao, mais pecas para manter. Adiado.

## Design - Fase 1a (nao muda o comportamento de quem tem permissao)

### 1. Acoes do Paulo no painel do Supabase (nao delegaveis)

1. Gerar nova `service_role` key e trocar a senha do Postgres.
2. Desligar "Allow new users to sign up" (Authentication).
3. Trocar a senha temporaria dos 8 usuarios e apagar `data/supabase-users.txt`.
4. Ligar MFA (TOTP) para quem tem Cadastros ou revisao final: Paulo, Heverton, Renato (escolha minha).

### 2. Vinculo usuario -> perfil por `auth.uid()`

Adicionar `team_members.auth_user_id uuid` com unique, preenchida uma vez a partir de `auth.users` pelo e-mail. As funcoes buscam o perfil por `auth.uid()`, nao pelo e-mail do JWT, para que trocar o e-mail da conta nao permita se passar por outro membro. (Escolha minha.)

### 3. Funcoes auxiliares

`security definer`, `set search_path = ''`, `execute` revogado de `public` e `anon`, concedido a `authenticated`:

- `is_member()` - existe linha em `team_members` com `auth_user_id = auth.uid()`, `active = true` e `allowed_sectors` nao vazio.
- `has_sector(text)` - o setor consta em `allowed_sectors` (lista separada por virgula).
- `can_write()` - `permission_level` em (`full`, `status_only`).
- `can_manage()` - `can_manage_records = true`.

### 4. Matriz de policies (espelha a interface)

| Tabela | SELECT | INSERT / UPDATE | DELETE |
|---|---|---|---|
| `team_members` | `is_member()` | ninguem (so SQL / `setup_supabase.py` com conexao direta) | ninguem |
| `clients` | `is_member()` | `is_member() and can_write()` | `can_manage()` |
| `client_private` | `is_member()` | `can_manage()` | `can_manage() and has_sector('Cadastros')` |
| `documents` | `is_member()` | `is_member() and can_write()` | `is_member() and can_write()` |
| `contact_log` | `is_member()` | `is_member() and can_write()` | `can_manage()` |
| `declaration_checkpoints` | `is_member()` | `is_member() and can_write()` | `can_manage()` |
| `daily_snapshots` | `is_member()` | `is_member()` (o snapshot do dia e gravado por quem abre o app primeiro, `app.py:1451`) | ninguem |

Conferencia tela por tela (2026-11-23): o desenho original exigia `can_manage()` para apagar documento e `can_manage() and has_sector('Cadastros')` para apagar cliente. No codigo, quem remove documento no Preenchimento e quem tem `full` ou `status_only` (`preenchimento.py:642`), e excluir cliente na tela Comercial depende so de `can_manage_records` (`comercial.py:506`). Para a Fase 1a nao mudar o comportamento de ninguem, a matriz acima usa essas regras. Restringir exclusao de cliente a Cadastros (so Paulo e Heverton) fica como decisao do Paulo, para depois.

Alem disso: `revoke all on all tables in schema public from anon` e idem para sequences e functions, para que `anon` nao tenha nada nem se uma policy for esquecida.

### 5. Erros sem vazamento

Trocar os 23 `st.error(f"... {exc}")` por mensagem generica e registrar o detalhe no log do servidor. Um helper unico para nao repetir.

### 6. Segredos fora do fluxo do app

O app so precisa de `SUPABASE_URL` e `SUPABASE_ANON_KEY`, vindas de variavel de ambiente ou `st.secrets`. `setup_supabase.py` e `bootstrap_database.py` passam a ler a connection string de variavel de ambiente. O arquivo `data/supabase-credentials.txt` deixa de existir no fluxo (escolha minha; o app hoje o le como fallback em `app.py:228` e `609-652`).

### 7. Teste e aplicacao

- Nao ha staging (o Paulo so tem este banco). Os testes rodam no proprio banco, dentro de uma transacao que termina sempre em rollback: o SQL novo e aplicado, usuarios e clientes ficticios sao criados, a matriz e verificada e tudo e desfeito. Postgres desfaz DDL em rollback, entao o ensaio nao deixa policy, funcao nem linha.
- Script de teste que assume cada perfil (`set local role` + claims do JWT) e confere a matriz permitido/negado: `full` com `can_manage`, `full` sem `can_manage`, `status_only`, `read_only`, usuario sem cadastro, usuario inativo, `anon`.
- Entregar `supabase_rls_v2.sql` e `supabase_rls_v1_rollback.sql` (recria as policies atuais).
- Em producao: ensaio final com rollback, export de backup, rodar o SQL fora do horario de uso, smoke test pelo checklist do `DEPLOY_CHECKLIST.md` (um usuario de cada perfil), rollback se algo quebrar.

## Design - Fase 1b (senha gov.br)

Escolha: **revelar sob demanda, com auditoria**. (Alternativa mais segura, nao escolhida: parar de guardar a senha, ao custo de a equipe perder o acesso rapido no Pos-envio.)

Como foi construido:

- A senha cifrada (pgcrypto, chave `gov_password_key` no Vault, fora do banco e do repositorio) fica na tabela `client_secrets`, sem nenhum grant para a API. Foi escolhida uma tabela propria, e nao uma coluna de `client_private`, porque revogar `select` de uma coluna exige grants por coluna e o PostgREST devolve todas as colunas nos `upsert`, o que quebraria o app.
- `reveal_gov_password(client_id)` devolve a senha e grava em `audit_log` quem viu; `set_gov_password(client_id, valor)` grava cifrado e tambem audita. `client_private.has_gov_password` e o indicador nao sensivel que as telas usam.
- Durante a transicao, um trigger cifra qualquer senha que o app antigo ainda grave em texto puro; o finalize confere que tudo que esta em texto puro tem versao cifrada igual, e so entao apaga a coluna `gov_password`.
- Telas: mostram "Cadastrada" ou "Nao informada" e um botao "Mostrar senha"; o campo de senha dos formularios vem vazio e, em branco, mantem a atual. A comparacao da importacao nao mostra senha. O XLSX do banco completo sai sem a coluna `Senha Gov`.

## Riscos

- Policy estrita demais bloqueia fluxo legitimo. Mitigacao: teste por perfil no staging e rollback pronto.
- `team_members` precisa de `auth_user_id` preenchido para todos que logam. Erlane tem e-mail em `team_members`, mas nao tem conta no Auth, entao nao loga hoje e continua assim ate o Paulo criar a conta.
- O `status_only` ainda pode atualizar qualquer coluna de `clients` (nao-meta acima).
- O ensaio com rollback roda no banco real: o DDL segura locks por alguns segundos (o app pode demorar nesse intervalo) e os contadores de id das tabelas avancam (ids pulam, sem perda de dados). Rodar fora do horario de uso e conferir ao final que as contagens de linhas e de policies nao mudaram.
- O ensaio nao cobre o PostgREST (exposicao de schemas, formato dos erros). Isso fica para o smoke test no app, na aplicacao real.

## Deixado ao construtor

- Nomes exatos de funcoes e policies, e se ficam em schema `private`.
- Texto das mensagens de erro e formato do log.
- Mecanismo de criptografia da Fase 1b.
- Conferir, tela por tela, se cada escrita da matriz acima bate com o que os perfis fazem hoje (em especial `documents` e `declaration_checkpoints` para `status_only`).

## Estimativa

- Acoes do Paulo no painel: cerca de 20 min.
- Fase 1a (SQL, helper de erros e testes): cerca de 3 a 4 h.
- Fase 1b: cerca de 3 a 4 h adicionais.
