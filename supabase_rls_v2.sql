-- RLS v2: permissoes por perfil aplicadas no proprio banco (espelham as da interface).
-- Seguro para rodar mais de uma vez. Nao contem BEGIN/COMMIT e nao reabilita RLS (ja esta ligado
-- nas 7 tabelas). Para voltar ao estado anterior: supabase_rls_v1_rollback.sql.
-- Desenho: docs/superpowers/specs/2026-11-23-hardening-banco-design.md

-- 1) Vinculo usuario -> perfil por auth.uid() (nao pelo e-mail do JWT).
alter table public.team_members
    add column if not exists auth_user_id uuid unique references auth.users(id) on delete set null;

-- 2) Schema privado (nao exposto pela API do Supabase) com as funcoes de perfil.
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

-- Membro = usuario logado ligado a uma linha ATIVA de team_members com ao menos um setor.
create or replace function private.is_member()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.team_members tm
        where tm.auth_user_id = auth.uid()
          and tm.active
          and btrim(coalesce(tm.allowed_sectors, '')) <> ''
    );
$$;

-- O setor consta em allowed_sectors (lista separada por virgula; compara exato, com acento e caixa).
create or replace function private.has_sector(sector text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select private.is_member() and exists (
        select 1
        from public.team_members tm
        where tm.auth_user_id = auth.uid()
          and sector = any (
              array(select btrim(s) from unnest(string_to_array(coalesce(tm.allowed_sectors, ''), ',')) as s)
          )
    );
$$;

create or replace function private.can_write()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select private.is_member() and exists (
        select 1
        from public.team_members tm
        where tm.auth_user_id = auth.uid()
          and tm.permission_level in ('full', 'status_only')
    );
$$;

create or replace function private.can_manage()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select private.is_member() and exists (
        select 1
        from public.team_members tm
        where tm.auth_user_id = auth.uid()
          and tm.can_manage_records
    );
$$;

-- Preenche auth_user_id casando e-mails sem diferenciar maiusculas. Devolve quantas linhas mudou.
create or replace function private.backfill_auth_user_ids()
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
    changed integer;
begin
    update public.team_members tm
    set auth_user_id = u.id
    from auth.users u
    where tm.auth_user_id is null
      and coalesce(tm.email, '') <> ''
      and lower(u.email) = lower(tm.email);
    get diagnostics changed = row_count;
    return changed;
end;
$$;

revoke execute on function private.is_member() from public, anon;
revoke execute on function private.has_sector(text) from public, anon;
revoke execute on function private.can_write() from public, anon;
revoke execute on function private.can_manage() from public, anon;
revoke execute on function private.backfill_auth_user_ids() from public, anon, authenticated;
grant execute on function private.is_member() to authenticated;
grant execute on function private.has_sector(text) to authenticated;
grant execute on function private.can_write() to authenticated;
grant execute on function private.can_manage() to authenticated;

-- 3) Remove TODAS as policies atuais das 7 tabelas (v1 e qualquer outra) e recria.
do $$
declare
    p record;
begin
    for p in
        select policyname, tablename
        from pg_policies
        where schemaname = 'public'
          and tablename in ('team_members', 'clients', 'client_private', 'documents',
                            'contact_log', 'declaration_checkpoints', 'daily_snapshots')
    loop
        execute format('drop policy if exists %I on public.%I', p.policyname, p.tablename);
    end loop;
end;
$$;

-- team_members: leitura para membros; escrita so por SQL/service (setup_supabase.py), nunca pela API.
create policy team_members_select on public.team_members
    for select to authenticated using ((select private.is_member()));

-- clients
create policy clients_select on public.clients
    for select to authenticated using ((select private.is_member()));
create policy clients_insert on public.clients
    for insert to authenticated with check ((select private.can_write()));
create policy clients_update on public.clients
    for update to authenticated
    using ((select private.can_write())) with check ((select private.can_write()));
create policy clients_delete on public.clients
    for delete to authenticated using ((select private.can_manage()));

-- client_private (CPF, telefone, senha gov.br)
create policy client_private_select on public.client_private
    for select to authenticated using ((select private.is_member()));
create policy client_private_insert on public.client_private
    for insert to authenticated with check ((select private.can_manage()));
create policy client_private_update on public.client_private
    for update to authenticated
    using ((select private.can_manage())) with check ((select private.can_manage()));
create policy client_private_delete on public.client_private
    for delete to authenticated
    using ((select private.can_manage()) and (select private.has_sector('Cadastros')));

-- documents (Preenchimento tambem remove documento: preenchimento.py:642)
create policy documents_select on public.documents
    for select to authenticated using ((select private.is_member()));
create policy documents_insert on public.documents
    for insert to authenticated with check ((select private.can_write()));
create policy documents_update on public.documents
    for update to authenticated
    using ((select private.can_write())) with check ((select private.can_write()));
create policy documents_delete on public.documents
    for delete to authenticated using ((select private.can_write()));

-- contact_log
create policy contact_log_select on public.contact_log
    for select to authenticated using ((select private.is_member()));
create policy contact_log_insert on public.contact_log
    for insert to authenticated with check ((select private.can_write()));
create policy contact_log_update on public.contact_log
    for update to authenticated
    using ((select private.can_write())) with check ((select private.can_write()));
create policy contact_log_delete on public.contact_log
    for delete to authenticated using ((select private.can_manage()));

-- declaration_checkpoints
create policy declaration_checkpoints_select on public.declaration_checkpoints
    for select to authenticated using ((select private.is_member()));
create policy declaration_checkpoints_insert on public.declaration_checkpoints
    for insert to authenticated with check ((select private.can_write()));
create policy declaration_checkpoints_update on public.declaration_checkpoints
    for update to authenticated
    using ((select private.can_write())) with check ((select private.can_write()));
create policy declaration_checkpoints_delete on public.declaration_checkpoints
    for delete to authenticated using ((select private.can_manage()));

-- daily_snapshots (gravado por quem abrir o app primeiro no dia; ninguem apaga)
create policy daily_snapshots_select on public.daily_snapshots
    for select to authenticated using ((select private.is_member()));
create policy daily_snapshots_insert on public.daily_snapshots
    for insert to authenticated with check ((select private.is_member()));
create policy daily_snapshots_update on public.daily_snapshots
    for update to authenticated
    using ((select private.is_member())) with check ((select private.is_member()));

-- 4) Fecha o papel anonimo: nada nas tabelas, sequences e functions do schema public.
revoke all on all tables in schema public from anon;
revoke all on all sequences in schema public from anon;
revoke all on all functions in schema public from anon;
alter default privileges in schema public revoke all on tables from anon;
alter default privileges in schema public revoke all on sequences from anon;
alter default privileges in schema public revoke all on functions from anon;

-- 5) Liga os usuarios do Auth as linhas de team_members (mostra quantas ligou).
select private.backfill_auth_user_ids() as vinculos_preenchidos;
