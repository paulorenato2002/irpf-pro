-- Volta as policies das 7 tabelas ao estado da v1 (supabase_rls.sql): aberto para qualquer
-- usuario autenticado. Use SO se a v2 travar o trabalho da equipe e o problema nao puder
-- esperar correcao. Nao contem BEGIN/COMMIT.
-- Nao apaga auth_user_id nem as funcoes do schema private (inofensivas sem policy).
-- Nao devolve privilegios ao papel anon: ele nao tinha policy, entao nunca teve acesso efetivo.

do $$
declare
    p record;
    t text;
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

    foreach t in array array['team_members', 'clients', 'client_private', 'documents',
                             'contact_log', 'declaration_checkpoints', 'daily_snapshots']
    loop
        execute format('create policy %I on public.%I for select to authenticated using (true)',
                       t || '_authenticated_select', t);
        execute format('create policy %I on public.%I for insert to authenticated with check (true)',
                       t || '_authenticated_insert', t);
        execute format('create policy %I on public.%I for update to authenticated using (true) with check (true)',
                       t || '_authenticated_update', t);
        execute format('create policy %I on public.%I for delete to authenticated using (true)',
                       t || '_authenticated_delete', t);
    end loop;
end;
$$;
