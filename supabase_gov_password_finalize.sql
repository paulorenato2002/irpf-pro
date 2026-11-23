-- Fase 1b (parte 2, FINALIZE): apaga a senha gov.br em texto puro.
-- Rode SO depois de: (1) supabase_gov_password.sql aplicado, (2) app novo publicado e testado,
-- (3) backup feito. Depois disso a volta e so pelo backup. Sem BEGIN/COMMIT.
-- Aborta sozinho se alguma senha em texto puro nao tiver versao cifrada igual.

do $$
begin
    -- Completa o que faltar (nao sobrescreve o que ja estiver cifrado).
    insert into public.client_secrets (client_id, gov_password_enc)
    select cp.client_id, extensions.pgp_sym_encrypt(cp.gov_password, private.gov_key())
    from public.client_private cp
    where coalesce(btrim(cp.gov_password), '') <> ''
    on conflict (client_id) do nothing;

    -- Toda senha em texto puro precisa ter a versao cifrada e ela precisa decifrar para o mesmo valor.
    if exists (
        select 1
        from public.client_private cp
        left join public.client_secrets s on s.client_id = cp.client_id
        where coalesce(btrim(cp.gov_password), '') <> ''
          and (s.client_id is null
               or extensions.pgp_sym_decrypt(s.gov_password_enc, private.gov_key()) is distinct from cp.gov_password)
    ) then
        raise exception 'finalize abortado: ha senha em texto puro sem versao cifrada equivalente';
    end if;

    update public.client_private cp
    set has_gov_password = true
    where exists (select 1 from public.client_secrets s where s.client_id = cp.client_id)
      and not cp.has_gov_password;
end;
$$;

drop trigger if exists client_private_encrypt_gov_password on public.client_private;
alter table public.client_private drop column if exists gov_password;
drop function if exists private.encrypt_gov_password_on_write();
