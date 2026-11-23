"""Senha gov.br: leitura sob demanda e gravação só pelas funções do banco (com auditoria).

O banco guarda a senha cifrada e só a devolve por `reveal_gov_password` (que registra quem viu);
a gravação passa por `set_gov_password`. Nenhuma tela carrega a senha em massa.
"""
from __future__ import annotations

import streamlit as st
from supabase import Client


def reveal_gov_password(client: Client, client_id: int) -> str:
    response = client.rpc("reveal_gov_password", {"p_client_id": int(client_id)}).execute()
    return response.data or ""


def _bump_input_nonce() -> None:
    try:
        st.session_state["gov_input_nonce"] = st.session_state.get("gov_input_nonce", 0) + 1
    except Exception:  # fora do Streamlit (testes) não há sessão
        pass


def set_gov_password(client: Client, client_id: int, value: str) -> None:
    """Grava a senha pela função do banco. Valor em branco = manter a atual (não faz nada)."""
    if not (value or "").strip():
        return
    client.rpc("set_gov_password", {"p_client_id": int(client_id), "p_value": value}).execute()
    _bump_input_nonce()  # o campo de senha dos formulários volta vazio depois de salvar


def gov_password_input(label: str, client_id: int) -> str:
    """Campo de senha para formulários: vazio por padrão, em branco mantém a senha atual."""
    nonce = st.session_state.get("gov_input_nonce", 0)
    return st.text_input(
        label,
        type="password",
        key=f"gov_input_{client_id}_{nonce}",
        help="Deixe em branco para manter a senha atual.",
    )


def render_gov_password_reveal(client: Client | None, client_id: int, has_password: bool, key: str) -> None:
    """Mostra se há senha cadastrada e, se houver, um botão que a revela uma vez (fica registrado)."""
    st.caption("Senha Gov.br")
    if not has_password:
        st.write("Não informada")
        return
    revealed = st.session_state.pop(f"gov_reveal_{key}", None)
    if revealed is not None:
        st.code(revealed or "(vazia)", language=None)
        return
    if client is None:
        st.write("Cadastrada")
        return
    if st.button("Mostrar senha", key=f"gov_button_{key}"):
        try:
            st.session_state[f"gov_reveal_{key}"] = reveal_gov_password(client, client_id)
        except Exception:
            st.error("Não foi possível mostrar a senha. Seu usuário pode não ter permissão.")
            return
        st.rerun()
    else:
        st.write("Cadastrada")
