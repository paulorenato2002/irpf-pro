from __future__ import annotations

import io

import openpyxl
import pandas as pd

import app


def test_full_export_has_no_senha_gov_column():
    people_df = pd.DataFrame(
        [
            {
                "client_id": 1,
                "NOME": "CLIENTE FICTICIO",
                "Grupo": "G",
                "Responsável pelo Preenchimento": "Paulo",
                "Status Preenchimento": "PENDENTE",
                "CPF": "000.000.000-00",
                "Senha Gov": "x-senha-fake",
                "Senha Gov Cadastrada": True,
            }
        ]
    )
    documents_df = pd.DataFrame(columns=["client_id", "Tipo Documento", "Status"])
    checkpoints_df = pd.DataFrame(columns=["client_id", "step_key"])

    workbook = openpyxl.load_workbook(io.BytesIO(app.build_full_database_export(people_df, documents_df, checkpoints_df)))
    sheet = workbook["Clientes"]
    headers = [cell.value for cell in sheet[1]]
    assert "Senha Gov" not in headers
    assert "Senha Gov Cadastrada" in headers  # indicador não sensível pode ir
    every_value = [cell.value for row in sheet.iter_rows() for cell in row]
    assert "x-senha-fake" not in every_value
