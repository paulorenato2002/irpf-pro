from __future__ import annotations

import gov_password


class _Rpc:
    def __init__(self, data):
        self._data = data

    def execute(self):
        return type("Response", (), {"data": self._data})()


class _FakeClient:
    def __init__(self, data=None):
        self.calls: list[tuple[str, dict]] = []
        self._data = data

    def rpc(self, name, params):
        self.calls.append((name, params))
        return _Rpc(self._data)


def test_reveal_calls_rpc_with_client_id():
    client = _FakeClient(data="senha-ficticia")
    assert gov_password.reveal_gov_password(client, 7) == "senha-ficticia"
    assert client.calls == [("reveal_gov_password", {"p_client_id": 7})]


def test_reveal_returns_empty_string_when_no_password():
    assert gov_password.reveal_gov_password(_FakeClient(data=None), 7) == ""


def test_set_skips_blank_value():
    client = _FakeClient()
    gov_password.set_gov_password(client, 7, "   ")
    gov_password.set_gov_password(client, 7, "")
    assert client.calls == []


def test_set_calls_rpc_for_real_value():
    client = _FakeClient()
    gov_password.set_gov_password(client, 7, "nova-senha")
    assert client.calls == [("set_gov_password", {"p_client_id": 7, "p_value": "nova-senha"})]
