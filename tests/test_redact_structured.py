import pytest
from fastmcp import Client

pytestmark = [pytest.mark.track_a]


async def test_redacted_structured_result_keeps_output_schema(tmp_path, monkeypatch):
    """A list-returning tool whose result is redacted still satisfies its output schema (no client RuntimeError)."""
    monkeypatch.setenv("TOLLGATE_AUDIT", str(tmp_path / "events.jsonl"))
    from mocks.tickets import reset
    from tollgate.gateway import build_role_server, taint
    from tollgate.gateway.policy import load_policy

    reset()
    taint.reset("local")
    async with Client(build_role_server("role-2", load_policy())) as c:
        res = await c.call_tool("tickets.query", {"sql": "SELECT name, email, iban FROM customers"})
    taint.reset("local")
    text = res.content[0].text
    assert "jan@acme.pl" not in text and "[EMAIL]" in text and "PL61" not in text
    assert res.data[0][0] == "Jan Kowalski" and res.data[0][1] == "[EMAIL]"  # rows survive as rows
