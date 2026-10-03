"""Tier 1 secrets beyond fixed prefixes: key-value assignments, GitHub fine-grained / Slack tokens, entropy."""
import pytest

from tollgate.content import scan

pytestmark = [pytest.mark.track_b]

BLOCK = {"secrets": "block"}
REDACT = {"secrets": "redact"}
ENV = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nSALARY_ALICE=182000\n"


def rules(v):
    return [r.rule for r in v.reasons]


def test_demo_env_masks_both_aws_keys():
    v = scan(ENV, "tool_result", REDACT)
    assert v.action == "redact"
    assert v.redacted_text == "AWS_ACCESS_KEY_ID=[SECRET]\nAWS_SECRET_ACCESS_KEY=[SECRET]\nSALARY_ALICE=182000\n"


@pytest.mark.parametrize("text, masked", [
    ('{"password": "hunter2hunter2"}', '{"password": "[SECRET]"}'),
    ("API_KEY='sk_live_51Habc'", "API_KEY='[SECRET]'"),
    ("db_passwd: Zx9!long-pass", "db_passwd: [SECRET]"),
    ('client_secret = "8f2a9c1e7b"', 'client_secret = "[SECRET]"'),
])
def test_kv_masks_only_the_value(text, masked):
    v = scan(text, "response", REDACT)
    assert "secret.kv" in rules(v) and v.redacted_text == masked


@pytest.mark.parametrize("text, rule", [
    ("token github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz", "secret.github_pat"),
    ("slack xoxb-1234567890-0987654321-AbCdEfGhIjKl", "secret.slack_token"),
    ("blob Zm9vYmFyQmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A_x-Yq", "secret.entropy"),
])
def test_token_rules_block(text, rule):
    v = scan(text, "tool_result", BLOCK)
    assert v.action == "block" and rule in rules(v)


@pytest.mark.parametrize("text", [
    "request id 3f2b8c4e-1a7d-4e9b-8c2f-5d6a7b8c9d0e failed",
    "use token=abc for the sandbox",
    "AWS_SECRET_ACCESS_KEY=[SECRET]",  # already masked upstream: no double hit
    "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "The secret: patience. Password policy: rotate yearly.",
])
def test_benign_lookalikes_allowed(text):
    assert scan(text, "tool_result", BLOCK).action == "allow"
