"""AC8 (PII part): tier 1 normalisation, checksum-validated PII and secrets via scan()."""
import base64

import pytest

from tollgate.content import scan

pytestmark = [pytest.mark.track_b]

POLICY = {"pii": {"iban": "redact", "pesel": "block", "card": "redact", "email": "redact"}, "secrets": "block"}

IBAN = "PL61 1090 1014 0000 0712 1981 2874"
GHP = "ghp_" + "a1B2c3D4e5" * 3 + "F6g7H8"  # ghp_ + 36 alnum
AKIA = "AKIAIOSFODNN7EXAMPLE"
ZW = "​"


def rules(v):
    return [r.rule for r in v.reasons]


@pytest.mark.parametrize(
    "text, action, rule",
    [
        (f"Account: {IBAN}", "redact", "pii.iban"),
        ("Account: PL61 1090 1014 0000 0712 1981 2875", "allow", None),
        ("PESEL 44051401359", "block", "pii.pesel"),
        ("PESEL 44051401358", "allow", None),
        ("card 4111 1111 1111 1111", "redact", "pii.card"),
        ("card 4111 1111 1111 1112", "allow", None),
        ("mail me at jan.kowalski@example.pl", "redact", "pii.email"),
        (f"token {GHP}", "block", "secret.github_token"),
        (f"aws {AKIA}", "block", "secret.aws_key"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIE...", "block", "secret.private_key"),
        ("NIP 123-456-32-18", "redact", "pii.nip"),
        ("NIP 123-456-32-19", "allow", None),
        ("Please summarise the open issues in the repo by Friday.", "allow", None),
    ],
)
def test_tier1_rules(text, action, rule):
    v = scan(text, "tool_result", POLICY)
    assert v.action == action
    if rule is None:
        assert v.reasons == []
    else:
        assert rule in rules(v)
        assert all(r.tier == 1 and r.span for r in v.reasons)
    assert "t1" in v.latency_ms


def test_iban_redaction_replaces_only_span():
    v = scan(f"Account: {IBAN} thanks", "response", POLICY)
    assert v.redacted_text == "Account: [IBAN:…2874] thanks"
    (r,) = v.reasons
    assert r.rule == "pii.iban" and r.span == (9, 9 + len(IBAN))


def test_card_regex_does_not_fire_inside_iban():
    v = scan(f"IBAN {IBAN}", "tool_result", POLICY)
    assert rules(v) == ["pii.iban"]


def test_fusion_most_severe_wins():
    v = scan(f"{IBAN} and PESEL 44051401359", "tool_result", POLICY)
    assert v.action == "block" and v.redacted_text is None
    assert set(rules(v)) == {"pii.iban", "pii.pesel"}


def test_policy_overrides_defaults():
    v = scan("PESEL 44051401359", "tool_result", {"pii": {"pesel": "redact"}})
    assert v.action == "redact" and v.redacted_text == "PESEL [PESEL]"


def test_zero_width_stripped_inside_secret():
    v = scan(f"token {GHP[:10]}{ZW}{GHP[10:]}", "tool_args", POLICY)
    assert v.action == "block" and "zero_width" in v.transforms


def test_fullwidth_digits_nfkc():
    v = scan("PESEL ４４０５１４０１３５９", "tool_result", POLICY)
    assert v.action == "block" and "nfkc" in v.transforms


def test_base64_run_is_decoded_and_scanned():
    blob = base64.b64encode(f"here is my key {AKIA} ok".encode()).decode()
    v = scan(f"data: {blob}", "tool_args", POLICY)
    assert v.action == "block"
    assert "secret.aws_key" in rules(v) and "base64" in v.transforms


def test_base64_pii_redacts_whole_run():
    blob = base64.b64encode(b"contact jan@example.com please").decode()
    v = scan(f"x {blob} y", "tool_result", POLICY)
    assert v.action == "redact" and v.redacted_text == "x [EMAIL] y"


def test_benign_base64_not_flagged():
    blob = base64.b64encode(b"just some ordinary harmless words").decode()
    v = scan(f"x {blob} y", "tool_result", POLICY)
    assert v.action == "allow" and v.reasons == []


def test_scan_never_raises():
    v = scan(None, "prompt", POLICY)  # type: ignore[arg-type]
    assert v.action == "allow" and rules(v) == ["content.error"]


def test_validators():
    from tollgate.content.tier1 import iban_ok, luhn_ok, nip_ok, pesel_ok

    assert iban_ok("PL61109010140000071219812874") and not iban_ok("PL61109010140000071219812875")
    assert iban_ok("DE89370400440532013000") and not iban_ok("DE89370400440532013001")
    assert pesel_ok("44051401359") and pesel_ok("02070803628") and not pesel_ok("44051401358")
    assert luhn_ok("4111111111111111") and luhn_ok("5500005555555559") and not luhn_ok("4111111111111112")
    assert nip_ok("1234563218") and not nip_ok("1234563219")
