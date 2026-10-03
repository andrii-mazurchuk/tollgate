"""Tier 1: deterministic PII (regex + checksum) and secret detection."""
import re


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    return int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1


def pesel_ok(s: str) -> bool:
    d = [int(c) for c in s]
    month, day = int(s[2:4]) % 20, int(s[4:6])  # month +20 per century; cuts random 11-digit hits
    return len(d) == 11 and 1 <= month <= 12 and 1 <= day <= 31 and (10 - sum(w * x for w, x in zip((1, 3, 7, 9) * 3, d[:10])) % 10) % 10 == d[10]


def nip_ok(s: str) -> bool:
    d = [int(c) for c in s if c.isdigit()]
    return len(d) == 10 and sum(w * x for w, x in zip((6, 5, 7, 2, 3, 4, 5, 6, 7), d)) % 11 == d[9]


def luhn_ok(s: str) -> bool:
    d = [int(c) for c in s if c.isdigit()][::-1]
    return 13 <= len(d) <= 19 and sum(x if i % 2 == 0 else (x * 2 - 9 if x > 4 else x * 2) for i, x in enumerate(d)) % 10 == 0


def _last4(m: str) -> str:
    return m.replace(" ", "").replace("-", "")[-4:]


# (rule_id, regex, validator, policy path, default action, mask, detail)
# Order matters: earlier rules claim their span; later rules skip overlapping matches.
RULES = [
    ("secret.private_key", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"), None, ("secrets",), "block", lambda m: "[SECRET]", "private key header"),
    ("secret.github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"), None, ("secrets",), "block", lambda m: "[SECRET]", "GitHub token"),
    ("secret.aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), None, ("secrets",), "block", lambda m: "[SECRET]", "AWS access key id"),
    ("pii.iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"), iban_ok, ("pii", "iban"), "redact", lambda m: f"[IBAN:…{_last4(m)}]", "IBAN, checksum valid"),
    ("pii.pesel", re.compile(r"\b\d{11}\b"), pesel_ok, ("pii", "pesel"), "block", lambda m: "[PESEL]", "PESEL, checksum valid"),
    ("pii.nip", re.compile(r"\b\d{3}-?\d{3}-?\d{2}-?\d{2}\b"), nip_ok, ("pii", "nip"), "redact", lambda m: "[NIP]", "NIP, checksum valid"),
    ("pii.card", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), luhn_ok, ("pii", "card"), "redact", lambda m: f"[CARD:…{_last4(m)}]", "payment card, Luhn valid"),
    ("pii.email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"), None, ("pii", "email"), "redact", lambda m: "[EMAIL]", "email address"),
]
# ponytail: no secret entropy check or phone numbers yet; add when eval shows misses.


def _action(policy: dict, path: tuple, default: str) -> str:
    node = policy.get(path[0], default)
    if len(path) > 1:
        node = node.get(path[1], default) if isinstance(node, dict) else node
    return node if node in ("allow", "redact", "approve", "block") else default


def find(text: str, policy: dict) -> list[tuple[str, int, int, str, str, str]]:
    """Findings as (rule, start, end, action, mask, detail). Actions resolved against the policy; 'allow' dropped."""
    claimed: list[tuple[int, int]] = []
    out = []
    for rule, rx, ok, path, default, mask, detail in RULES:
        for m in rx.finditer(text):
            s, e = m.span()
            if any(s < ce and cs < e for cs, ce in claimed):
                continue
            if ok and not ok(m.group()):
                if rule == "pii.iban":  # an IBAN-shaped string claims its span even with a bad checksum,
                    claimed.append((s, e))  # so its digit groups are not re-read as a card number
                continue
            claimed.append((s, e))
            action = _action(policy, path, default)
            if action != "allow":
                out.append((rule, s, e, action, mask(m.group()), detail))
    return out
