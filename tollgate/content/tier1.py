"""Tier 1: deterministic secrets, injection heuristics, PII (regex + checksum) and the signature feed."""
import math
import re
from collections import Counter

from tollgate.content import signatures
from tollgate.content.normalise import base64_runs


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


def kv_ok(v: str) -> bool:
    """A value that is one plain word ('patience.') is prose, not a credential."""
    return not v.rstrip(".,;:!?)").isalpha()


def entropy_ok(s: str) -> bool:
    """Shannon entropy >= 4.0 bits/char: random tokens pass, hex digests (max 4.0, ~3.8 in practice) and words do not.

    Base64 that decodes to text is not a secret itself: scan() decodes and scans its content instead.
    """
    n = len(s)
    if not (any(c.isdigit() for c in s) and any(c.isalpha() for c in s)):  # Long_Identifier_Names are not secrets
        return False
    return not base64_runs(s) and -sum(c / n * math.log2(c / n) for c in Counter(s).values()) >= 4.0


_KV = (r"(?i:[\w.-]*(?:secret|passw(?:or)?d|token|api[_-]?key|private[_-]?key|access[_-]?key)[\w.-]*)"
       r"""["']?\s*[:=]\s*["']?(?P<v>[^\s"'\[,;}]{8,})""")  # client_secret is covered by `secret`
_TOK = r"[A-Za-z0-9+=_-]"  # no "/": URL paths (a/b/c-d) scored as tokens in the eval; a slashed secret needs a key (secret.kv)

_inj = lambda m: "[INJ]"  # noqa: E731  never used for masking (inj actions are allow/approve/block)

# (rule_id, regex, validator, policy path, default action, mask, detail)
# Order matters: earlier rules claim their span; later rules skip overlapping matches.
RULES = [
    ("secret.private_key", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"), None, ("secrets",), "block", lambda m: "[SECRET]", "private key header"),
    ("secret.github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"), None, ("secrets",), "block", lambda m: "[SECRET]", "GitHub token"),
    ("secret.github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}"), None, ("secrets",), "block", lambda m: "[SECRET]", "GitHub fine-grained token"),
    ("secret.slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), None, ("secrets",), "block", lambda m: "[SECRET]", "Slack token"),
    ("secret.aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), None, ("secrets",), "block", lambda m: "[SECRET]", "AWS access key id"),
    # masks the value only (group v); a value starting with '[' is already masked
    ("secret.kv", re.compile(_KV), kv_ok, ("secrets",), "block", lambda m: "[SECRET]", "credential assignment"),
    # injection heuristics: default tier1_action 'allow' = reason kept as a flag for tier 2, verdict unaffected
    ("inj.md_exfil", re.compile(r"!\[[^\]]*\]\(\s*https?://[^\s)]*\?[^\s)]*=[^\s)]*\)", re.I), None, ("injection", "md_exfil"), "block", _inj, "markdown image exfiltration (URL with query)"),
    ("inj.ignore_prev", re.compile(r"\b(?:ignore|disregard|forget)\s+(?:(?:all|any|the|of|your)\s+){0,3}(?:previous|prior|above|earlier)\s+(?:instructions|rules|prompts?)\b", re.I), None, ("injection", "tier1_action"), "allow", _inj, "ignore-previous-instructions phrase"),
    ("inj.ignore_prev_pl", re.compile(r"\b(?:zignoruj|pomiń|zapomnij)\s+(?:o\s+)?(?:wszystki(?:e|ch)\s+)?(?:poprzedni(?:e|ch)|wcześniejsz(?:e|ych))\s+(?:instrukcj(?:e|i)|polece(?:nia|ń))", re.I), None, ("injection", "tier1_action"), "allow", _inj, "ignore-previous-instructions phrase (PL)"),
    ("inj.role_switch", re.compile(r"<\|im_start\|>|\[INST\]|^[ \t]*system[ \t]*:|\byou are now (?:in )?\w+ mode\b", re.I | re.M), None, ("injection", "tier1_action"), "allow", _inj, "chat-template token or role switch"),
    ("inj.hide_from_user", re.compile(r"\b(?:do not|don['’]?t)\s+(?:tell|inform|mention (?:this |it |anything )?to)\s+the user\b|\bnie (?:mów|informuj) użytkownik(?:owi|a)\b", re.I), None, ("injection", "tier1_action"), "allow", _inj, "instruction to hide from the user"),
    ("pii.iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"), iban_ok, ("pii", "iban"), "redact", lambda m: f"[IBAN:…{_last4(m)}]", "IBAN, checksum valid"),
    ("pii.pesel", re.compile(r"\b\d{11}\b"), pesel_ok, ("pii", "pesel"), "block", lambda m: "[PESEL]", "PESEL, checksum valid"),
    ("pii.nip", re.compile(r"\b\d{3}-?\d{3}-?\d{2}-?\d{2}\b"), nip_ok, ("pii", "nip"), "redact", lambda m: "[NIP]", "NIP, checksum valid"),
    ("pii.card", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), luhn_ok, ("pii", "card"), "redact", lambda m: f"[CARD:…{_last4(m)}]", "payment card, Luhn valid"),
    ("pii.email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"), None, ("pii", "email"), "redact", lambda m: "[EMAIL]", "email address"),
    # last: PII and named secrets claim their spans first
    ("secret.entropy", re.compile(rf"(?<!{_TOK}){_TOK}{{32,}}(?!{_TOK})"), entropy_ok, ("secrets",), "block", lambda m: "[SECRET]", "high-entropy token"),
]
# ponytail: no phone numbers yet; add when eval shows misses.


def _action(policy: dict, path: tuple, default: str) -> str:
    node = policy.get(path[0], default)
    if len(path) > 1:
        node = node.get(path[1], default) if isinstance(node, dict) else node
    return node if node in ("allow", "redact", "approve", "block") else default


def find(text: str, policy: dict) -> list[tuple[str, int, int, str, str, str]]:
    """Findings as (rule, start, end, action, mask, detail). Actions resolved against the policy.

    'allow' findings are dropped, except inj.* which are kept as flags (tier 2 escalation hint).
    """
    claimed: list[tuple[int, int]] = []
    out = []
    feed = [(r, rx, None, None, a, lambda m: "[SIG]", d) for r, rx, a, d in signatures.rules(policy.get("signatures"))]
    for rule, rx, ok, path, default, mask, detail in RULES + feed:
        for m in rx.finditer(text):
            g = "v" if "v" in rx.groupindex else 0  # a rule may mask one named group, not its whole match
            s, e = m.span(g)
            if any(s < ce and cs < e for cs, ce in claimed):
                continue
            if ok and not ok(m.group(g)):
                if rule == "pii.iban":  # an IBAN-shaped string claims its span even with a bad checksum,
                    claimed.append((s, e))  # so its digit groups are not re-read as a card number
                continue
            claimed.append((s, e))
            action = _action(policy, path, default) if path else default
            if action != "allow" or rule.startswith("inj."):
                out.append((rule, s, e, action, mask(m.group()), detail))
    return out
