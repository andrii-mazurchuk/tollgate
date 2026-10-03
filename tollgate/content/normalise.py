"""Stage 1: normalise text before tier 1. Records each transform that fired (obfuscation is a signal)."""
import base64
import binascii
import re
import unicodedata

# zero-width, bidi controls, word joiners, BOM, soft hyphen
_INVISIBLE = re.compile("[­​-‏‪-‮⁠-⁤⁦-⁩﻿]")
_B64_RUN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
MAX_B64_RUNS = 32
MAX_B64_LEN = 65536


def normalise(text: str) -> tuple[str, list[str]]:
    transforms = []
    nfkc = unicodedata.normalize("NFKC", text)
    if nfkc != text:
        transforms.append("nfkc")
    stripped = _INVISIBLE.sub("", nfkc)
    if stripped != nfkc:
        transforms.append("zero_width")
    # ponytail: no homoglyph folding / hex / URL decoding yet; add with AC9 (obfuscated-variant recall).
    return stripped, transforms


def base64_runs(text: str) -> list[tuple[int, int, str]]:
    """(start, end, decoded) for base64 runs that decode to printable UTF-8. Bounded in count and length."""
    out = []
    for m in _B64_RUN.finditer(text):
        run = m.group()
        if len(run) % 4 or len(run) > MAX_B64_LEN:
            continue
        try:
            decoded = base64.b64decode(run, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if decoded and all(c.isprintable() or c.isspace() for c in decoded):
            out.append((m.start(), m.end(), normalise(decoded)[0]))
            if len(out) >= MAX_B64_RUNS:
                break
    return out
