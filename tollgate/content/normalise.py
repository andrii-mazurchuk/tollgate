"""Stage 1: normalise text before tier 1. Records each transform that fired (obfuscation is a signal)."""
import base64
import binascii
import codecs
import re
import unicodedata
from urllib.parse import unquote_plus

# zero-width, bidi controls, word joiners, BOM, soft hyphen
_INVISIBLE = re.compile("[­​-‏‪-‮⁠-⁤⁦-⁩﻿]")
_B64_RUN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){12,}(?![0-9A-Fa-f])")
_URL_RUN = re.compile(r"[^\s%]{0,200}(?:%[0-9A-Fa-f]{2}[^\s%]{0,200}){3,}")
MAX_B64_RUNS = 32  # cap on decoded runs of all kinds per scan
MAX_B64_LEN = 65536
# Cyrillic/Greek lookalikes -> Latin, 1:1 so spans are preserved
_LOOK = "аеорсухіјѕԁӏкмАВЕКМНОРСТХІЈЅαονικτρΑΒΕΖΗΙΚΜΝΟΡΤΥΧ"
_HOMOGLYPHS = str.maketrans(_LOOK, "aeopcyxijsdlkmABEKMHOPCTXIJSaoviktpABEZHIKMNOPTYX")
_WORD = re.compile(r"\w+")
_LATIN = re.compile(r"[A-Za-z]")
_NONLATIN = re.compile(r"[^\W\d_A-Za-z]")
# leetspeak: digits standing in for letters inside a word that also has letters ("1gn0r3", "y0ur")
_LEET = str.maketrans("0134578", "oieastb")
# a letter beyond a-f is required: hex ids/UUIDs/digests ("3f2b8c4e") are not leetspeak
_LEET_WORD = re.compile(r"\b(?=\w*[g-zG-Z])(?=\w*\d)\w{3,}\b")
_LEET_INSIDE = re.compile(r"\b(?=\w*[g-zG-Z])\w*[A-Za-z]\d+[A-Za-z]\w*\b")
# letters split by one separator each: "i g n o r e", "S-Y-S-T-E-M", "d.i.s.r.e.g.a.r.d"
_SPACED = re.compile(r"(?<!\w)(?:[A-Za-z][ .\-_*]){2,}[A-Za-z](?!\w)")


def _fold_word(m: re.Match, whole: bool) -> str:
    w = m.group()
    # mixed-script words always; all-lookalike words only when the text is mostly Latin (pure Cyrillic stays)
    if any("a" <= c.lower() <= "z" for c in w) or (whole and all(c in _LOOK for c in w)):
        return w.translate(_HOMOGLYPHS)
    return w


def normalise(text: str) -> tuple[str, list[str]]:
    transforms = []
    nfkc = unicodedata.normalize("NFKC", text)
    if nfkc != text:
        transforms.append("nfkc")
    stripped = _INVISIBLE.sub("", nfkc)
    if stripped != nfkc:
        transforms.append("zero_width")
    whole = len(_LATIN.findall(stripped)) > len(_NONLATIN.findall(stripped))
    folded = _WORD.sub(lambda m: _fold_word(m, whole), stripped)
    if folded != stripped:
        transforms.append("homoglyph")
    return folded, transforms


def _printable(s: str) -> bool:
    return bool(s) and all(c.isprintable() or c.isspace() for c in s)


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
        if _printable(decoded):
            out.append((m.start(), m.end(), normalise(decoded)[0]))
            if len(out) >= MAX_B64_RUNS:
                break
    return out


def _hex_runs(text: str) -> list[tuple[int, int, str]]:
    out = []
    for m in _HEX_RUN.finditer(text):
        try:
            decoded = bytes.fromhex(m.group()).decode("utf-8")
        except (ValueError, UnicodeDecodeError):  # digests decode to binary and stop here
            continue
        if _printable(decoded) and " " in decoded:
            out.append((m.start(), m.end(), normalise(decoded)[0]))
        if len(out) >= MAX_B64_RUNS:
            break
    return out


def _url_runs(text: str) -> list[tuple[int, int, str]]:
    out = []
    for m in _URL_RUN.finditer(text):
        decoded = unquote_plus(m.group())
        if decoded != m.group() and _printable(decoded):
            out.append((m.start(), m.end(), normalise(decoded)[0]))
        if len(out) >= MAX_B64_RUNS:
            break
    return out


def fold_variant(text: str) -> tuple[str | None, list[str]]:
    """Whole-text variant with spaced letters joined and leetspeak folded, or None if neither is substantial.

    A variant, not the normalised text: folding "4B" or "sha256" in place would break PII/secret spans.
    """
    tf, out = [], text
    if sum(len(s) for s in _SPACED.findall(out)) >= 15:  # a few single-letter lists ("a, b, c") do not count
        out = _SPACED.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group()), out)
        tf.append("spaced")
    # trigger on digits *inside* words ("y0ur", "1gn0r3"); "x86", "utf8", "v2" have them only at an edge
    strong = _LEET_INSIDE.findall(out)
    if len(strong) >= 2 and len(strong) * 10 >= len(_WORD.findall(out)):
        out = _LEET_WORD.sub(lambda m: m.group().lower().translate(_LEET), out)
        tf.append("leet")
    return (out if tf else None), tf


def rot13(text: str) -> str:
    return codecs.encode(text, "rot13")


def decoded_runs(text: str) -> list[tuple[int, int, str, str]]:
    """(start, end, decoded, transform) for base64, hex and URL-encoded runs. Bounded in count."""
    out = [(*r, "base64") for r in base64_runs(text)]
    out += [(*r, "hex") for r in _hex_runs(text)]
    out += [(*r, "url") for r in _url_runs(text)]
    return out[:MAX_B64_RUNS]
