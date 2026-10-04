"""Tier 2: protectai/deberta-v3-base-prompt-injection-v2, ONNX fp32 on CPU. Lazy singleton; None when unavailable."""
import hashlib
import logging
import os
import threading

log = logging.getLogger(__name__)
REPO = "protectai/deberta-v3-base-prompt-injection-v2"
REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"  # pinned commit: a pushed model change is not picked up silently
CHUNK, OVERLAP = 256, 32
CACHE: dict[str, list[float]] | None = None  # sha256(text) -> [score, ms]; set by the eval runner only
MS = 0.0  # with CACHE set: model ms summed over score() calls; the eval runner resets it per case

_lock = threading.Lock()
_model = None  # (tokenizer, session, cls, sep) | False once loading failed


def _load():
    global _model
    if os.environ.get("TOLLGATE_T2") == "off":  # fast test runs (smoke): unavailable without poisoning the singleton
        return None
    if _model is None:
        with _lock:
            if _model is None:
                try:
                    import onnxruntime as ort
                    from huggingface_hub import hf_hub_download
                    from tokenizers import Tokenizer

                    tok = Tokenizer.from_file(hf_hub_download(REPO, "onnx/tokenizer.json", revision=REVISION))
                    so = ort.SessionOptions()
                    so.intra_op_num_threads = 4
                    sess = ort.InferenceSession(hf_hub_download(REPO, "onnx/model.onnx", revision=REVISION), so, providers=["CPUExecutionProvider"])
                    _model = (tok, sess, tok.token_to_id("[CLS]"), tok.token_to_id("[SEP]"))
                except Exception as exc:  # no model / no runtime: tier 2 reports unavailable, never raises
                    log.warning("tier 2 unavailable: %s", exc)
                    _model = False
    return _model or None


def available() -> bool:
    return _load() is not None


def n_tokens(text: str) -> int | None:
    m = _load()
    return None if m is None else len(m[0].encode(text, add_special_tokens=False).ids)


def _score(text: str, max_chunks: int | None = None) -> float | None:
    m = _load()
    if m is None:
        return None
    import numpy as np

    tok, sess, cls, sep = m
    ids = tok.encode(text, add_special_tokens=False).ids or [sep]
    body, step, best = CHUNK - 2, CHUNK - 2 - OVERLAP, 0.0
    starts = list(range(0, max(len(ids) - OVERLAP, 1), step))
    if max_chunks and len(starts) > max_chunks:  # evenly spaced sample, first and last always in
        starts = [starts[round(i * (len(starts) - 1) / (max_chunks - 1))] for i in range(max_chunks)] if max_chunks > 1 else starts[:1]
    for s in starts:
        x = np.array([[cls, *ids[s:s + body], sep]], dtype=np.int64)
        lg = sess.run(None, {"input_ids": x, "attention_mask": np.ones_like(x)})[0][0]
        e = np.exp(lg - lg.max())
        best = max(best, float(e[1] / e.sum()))
    return best


def score(text: str, max_chunks: int | None = None) -> float | None:
    """Injection probability (max over 256-token chunks, or an evenly spaced sample of max_chunks), None if unavailable."""
    if CACHE is None:
        return _score(text, max_chunks)
    key = hashlib.sha256(text.encode()).hexdigest() + (f":{max_chunks}" if max_chunks else "")
    if key not in CACHE:
        import time

        t0 = time.perf_counter()
        s = _score(text, max_chunks)
        if s is None:
            return None
        CACHE[key] = [s, round((time.perf_counter() - t0) * 1000, 3)]
    global MS
    MS += CACHE[key][1]
    return CACHE[key][0]
