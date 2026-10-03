"""Loads policy.yaml. The gateway reads `holder.data` on every request, so hot reload (AC7) only swaps it."""
from pathlib import Path

import yaml

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "policy.yaml"


class PolicyHolder:
    def __init__(self, data: dict):
        self.data = data


def validate(p: dict) -> dict:
    """Checks A's sections only; `content` is passed through untouched (Track B)."""
    servers = p.get("servers") or {}
    for role, r in (p.get("roles") or {}).items():
        for srv, spec in (r.get("servers") or {}).items():
            if srv not in servers:
                raise ValueError(f"roles.{role}.servers.{srv}: unknown server")
            if spec.get("access") not in ("read", "rw") and not isinstance(spec.get("tools"), list):
                raise ValueError(f"roles.{role}.servers.{srv}: need access: read|rw or tools: [...]")
        for tool, c in (r.get("constrain") or {}).items():
            if not isinstance(c, dict) or tool.split(".")[0] not in servers:
                raise ValueError(f"roles.{role}.constrain.{tool}: bad constraint")
    return p


def load_policy(path: str | Path = DEFAULT_PATH) -> PolicyHolder:
    return PolicyHolder(validate(yaml.safe_load(Path(path).read_text(encoding="utf-8"))))
