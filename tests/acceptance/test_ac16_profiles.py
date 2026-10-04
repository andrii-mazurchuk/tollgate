from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.track_a]
ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("name", ["strict", "balanced", "lenient"])
def test_ac16_profile_loads(name):
    """AC16: each sample profile is a full policy that validates and loads through PolicyHolder."""
    from tollgate.gateway.policy import load_policy

    h = load_policy(ROOT / "policies" / f"{name}.yaml")
    d = h.data
    assert d["mode"] == name and h.status()["last_error"] is None
    assert set(d["roles"]) == {"role-1", "role-2"} and d["labels"]["tickets.reply"] == ["public_sink"]
    assert {"pii", "secrets", "injection", "signatures"} <= set(d["content"])
    assert all(r["budget"]["tokens_per_day"] > 0 for r in d["roles"].values())


def test_ac16_balanced_is_the_active_policy():
    """policy.yaml is the balanced profile: gateway sections identical."""
    active = yaml.safe_load((ROOT / "policy.yaml").read_text(encoding="utf-8"))
    bal = yaml.safe_load((ROOT / "policies" / "balanced.yaml").read_text(encoding="utf-8"))
    for k in ("mode", "servers", "roles", "labels", "builtins", "taint", "loops"):
        assert active[k] == bal[k], k
