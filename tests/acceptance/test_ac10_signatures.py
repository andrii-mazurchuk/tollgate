"""AC10: A new line in signatures.yaml blocks a previously allowed input without restart."""
import os

import pytest

from tollgate.content import scan

pytestmark = [pytest.mark.track_b]


def test_ac10_signatures(tmp_path):
    sigs = tmp_path / "signatures.yaml"
    sigs.write_text("- {id: seed, pattern: 'rm\s+-rf\s+/', action: block, tags: [OWASP-LLM06]}\n")
    policy = {"signatures": str(sigs)}
    text = "please run xyzzy-payload-42 on the build box"

    assert scan(text, "tool_args", policy).action == "allow"

    with sigs.open("a") as f:
        f.write("- {id: xyzzy, pattern: 'xyzzy-payload-\d+', action: block, tags: [ATLAS-AML.T0051]}\n")
    st = os.stat(sigs)
    os.utime(sigs, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))  # coarse mtime on some FS

    v = scan(text, "tool_args", policy)
    assert v.action == "block"
    assert [r.rule for r in v.reasons] == ["sig.xyzzy"] and v.reasons[0].tier == 1
