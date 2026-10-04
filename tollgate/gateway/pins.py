"""Tool-description pinning (rug-pull defence): hash each source tool at startup; a changed tool is hidden and alerted.

ponytail: pins live in memory, taken when the app starts; re-pinning (accepting a new description) is a restart.
"""
import hashlib
import json

from tollgate.contract import AuditEvent, Reason
from tollgate.gateway import audit
from tollgate.util import now_z


def digest(tool) -> str:
    blob = json.dumps([tool.name, tool.description or "", tool.parameters], sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


class Pins:
    def __init__(self):
        self.pins: dict[str, str] = {}
        self.alerts: dict[str, dict] = {}  # tool -> {tool, old, new, ts}

    def take(self, tools) -> None:
        self.pins = {t.name: digest(t) for t in tools}

    def changed(self, tool, role: str) -> bool:
        """True if the tool no longer matches its pin. A new hash is alerted (and audited) once."""
        old = self.pins.get(tool.name)
        new = digest(tool)
        if old is None or old == new:  # ponytail: tools added after startup are not pinned; pin them on first sight if needed
            return False
        if (self.alerts.get(tool.name) or {}).get("new") != new:
            ts = now_z("milliseconds")
            self.alerts[tool.name] = {"tool": tool.name, "old": old, "new": new, "ts": ts}
            audit.write(AuditEvent(ts=ts, role=role, key_id="-", door="tool", verdict="block",
                                   reasons=[Reason(rule="pin.changed", tier=0, detail=f"{old[:12]} -> {new[:12]}")],
                                   source=tool.name.partition(".")[0], tool=tool.name))
        return True
