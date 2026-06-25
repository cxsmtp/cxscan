"""Data models: config, the unified Finding, and gate evaluation."""
from __future__ import annotations
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Optional

# Single normalized severity scale across all four engines.
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Per-engine native severity -> normalized.
SAST_MAP = {"information": "INFO", "info": "INFO", "low": "LOW",
            "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}
SCA_MAP = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}
# SARIF level -> normalized (used by KICS + 2ms when no richer field exists).
SARIF_LEVEL_MAP = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
KICS_SEV_MAP = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                "low": "LOW", "info": "INFO", "trace": "INFO"}


def normalize_sev(raw: str, table: dict, default: str = "MEDIUM") -> str:
    return table.get((raw or "").strip().lower(), default)


_ENV = re.compile(r"\$\{([^}]+)\}")


def resolve_env(value):
    """Replace ${VAR} with the environment value, recursively over dict/list."""
    if isinstance(value, str):
        return _ENV.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: resolve_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_env(v) for v in value]
    return value


@dataclass
class Finding:
    engine: str            # sast | sca | kics | twoms
    rule_id: str
    title: str
    severity: str          # normalized
    file: Optional[str] = None
    line: Optional[int] = None
    description: str = ""
    extra: dict = field(default_factory=dict)

    def public(self, redact: bool = True) -> dict:
        d = asdict(self)
        # Never ship a raw secret value to the dashboard.
        if redact and self.engine == "twoms":
            d["extra"] = {k: v for k, v in self.extra.items()
                          if k not in ("secret", "match", "value")}
        return d


@dataclass
class EngineThreshold:
    """Map of normalized severity -> max allowed count at or above that severity."""
    limits: dict = field(default_factory=dict)

    @classmethod
    def from_config(cls, raw: dict) -> "EngineThreshold":
        norm = {}
        for k, v in (raw or {}).items():
            key = k.upper()
            if key in SEV_RANK:
                norm[key] = int(v)
        return cls(limits=norm)

    def evaluate(self, findings: list[Finding]) -> tuple[bool, list[str]]:
        """Return (passed, reasons). Fails if any severity floor is exceeded."""
        reasons = []
        for sev, max_allowed in self.limits.items():
            floor = SEV_RANK[sev]
            count = sum(1 for f in findings if SEV_RANK.get(f.severity, 1) >= floor)
            if count > max_allowed:
                reasons.append(f"{count} finding(s) >= {sev} (limit {max_allowed})")
        return (len(reasons) == 0, reasons)
