"""YARA scanning. Rules are compiled once; files are memory-mapped via ``filepath=``."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

import yara

RULES_PATH = Path(__file__).resolve().parents[1] / "rules" / "usb_threats.yar"
YARA_TIMEOUT_S = 10

_lock = threading.Lock()
_rules: yara.Rules | None = None


@dataclass(frozen=True)
class YaraHit:
    rule: str
    mitre: str


def get_rules() -> yara.Rules:
    """Compile the rule file on first use and cache it."""
    global _rules
    with _lock:
        if _rules is None:
            _rules = yara.compile(
                filepath=str(RULES_PATH), externals={"filename": "", "extension": ""}
            )
        return _rules


def rule_count() -> int:
    """Number of compiled rules."""
    return sum(1 for _ in get_rules())


def scan_file(path: str, filename: str, extension: str) -> list[YaraHit]:
    """Scan ``path`` and return matching rules (empty on timeout)."""
    try:
        matches = get_rules().match(
            filepath=path,
            externals={"filename": filename.lower(), "extension": extension.lower()},
            timeout=YARA_TIMEOUT_S,
        )
    except yara.TimeoutError:
        return []
    return [YaraHit(m.rule, str(m.meta.get("mitre", ""))) for m in matches]
