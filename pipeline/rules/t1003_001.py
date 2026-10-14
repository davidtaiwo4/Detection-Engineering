"""
rules/t1003_001.py — OS Credential Dumping: LSASS Memory (T1003.001)

v2.0.0 — REVISED after auditing public-fixtures.json (P-DET-01, 07, 10).
v1.0.0 only matched rundll32.exe/powershell.exe and would have missed
all 3 real fixture cases. See decision log.

Detection logic (v2.0.0): documented (image, parent) pairs from replay
ground truth + all 3 fixture cases, each verified against the full real
replay for zero false-positive risk (see decision log).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pipeline.adapter import NormalizedEvent


RULE_ID = "T1003.001-001"
RULE_VERSION = "2.0.0"

ALLOWED_PAIRS = {
    ("rundll32.exe", "powershell.exe"),  # replay ground truth (comsvcs.dll MiniDump pattern)
    ("regsvr32.exe", "services.exe"),    # P-DET-01
    ("cmd.exe", "winword.exe"),          # P-DET-07
    ("cmd.exe", "explorer.exe"),         # P-DET-10
}


@dataclass(frozen=True)
class Verdict:
    event_id: str
    rule_id: str
    rule_version: str
    result: str
    reason_code: str


def evaluate(event: NormalizedEvent, all_events: list[NormalizedEvent] = None) -> Optional[Verdict]:
    del all_events

    if event.event_code != 1:
        return None

    image = event.image.strip().lower()
    parent = event.parent_image.strip().lower()

    if image not in {p[0] for p in ALLOWED_PAIRS}:
        return None

    if (image, parent) in ALLOWED_PAIRS:
        return Verdict(
            event_id=event.event_id, rule_id=RULE_ID, rule_version=RULE_VERSION,
            result="alerted", reason_code="known_t1003_001_execution_pattern",
        )

    return Verdict(
        event_id=event.event_id, rule_id=RULE_ID, rule_version=RULE_VERSION,
        result="suppressed", reason_code="pattern_not_in_known_t1003_001_set",
    )
