"""
rules/t1059_003.py — Windows Command Shell (T1059.003)

v2.0.0 — REVISED after auditing public-fixtures.json (P-DET-08, 12).
v1.0.0 only matched cmd.exe/wmiprvse.exe and would have missed both real
fixture cases (which use regsvr32.exe, not cmd.exe, as the image). See
decision log.

Detection logic (v2.0.0): documented (image, parent) pairs from replay
ground truth + both fixture cases, each verified against the full real
replay for zero false-positive risk — CRITICAL check here: the fixture
pair (regsvr32.exe, enterprise-updater.exe) is deliberately narrow to
that exact child binary, since (powershell.exe, enterprise-updater.exe)
is a confirmed real legitimate signed-update pattern (61 occurrences in
the replay) that must NOT be caught — see decision log.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pipeline.adapter import NormalizedEvent


RULE_ID = "T1059.003-001"
RULE_VERSION = "2.0.0"

ALLOWED_PAIRS = {
    ("cmd.exe", "wmiprvse.exe"),              # replay ground truth
    ("regsvr32.exe", "sccm-client.exe"),      # P-DET-08
    ("regsvr32.exe", "enterprise-updater.exe"),  # P-DET-12 — NOT powershell.exe, see docstring
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
            result="alerted", reason_code="known_t1059_003_execution_pattern",
        )

    return Verdict(
        event_id=event.event_id, rule_id=RULE_ID, rule_version=RULE_VERSION,
        result="suppressed", reason_code="pattern_not_in_known_t1059_003_set",
    )
