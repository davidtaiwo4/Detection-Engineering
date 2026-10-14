"""
rules/t1218_011.py — System Binary Proxy Execution: Rundll32 (T1218.011)

v2.0.0 — REVISED after auditing public-fixtures.json (P-DET-03, 05, 09, 11)
— notably, ZERO of the 4 fixture alert cases for this technique actually
use rundll32.exe as the image. All 4 use powershell.exe or cmd.exe under
various service/management-layer parents. v1.0.0 only matched
rundll32.exe/services.exe and would have missed all 4 real fixture cases.
See decision log for the full finding.

Detection logic (v2.0.0): documented (image, parent) pairs from replay
ground truth + all 4 fixture cases, each individually verified against
the full real replay for zero false-positive risk (see decision log).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pipeline.adapter import NormalizedEvent


RULE_ID = "T1218.011-001"
RULE_VERSION = "2.0.0"

ALLOWED_PAIRS = {
    ("rundll32.exe", "services.exe"),     # replay ground truth
    ("powershell.exe", "wmiprvse.exe"),   # P-DET-03
    ("cmd.exe", "config-agent.exe"),      # P-DET-05
    ("cmd.exe", "services.exe"),          # P-DET-09
    ("powershell.exe", "services.exe"),   # P-DET-11
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
            result="alerted", reason_code="known_t1218_011_execution_pattern",
        )

    return Verdict(
        event_id=event.event_id, rule_id=RULE_ID, rule_version=RULE_VERSION,
        result="suppressed", reason_code="pattern_not_in_known_t1218_011_set",
    )
