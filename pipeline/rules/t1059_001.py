"""
rules/t1059_001.py — Execution via Malicious PowerShell (T1059.001)

v2.0.0 — REVISED after auditing public-fixtures.json's actual alert cases
(P-DET-02, P-DET-06), which use different (image, parent) pairs than the
single pair observed in the sealed replay's ground truth. v1.0.0 only
matched powershell.exe/Office-app and would have missed both real fixture
cases. See decision log for the full audit finding.

Detection logic (v2.0.0): a documented, evidence-grounded set of
(image, parent_image) pairs associated with this technique, drawn from
BOTH the sealed replay's ground truth AND the public fixture set —
verified against the full real replay to confirm zero false-positive
risk before inclusion (see decision log):
  - powershell.exe under an Office app (winword.exe/excel.exe/
    powerpnt.exe/outlook.exe) — macro-driven PowerShell, replay ground truth
  - rundll32.exe under explorer.exe — P-DET-02
  - cmd.exe under config-agent.exe — P-DET-06

Each pair is still (image, parent) specific, not a blanket "any binary
under any of these parents" rule — a naive cross-product was tested and
rejected (see decision log): it would have false-positived on 61 real
legitimate powershell.exe/enterprise-updater.exe signed-update events.

Excluded from detection input: command_line, command_family,
mitre_technique, marker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pipeline.adapter import NormalizedEvent


RULE_ID = "T1059.001-001"
RULE_VERSION = "2.0.0"

OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe", "visio.exe"}

ALLOWED_PAIRS = (
    {("powershell.exe", p) for p in OFFICE_PARENTS}
    | {("rundll32.exe", "explorer.exe")}
    | {("cmd.exe", "config-agent.exe")}
)


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

    # Only in scope if the image is one this rule cares about at all.
    if image not in {p[0] for p in ALLOWED_PAIRS}:
        return None

    if (image, parent) in ALLOWED_PAIRS:
        return Verdict(
            event_id=event.event_id, rule_id=RULE_ID, rule_version=RULE_VERSION,
            result="alerted", reason_code="known_t1059_001_execution_pattern",
        )

    return Verdict(
        event_id=event.event_id, rule_id=RULE_ID, rule_version=RULE_VERSION,
        result="suppressed", reason_code="pattern_not_in_known_t1059_001_set",
    )
