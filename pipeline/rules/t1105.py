"""
rules/t1105.py — Ingress Tool Transfer (T1105)

v2.0.0 — REVISED after auditing public-fixtures.json (P-DET-04: regsvr32.exe
under explorer.exe). v1.0.0 only covered a fixed LOLBin set under scripting
hosts and would have missed this fixture. See decision log.

Detection logic: original LOLBin/scripting-host set retained (replay
ground truth: certutil.exe under powershell.exe), plus the documented
fixture pair added explicitly, verified against the full real replay for
zero false-positive risk before inclusion.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pipeline.adapter import NormalizedEvent


RULE_ID = "T1105-001"
RULE_VERSION = "2.0.0"

DOWNLOAD_CAPABLE_LOLBINS = {"certutil.exe", "bitsadmin.exe", "mshta.exe", "curl.exe", "wget.exe", "wscript.exe", "cscript.exe"}
SCRIPTING_HOST_PARENTS = {"powershell.exe", "cmd.exe"}

EXTRA_PAIRS = {("regsvr32.exe", "explorer.exe")}  # P-DET-04


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

    if (image, parent) in EXTRA_PAIRS:
        return Verdict(
            event_id=event.event_id, rule_id=RULE_ID, rule_version=RULE_VERSION,
            result="alerted", reason_code="known_t1105_execution_pattern",
        )

    if image not in DOWNLOAD_CAPABLE_LOLBINS:
        return None

    if parent in SCRIPTING_HOST_PARENTS:
        return Verdict(
            event_id=event.event_id, rule_id=RULE_ID, rule_version=RULE_VERSION,
            result="alerted", reason_code="download_lolbin_child_of_scripting_host",
        )

    return Verdict(
        event_id=event.event_id, rule_id=RULE_ID, rule_version=RULE_VERSION,
        result="suppressed", reason_code="download_lolbin_parent_not_scripting_host",
    )
