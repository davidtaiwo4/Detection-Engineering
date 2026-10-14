"""
rules/t1057.py — Process Discovery (T1057)

RETROFITTED to a correlation rule — see decision log for why. Original
version (v1.0.0) alerted on a single tasklist.exe/wmic.exe call under a
scripting host. That's too weak a signal on its own: a lone tasklist.exe
invocation is extremely common (routine troubleshooting) and, separately,
this rule needed to become one of the required correlation/sequence
rules — no replay-covered technique had genuine correlated telemetry to
retrofit safely, so this self-constructed, fixture-only rule was the
correct place to fix the shortfall rather than any replay-validated rule.

Detection logic (v2.0.0): 2+ occurrences of a discovery binary
(tasklist.exe, wmic.exe — same or different) under the SAME parent
process, within a 5-minute window. A single occurrence alone does not
alert — this matches real behavior: one tasklist.exe call is routine,
repeated enumeration calls in quick succession is the actual recon signal.

No genuine process-discovery telemetry exists anywhere in the sealed
replay. The 9 public "T1057" benign fixtures (public-fixtures.json,
P-DET-13/20/22/23/24/26/28/31/36) don't contain tasklist.exe/wmic.exe at
all — see fixtures/synthetic/t1057.jsonl for the actual boundary test.

Known blind spot: wmic.exe is heavily overloaded (inventory, patching,
disk management, not just process listing); command_line is unusable per
the brief's own scrubbing, so this rule can't disambiguate wmic sub-
commands. Accepted trade-off, same as v1.0.0.

Excluded from detection input: command_line, command_family,
mitre_technique, marker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pipeline.adapter import NormalizedEvent
from pipeline.sequence import find_correlated_event


RULE_ID = "T1057-001"
RULE_VERSION = "2.0.0"

DISCOVERY_BINARIES = {"tasklist.exe", "wmic.exe"}
SCRIPTING_HOST_PARENTS = {"powershell.exe", "cmd.exe"}
BURST_WINDOW_MINUTES = 5


@dataclass(frozen=True)
class Verdict:
    event_id: str
    rule_id: str
    rule_version: str
    result: str
    reason_code: str
    correlated_event_id: Optional[str] = None


def evaluate(event: NormalizedEvent, all_events: list[NormalizedEvent]) -> Optional[Verdict]:
    if event.event_code != 1:
        return None

    image = event.image.strip().lower()
    parent = event.parent_image.strip().lower()

    if image not in DISCOVERY_BINARIES:
        return None  # not in scope for this rule

    if parent not in SCRIPTING_HOST_PARENTS:
        return Verdict(
            event_id=event.event_id,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            result="suppressed",
            reason_code="discovery_binary_parent_not_scripting_host",
        )

    def is_repeat_discovery_call_same_parent(candidate: NormalizedEvent) -> bool:
        c_image = candidate.image.strip().lower()
        c_parent = candidate.parent_image.strip().lower()
        return c_image in DISCOVERY_BINARIES and c_parent == parent

    correlated = find_correlated_event(
        anchor=event,
        all_events=all_events,
        predicate=is_repeat_discovery_call_same_parent,
        window_minutes=BURST_WINDOW_MINUTES,
        after_only=False,
    )

    if correlated is not None:
        return Verdict(
            event_id=event.event_id,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            result="alerted",
            reason_code="repeated_discovery_binary_calls_same_parent",
            correlated_event_id=correlated.event_id,
        )

    return Verdict(
        event_id=event.event_id,
        rule_id=RULE_ID,
        rule_version=RULE_VERSION,
        result="suppressed",
        reason_code="single_discovery_call_no_repeat",
    )
