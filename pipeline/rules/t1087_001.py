"""
rules/t1087_001.py — Account Discovery: Local Account (T1087.001)

No source telemetry for this technique exists in the sealed replay. Built
against the documented ATT&CK procedure and tested against a
self-constructed synthetic fixture — see
fixtures/synthetic/t1087_001.PROVENANCE.md.

Why this is a burst rule, not a single-binary rule: command_line is
scrubbed in this schema, so `net.exe` alone can't be distinguished from
"net user" (discovery) vs. "net use" (mapping a drive) vs. "net time".
Alerting on image == "net.exe" alone would be far too noisy for real
deployment — that binary is common in ordinary admin scripting.

Detection logic: TWO OR MORE DIFFERENT discovery-capable binaries spawned
by the SAME parent process within a 3-minute window. A single discovery
binary call, alone, is never sufficient — it's the burst of multiple
distinct enumeration steps under one session that carries the signal,
matching how real recon behavior actually looks (enumerate accounts, then
groups, then host info, in quick succession).

Same parent_image (not just same host) is required for correlation, to
avoid conflating unrelated activity from different users/sessions on a
shared or jump-box-style machine.

Benign lookalike: a single net.exe call (e.g. legitimate drive mapping)
with no other discovery binary nearby under the same parent -> suppressed.
Two discovery-looking calls hours apart (routine, unrelated admin tasks)
-> outside the window, suppressed.

Known blind spot: an attacker using only ONE discovery binary (e.g. just
`net user` alone, no follow-up) evades this rule by design — the
burst threshold is a deliberate trade-off to keep noise down, and is
itself the honest limitation to name in the coverage matrix.

Excluded from detection input: command_line, command_family,
mitre_technique, marker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pipeline.adapter import NormalizedEvent
from pipeline.sequence import find_correlated_event


RULE_ID = "T1087.001-001"
RULE_VERSION = "1.0.0"

DISCOVERY_BINARIES = {"net.exe", "net1.exe", "whoami.exe", "systeminfo.exe", "nltest.exe", "quser.exe"}
BURST_WINDOW_MINUTES = 3


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
    if image not in DISCOVERY_BINARIES:
        return None  # not in scope for this rule

    anchor_parent = event.parent_image.strip().lower()

    def is_different_discovery_binary_same_parent(candidate: NormalizedEvent) -> bool:
        c_image = candidate.image.strip().lower()
        c_parent = candidate.parent_image.strip().lower()
        return (
            c_image in DISCOVERY_BINARIES
            and c_image != image
            and c_parent == anchor_parent
        )

    correlated = find_correlated_event(
        anchor=event,
        all_events=all_events,
        predicate=is_different_discovery_binary_same_parent,
        window_minutes=BURST_WINDOW_MINUTES,
        after_only=False,  # burst order isn't fixed — search both directions
    )

    if correlated is not None:
        return Verdict(
            event_id=event.event_id,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            result="alerted",
            reason_code="discovery_binary_burst_same_parent",
            correlated_event_id=correlated.event_id,
        )

    return Verdict(
        event_id=event.event_id,
        rule_id=RULE_ID,
        rule_version=RULE_VERSION,
        result="suppressed",
        reason_code="single_discovery_binary_no_burst",
    )
