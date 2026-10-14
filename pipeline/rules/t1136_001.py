"""
rules/t1136_001.py — Create Account: Local Account (T1136.001)

No source telemetry exists in the sealed replay. Built against the
documented ATT&CK procedure and tested against a self-constructed
synthetic fixture.

Why this is a correlation rule, not single-event: net.exe/net1.exe is
heavily overloaded (net user, net localgroup, net use, net view, net
time, net share...) and command_line is unusable in this schema, so a
single net.exe call under a scripting host is genuinely ambiguous — it
could be T1087.001-style discovery, ordinary drive mapping, or account
creation. What IS distinguishing is the real-world T1136.001 procedure
shape: create the account, THEN immediately add it to a privileged group
— two net.exe/net1.exe invocations in quick succession under the same
parent. A single net.exe call does not alert.

Deliberate overlap with rules/t1087_001.py, documented rather than
hidden: both rules can fire on the same net.exe event if it's followed
by BOTH a different discovery binary (whoami.exe etc, triggering
T1087.001) AND a second net.exe call (triggering this rule). That's
realistic — a single recon/setup session can legitimately trip more
than one detection, and a SOC analyst would want both signals, not one
rule suppressing in favor of the other.

Detection logic: anchor = net.exe or net1.exe under powershell.exe or
cmd.exe. Correlated = another net.exe/net1.exe event, same parent, within
2 minutes (either direction — creation and group-add order isn't fixed
in all documented variants).

Benign lookalike: two net.exe calls under a trusted provisioning parent
(e.g. an automated onboarding tool) rather than a scripting host ->
suppressed based on parent context, same pattern as prior rules.

Known blind spot: a single net.exe call performing account creation with
NO follow-up group-add (e.g. a low-privilege backdoor account, never
escalated) evades this rule entirely by design.

Excluded from detection input: command_line, command_family,
mitre_technique, marker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pipeline.adapter import NormalizedEvent
from pipeline.sequence import find_correlated_event


RULE_ID = "T1136.001-001"
RULE_VERSION = "1.0.0"

ACCOUNT_BINARIES = {"net.exe", "net1.exe"}
CREATION_PARENTS = {"powershell.exe", "cmd.exe"}
CORRELATION_WINDOW_MINUTES = 2


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

    if image not in ACCOUNT_BINARIES:
        return None  # not in scope for this rule

    if parent not in CREATION_PARENTS:
        return Verdict(
            event_id=event.event_id,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            result="suppressed",
            reason_code="account_binary_parent_not_scripting_host",
        )

    def is_second_account_call_same_parent(candidate: NormalizedEvent) -> bool:
        c_image = candidate.image.strip().lower()
        c_parent = candidate.parent_image.strip().lower()
        return c_image in ACCOUNT_BINARIES and c_parent == parent

    correlated = find_correlated_event(
        anchor=event,
        all_events=all_events,
        predicate=is_second_account_call_same_parent,
        window_minutes=CORRELATION_WINDOW_MINUTES,
        after_only=False,
    )

    if correlated is not None:
        return Verdict(
            event_id=event.event_id,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            result="alerted",
            reason_code="account_create_and_privilege_pattern",
            correlated_event_id=correlated.event_id,
        )

    return Verdict(
        event_id=event.event_id,
        rule_id=RULE_ID,
        rule_version=RULE_VERSION,
        result="suppressed",
        reason_code="single_account_call_no_followup",
    )
