"""
rules/t1053_005.py — Scheduled Task/Job: Scheduled Task (T1053.005)

No source telemetry for this technique exists in the sealed replay (see
decision-log: 6 of 12 rows have zero embedded evidence). This rule is
designed against the documented ATT&CK T1053.005 procedure (schtasks.exe
task creation, followed by Task Scheduler later launching the configured
target program) and tested against a self-constructed synthetic fixture —
NOT the sealed replay. See fixtures/synthetic/t1053_005.jsonl and its
PROVENANCE.md for full construction methodology and honesty about its
non-replay origin.

Detection logic (genuine two-event correlation, not a disguised
single-event rule):
  1. Anchor: schtasks.exe /create spawned as a direct child of powershell.exe
     or cmd.exe (scripted/automated task creation, as opposed to GUI Task
     Scheduler use or a trusted installer).
  2. Correlated event: within 5 minutes AFTER the anchor, on the same host,
     a process launches with parent_image == "svchost.exe" (modern Windows
     Task Scheduler execution context — see design note below).

Both steps must be present for an alert. The anchor alone (schtasks
creation from a scripting host) is NOT sufficient — legitimate admin
scripting could create a task that's later cancelled or never fires, and
alerting on creation alone would be a weaker, less-evidenced claim than
what the full sequence supports.

Design note on step 2's parent process: Task Scheduler on modern Windows
(post-Windows 8) hosts scheduled task execution via the Schedule service
running under svchost.exe, not the legacy taskeng.exe. This is a
documented, defensible choice, not an arbitrary one — see decision-log.

Benign lookalike: schtasks.exe /create spawned by msiexec.exe (a trusted
installer registering a legitimate update-check task, e.g. software
auto-updaters) does not match the anchor condition (parent is msiexec.exe,
not powershell.exe/cmd.exe) and is correctly never flagged, regardless of
what executes later.

Known blind spot: an attacker using the Task Scheduler COM API directly
(no schtasks.exe process at all) would evade the anchor condition entirely.
This rule only covers the schtasks.exe-mediated creation path.

Excluded from detection input: command_line, command_family,
mitre_technique, marker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pipeline.adapter import NormalizedEvent
from pipeline.sequence import find_correlated_event


RULE_ID = "T1053.005-001"
RULE_VERSION = "1.0.0"

CREATION_PARENTS = {"powershell.exe", "cmd.exe"}
EXECUTION_WINDOW_MINUTES = 5


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

    if image != "schtasks.exe":
        return None  # not in scope for this rule

    if parent not in CREATION_PARENTS:
        return Verdict(
            event_id=event.event_id,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            result="suppressed",
            reason_code="schtasks_parent_not_scripting_host",
        )

    def is_scheduler_execution(candidate: NormalizedEvent) -> bool:
        return candidate.parent_image.strip().lower() == "svchost.exe"

    correlated = find_correlated_event(
        anchor=event,
        all_events=all_events,
        predicate=is_scheduler_execution,
        window_minutes=EXECUTION_WINDOW_MINUTES,
    )

    if correlated is not None:
        return Verdict(
            event_id=event.event_id,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            result="alerted",
            reason_code="schtasks_creation_followed_by_scheduler_execution",
            correlated_event_id=correlated.event_id,
        )

    return Verdict(
        event_id=event.event_id,
        rule_id=RULE_ID,
        rule_version=RULE_VERSION,
        result="rule_miss",
        reason_code="schtasks_creation_seen_but_no_correlated_execution_in_window",
    )
