"""
rules/t1555.py — Credentials from Password Stores (T1555)

No source telemetry exists in the sealed replay. Built against the
documented ATT&CK procedure and tested against a self-constructed
synthetic fixture.

Target binary: vaultcmd.exe — the native Windows Credential Manager CLI,
a documented LOLBAS tool for enumerating and reading stored credentials
(e.g. `vaultcmd /list`, then `vaultcmd /listcreds:<vault> /all` per
vault). This is a genuine, real two-step procedure pattern (enumerate
vaults, then extract each vault's credentials), which is why this is
built as a correlation rule rather than single-event: a single vaultcmd
call is lower-signal (could be one-off troubleshooting of a saved
credential), but two vaultcmd invocations in quick succession under the
same parent matches the documented enumerate-then-extract chain.

Detection logic: anchor = vaultcmd.exe under powershell.exe or cmd.exe.
Correlated = a second vaultcmd.exe event, same parent, within 3 minutes.

Benign lookalike: vaultcmd.exe under explorer.exe (interactive user
checking Credential Manager via the GUI's underlying process, or a
single manual troubleshooting invocation) -> suppressed by parent
context, same pattern as prior rules.

Known blind spot: this rule only covers the vaultcmd.exe-mediated path.
Browser-credential-store access (Chrome/Edge Login Data SQLite files) or
DPAPI-based extraction via other tooling would not involve vaultcmd.exe
at all and would evade this rule entirely — a real deployment would need
file-access telemetry (not present in this schema) to cover that path.

Excluded from detection input: command_line, command_family,
mitre_technique, marker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pipeline.adapter import NormalizedEvent
from pipeline.sequence import find_correlated_event


RULE_ID = "T1555-001"
RULE_VERSION = "1.0.0"

TARGET_BINARY = "vaultcmd.exe"
SCRIPTING_HOST_PARENTS = {"powershell.exe", "cmd.exe"}
CORRELATION_WINDOW_MINUTES = 3


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

    if image != TARGET_BINARY:
        return None  # not in scope for this rule

    if parent not in SCRIPTING_HOST_PARENTS:
        return Verdict(
            event_id=event.event_id,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            result="suppressed",
            reason_code="vaultcmd_parent_not_scripting_host",
        )

    def is_second_vaultcmd_call_same_parent(candidate: NormalizedEvent) -> bool:
        c_image = candidate.image.strip().lower()
        c_parent = candidate.parent_image.strip().lower()
        return c_image == TARGET_BINARY and c_parent == parent

    correlated = find_correlated_event(
        anchor=event,
        all_events=all_events,
        predicate=is_second_vaultcmd_call_same_parent,
        window_minutes=CORRELATION_WINDOW_MINUTES,
        after_only=False,
    )

    if correlated is not None:
        return Verdict(
            event_id=event.event_id,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            result="alerted",
            reason_code="vaultcmd_enumerate_then_extract_pattern",
            correlated_event_id=correlated.event_id,
        )

    return Verdict(
        event_id=event.event_id,
        rule_id=RULE_ID,
        rule_version=RULE_VERSION,
        result="suppressed",
        reason_code="single_vaultcmd_call_no_followup",
    )
