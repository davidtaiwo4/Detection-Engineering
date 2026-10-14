"""
rules/t1547_001.py — Boot or Logon Autostart Execution: Registry Run Keys (T1547.001)

Detection logic: reg.exe invoked as a direct child of cmd.exe. Real-world
persistence via Run/RunOnce keys is most commonly staged through reg.exe
(or PowerShell's registry provider, not covered by this rule) rather than
interactive regedit.exe use, and a cmd.exe parent is the common automation
pattern (batch scripts, macro-spawned shells) rather than an admin manually
opening a command prompt to edit autostart keys.

Data note (decision-log): checked +/-10min neighborhood for both T1547.001
ground-truth events on NS-WIN-101 — no correlated event exists (no process
matching a run-key target executing later, no cross-channel pairing).
Confirmed this same isolated-event pattern across all 6 replay-covered
techniques (T1059.001, T1105, T1547.001, T1059.003, T1218.011, T1003.001) —
this replay does not contain genuine multi-event attack chains for any
embedded technique. The six required correlation/sequence rules will come
from the six self-constructed technique fixtures instead (see coverage
notes), not from replay-covered techniques.

Excluded from detection input: command_line, command_family,
mitre_technique, marker — same reasoning as prior rules.

Known blind spot: reg.exe is only one of several ways to write a Run key
(PowerShell's New-ItemProperty, direct registry API calls via a compiled
binary, etc.) — this rule only covers the reg.exe-mediated path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pipeline.adapter import NormalizedEvent


RULE_ID = "T1547.001-001"
RULE_VERSION = "1.0.0"


@dataclass(frozen=True)
class Verdict:
    event_id: str
    rule_id: str
    rule_version: str
    result: str
    reason_code: str


def evaluate(event: NormalizedEvent) -> Optional[Verdict]:
    if event.event_code != 1:
        return None

    image = event.image.strip().lower()
    parent = event.parent_image.strip().lower()

    if image != "reg.exe":
        return None  # not in scope for this rule

    if parent == "cmd.exe":
        return Verdict(
            event_id=event.event_id,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            result="alerted",
            reason_code="reg_exe_child_of_cmd",
        )

    return Verdict(
        event_id=event.event_id,
        rule_id=RULE_ID,
        rule_version=RULE_VERSION,
        result="suppressed",
        reason_code="reg_exe_parent_not_cmd",
    )
