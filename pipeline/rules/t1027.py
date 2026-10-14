"""
rules/t1027.py — Obfuscated Files or Information (T1027)

No source telemetry exists in the sealed replay. Built against the
documented ATT&CK procedure and tested against a self-constructed
synthetic fixture.

Why content-based detection isn't possible here: T1027 is fundamentally
about the OBFUSCATED CONTENT of a payload (base64, XOR, packing), which
requires reading command-line or script content — precisely what this
schema deliberately scrubs (see decision log D-005 and every prior
rule's docstring). A rule that could read command_line would be capped
under the brief's prohibition on literal-command matching anyway.

Structural proxy instead: obfuscated droppers delivered via a script
host (wscript.exe/cscript.exe — commonly used for obfuscated JS/VBS
loaders) typically unpack and hand off execution to a second
interpreter shortly after starting. Ordinary legitimate login/logon
scripts run and exit; they don't commonly spawn a shell as a child
process. This rule detects that spawn-chain shape rather than payload
content — a real, if imperfect, structural signal.

Detection logic: anchor = wscript.exe or cscript.exe (any parent —
legitimate uses of these hosts vary too widely to restrict by parent
alone). Correlated = a process with parent_image matching the anchor's
OWN image (i.e., the script host itself spawns a child), specifically
powershell.exe or cmd.exe as that child, within 2 minutes.

Benign lookalike: wscript.exe/cscript.exe running standalone with no
child spawn (an ordinary VBS/JS script that does its job and exits) ->
suppressed.

Known blind spot, worth stating plainly: this is the weakest-evidenced
rule in the set. It cannot detect obfuscation in payloads delivered via
means other than a wscript/cscript spawn chain (e.g. obfuscated
PowerShell run directly, without a script-host precursor) — that case
would need command_line visibility this schema doesn't provide.

Excluded from detection input: command_line, command_family,
mitre_technique, marker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pipeline.adapter import NormalizedEvent
from pipeline.sequence import find_correlated_event


RULE_ID = "T1027-001"
RULE_VERSION = "1.0.0"

SCRIPT_HOSTS = {"wscript.exe", "cscript.exe"}
SPAWNED_INTERPRETERS = {"powershell.exe", "cmd.exe"}
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

    if image not in SCRIPT_HOSTS:
        return None  # not in scope for this rule

    def is_child_interpreter_spawn(candidate: NormalizedEvent) -> bool:
        c_image = candidate.image.strip().lower()
        c_parent = candidate.parent_image.strip().lower()
        return c_image in SPAWNED_INTERPRETERS and c_parent == image

    correlated = find_correlated_event(
        anchor=event,
        all_events=all_events,
        predicate=is_child_interpreter_spawn,
        window_minutes=CORRELATION_WINDOW_MINUTES,
        after_only=True,  # the spawn must follow the script host starting
    )

    if correlated is not None:
        return Verdict(
            event_id=event.event_id,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            result="alerted",
            reason_code="script_host_spawned_secondary_interpreter",
            correlated_event_id=correlated.event_id,
        )

    return Verdict(
        event_id=event.event_id,
        rule_id=RULE_ID,
        rule_version=RULE_VERSION,
        result="suppressed",
        reason_code="script_host_no_child_interpreter_spawn",
    )
