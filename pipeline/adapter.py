"""
adapter.py — versioned event adapter for the Stage 8 portable pipeline.

Reads the immutable signed replay (windows-replay.jsonl) and converts each
raw line into a NormalizedEvent that detection rules operate on.

Design rule (see decision-log.md D-005): `marker` and `mitre_technique` are
answer-key fields that never exist on real telemetry. They are extracted into
a *separate* GroundTruth structure used only by our own validation tests —
never attached to, or readable from, NormalizedEvent. This makes it
structurally impossible for a rule to accidentally key off them.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from typing import Iterator, Optional


# Fields intentionally excluded from NormalizedEvent — see module docstring.
GROUND_TRUTH_ONLY_FIELDS = {"marker", "mitre_technique"}


@dataclass(frozen=True)
class NormalizedEvent:
    event_id: str
    timestamp: str
    channel: str
    event_code: int
    computer: str
    user: str
    image: str
    parent_image: str
    command_line: str          # retained for evidence/citation only — rules
                                # must not match on this (it's tokenized/
                                # scrubbed and unusable for matching anyway).
    schema_version: str
    source_line_hash: str      # sha256 of the raw JSON line, for provenance


@dataclass(frozen=True)
class GroundTruth:
    """Validation-only. Never passed to rule evaluation."""
    event_id: str
    marker: Optional[str]
    mitre_technique: Optional[str]


def _hash_line(raw_line: str) -> str:
    return hashlib.sha256(raw_line.encode("utf-8")).hexdigest()


def load_raw_lines(path: str) -> Iterator[tuple[str, dict]]:
    """Yields (raw_line_text, parsed_dict) for every line in the replay."""
    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            raw_line = raw_line.rstrip("\n")
            if not raw_line:
                continue
            yield raw_line, json.loads(raw_line)


def normalize(raw_line: str, raw: dict) -> tuple[NormalizedEvent, Optional[GroundTruth]]:
    """
    Converts one raw record into (NormalizedEvent, GroundTruth|None).

    Schema-version aware by design even though, per decision-log D-004/D-002,
    schema_version 1/2/3 in this particular replay do not actually change the
    field set. Future/hidden fixtures may differ, so we branch on version
    explicitly rather than assuming a fixed shape.
    """
    version = str(raw.get("schema_version", "1"))

    # All three observed versions share the same field names in this replay.
    # If a future version renames fields, add a branch here (COALESCE-style,
    # per the Stage 6 lesson) rather than assuming the v1 shape everywhere.
    if version in {"1", "2", "3"}:
        event = NormalizedEvent(
            event_id=raw["event_id"],
            timestamp=raw["timestamp"],
            channel=raw["channel"],
            event_code=int(raw["event_code"]),
            computer=raw["computer"],
            user=raw["user"],
            image=raw["image"],
            parent_image=raw["parent_image"],
            command_line=raw.get("command_line", ""),
            schema_version=version,
            source_line_hash=_hash_line(raw_line),
        )
    else:
        raise ValueError(f"Unrecognized schema_version: {version!r} on event {raw.get('event_id')}")

    ground_truth = None
    if GROUND_TRUTH_ONLY_FIELDS & raw.keys():
        ground_truth = GroundTruth(
            event_id=raw["event_id"],
            marker=raw.get("marker"),
            mitre_technique=raw.get("mitre_technique"),
        )

    return event, ground_truth


def load_normalized(path: str) -> tuple[list[NormalizedEvent], dict[str, GroundTruth]]:
    """
    Loads and normalizes the full replay.

    Returns (events, ground_truth_by_event_id). ground_truth_by_event_id is
    for test/validation code only — do not pass it into rule evaluation.
    """
    events: list[NormalizedEvent] = []
    ground_truth: dict[str, GroundTruth] = {}

    for raw_line, raw in load_raw_lines(path):
        event, gt = normalize(raw_line, raw)
        events.append(event)
        if gt is not None:
            ground_truth[event.event_id] = gt

    return events, ground_truth


def normalize_fixture_event(raw: dict, event_id_override: str = None) -> NormalizedEvent:
    """
    Lenient normalizer for public-fixtures.json's thinner schema (no
    timestamp/computer/user fields — see decision log finding). Distinct
    from normalize(), which is strict about the full replay schema.

    Raises ValueError (caller should treat this as parse_failure) if any
    of the fields this pipeline actually depends on for detection logic
    are missing: image, parent_image, event_code. Other fields get
    placeholder defaults since no rule reads them for fixture-sourced data.
    """
    required = ("image", "parent_image", "event_code")
    missing = [f for f in required if f not in raw]
    if missing:
        raise ValueError(f"fixture event missing required field(s): {missing}")

    return NormalizedEvent(
        event_id=str(event_id_override if event_id_override is not None else raw.get("event_id", "unknown")),
        timestamp="1970-01-01T00:00:00Z",
        channel=raw.get("channel", ""),
        event_code=int(raw["event_code"]),
        computer="fixture-host",
        user="unknown",
        image=raw["image"],
        parent_image=raw["parent_image"],
        command_line="",
        schema_version="fixture",
        source_line_hash="n/a",
    )


class FixtureParseError(Exception):
    """Raised when a public-fixtures.json case is missing required fields."""
    pass


def normalize_fixture_case(case: dict) -> list[NormalizedEvent]:
    """
    Normalizes one public-fixtures.json case (thin schema: image,
    parent_image, event_code, channel, no timestamp/computer/user) into
    NormalizedEvents usable by any rule, including correlation rules.

    Design: each case gets a synthetic `computer` equal to its case_id, so
    correlation rules (same_host_only=True) only ever correlate events
    within that one case, never across cases. Timestamps are reconstructed
    from the fixture's own `delta_seconds` field relative to an arbitrary
    but fixed base time, preserving real relative ordering/spacing so
    time-window correlation logic behaves correctly against fixture data,
    not just against the real replay.

    Raises FixtureParseError (not a bare KeyError) if a required field is
    missing — this is what lets the harness classify a case as
    `parse_failure` distinctly from `rule_miss`.
    """
    base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    case_id = case.get("case_id", "UNKNOWN")
    events: list[NormalizedEvent] = []

    for raw_event in case.get("events", []):
        try:
            delta = raw_event.get("delta_seconds", 0)
            ts = base_time + timedelta(seconds=delta)
            event = NormalizedEvent(
                event_id=f"{case_id}-{raw_event['event_id']}",
                timestamp=ts.isoformat().replace("+00:00", "Z"),
                channel=raw_event["channel"],
                event_code=int(raw_event["event_code"]),
                computer=case_id,
                user="fixture-user",
                image=raw_event["image"],
                parent_image=raw_event["parent_image"],
                command_line="",
                schema_version="fixture",
                source_line_hash="n/a",
            )
        except KeyError as e:
            raise FixtureParseError(f"case {case_id}: missing required field {e}") from e
        events.append(event)

    return events


if __name__ == "__main__":
    import sys
    import os

    path = sys.argv[1] if len(sys.argv) > 1 else "raw-events/windows-replay.jsonl"
    if not os.path.exists(path):
        print(f"error: {path} not found", file=sys.stderr)
        sys.exit(1)

    events, gt = load_normalized(path)
    print(f"loaded {len(events)} normalized events")
    print(f"ground-truth-labeled events (validation-only, {len(gt)} total):")
    for eid, g in list(gt.items())[:3]:
        print(f"  {eid}: technique={g.mitre_technique} marker={g.marker}")
