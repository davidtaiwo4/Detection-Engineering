"""
harness.py Implements the required 6-state verdict taxonomy:
    no_telemetry    — case has no process-creation (event_code=1) event at all
    parse_failure   — a sysmon event exists but is missing a required field
                       (image/parent_image/event_code/channel) and cannot be
                       normalized
    rule_miss       — expected "alert", but no rule alerted (false negative)
    suppressed      — expected "no_alert", and no rule alerted (correct)
    alerted         — expected "alert", and >=1 rule alerted (correct)
    unexpected_alert — expected "no_alert", but >=1 rule alerted (false positive)
 
Design notes:
  - Ground truth (case_id/expected) is read ONLY at the harness level, to
    score outcomes — never passed into rule evaluation itself, same
    separation principle as adapter.py's GroundTruth vs NormalizedEvent.
  - Each fixture case gets its own synthetic "computer" (namespaced by
    case_id) so correlation rules never match across different fixture
    cases — cross-case contamination would be a real correctness bug,
    not just a cosmetic issue.
  - Uses each event's `delta_seconds` field (relative to a fixed base
    timestamp) to reconstruct real relative timing within a case, so
    sequence/correlation rules (t1053_005, t1087_001, t1057, t1136_001,
    t1555, t1027) work correctly against fixture data, not just the
    replay.
"""
 
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from pipeline.adapter import NormalizedEvent
from pipeline.rules import (
    t1059_001, t1105, t1547_001, t1059_003, t1218_011, t1003_001,
    t1053_005, t1087_001, t1057, t1136_001, t1555, t1027,
)

RULES = [
    t1059_001, t1105, t1547_001, t1059_003, t1218_011, t1003_001,
    t1053_005, t1087_001, t1057, t1136_001, t1555, t1027,
]

REQUIRED_FIELDS = ("event_code", "image", "parent_image", "channel")
BASE_TS = datetime(2026, 1, 1)


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    expected: str
    classification: str
    fired_rules: tuple  # rule_ids that alerted, empty if none
    detail: str
    source_locator: str  # where this case's raw record lives, for the FAQ's "triple"
    normalized_events: tuple  # tuple of dicts — intermediate normalized form


def _normalize_fixture_event(case_id: str, raw: dict) -> NormalizedEvent:
    """Raises KeyError/TypeError if a required field is missing/malformed —
    caller catches this and classifies as parse_failure."""
    for field in REQUIRED_FIELDS:
        if field not in raw:
            raise KeyError(f"missing required field '{field}'")

    delta = raw.get("delta_seconds", 0)
    ts = (BASE_TS + timedelta(seconds=float(delta))).isoformat() + "Z"

    return NormalizedEvent(
        event_id=f"{case_id}-{raw.get('event_id', 'unknown')}",
        timestamp=ts,
        channel=raw["channel"],
        event_code=int(raw["event_code"]),
        computer=f"FIXTURE-{case_id}",  # namespaced — never crosses case boundaries
        user="unknown",
        image=raw["image"],
        parent_image=raw["parent_image"],
        command_line="",
        schema_version="fixture",
        source_line_hash="n/a",
    )


def evaluate_case(case: dict) -> CaseResult:
    case_id = case["case_id"]
    expected = case["expected"]
    raw_events = case["events"]
    source_locator = f"public-fixtures.json#{case_id}"

    sysmon_raw = [e for e in raw_events if e.get("channel") == "sysmon"]
    if not sysmon_raw:
        return CaseResult(case_id, expected, "no_telemetry", (), "no sysmon event in fixture", source_locator, ())

    normalized_events = []
    parse_errors = []
    for raw in raw_events:
        try:
            normalized_events.append(_normalize_fixture_event(case_id, raw))
        except (KeyError, TypeError, ValueError) as e:
            parse_errors.append(str(e))

    normalized_export = tuple(
        {"event_id": e.event_id, "channel": e.channel, "event_code": e.event_code,
         "image": e.image, "parent_image": e.parent_image}
        for e in normalized_events
    )

    sysmon_normalized = [e for e in normalized_events if e.event_code == 1]
    if not sysmon_normalized:
        return CaseResult(case_id, expected, "parse_failure", (),
                           "; ".join(parse_errors) or "sysmon event present but failed to normalize",
                           source_locator, normalized_export)

    fired = []
    for event in sysmon_normalized:
        for rule_module in RULES:
            # Flexible exception handler hooks single-argument rules (like t1547_001) safely
            try:
                v = rule_module.evaluate(event, normalized_events)
            except TypeError:
                v = rule_module.evaluate(event)
            if v is not None and v.result == "alerted":
                fired.append(v.rule_id)

    fired = tuple(sorted(set(fired)))
    did_alert = len(fired) > 0

    if expected == "alert":
        classification = "alerted" if did_alert else "rule_miss"
    elif expected == "no_alert":
        classification = "unexpected_alert" if did_alert else "suppressed"
    else:
        raise ValueError(f"unrecognized expected value: {expected!r} for {case_id}")

    detail = f"fired={list(fired)}" if fired else "no rule alerted"
    return CaseResult(case_id, expected, classification, fired, detail, source_locator, normalized_export)


def run_harness(fixtures_path: str) -> list[CaseResult]:
    with open(fixtures_path) as f:
        data = json.load(f)

    results = [evaluate_case(case) for case in data["fixtures"]]
    results.sort(key=lambda r: r.case_id)  # deterministic order
    return results


def result_hash(results: list[CaseResult]) -> str:
    canonical = json.dumps(
        [[r.case_id, r.expected, r.classification, list(r.fired_rules)] for r in results],
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def write_junit_xml(results: list[CaseResult], path: str) -> None:
    passing_states = {"alerted", "suppressed"}
    failures = [r for r in results if r.classification not in passing_states]

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuite name="stage8_acceptance_harness" tests="{len(results)}" '
        f'failures="{len(failures)}" errors="0">',
    ]
    for r in results:
        lines.append(f'  <testcase name="{r.case_id}" classname="{r.expected}">')
        if r.classification not in passing_states:
            lines.append(
                f'    <failure message="expected={r.expected} '
                f'actual_classification={r.classification}">{r.detail}</failure>'
            )
        lines.append("  </testcase>")
    lines.append("</testsuite>")

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def write_json_report(results: list[CaseResult], h: str, path: str) -> None:
    report = {
        "result_hash": h,
        "total_cases": len(results),
        "counts": {},
        "cases": [
            {"case_id": r.case_id, "expected": r.expected, "classification": r.classification,
             "fired_rules": list(r.fired_rules), "detail": r.detail,
             "source_locator": r.source_locator,
             "normalized_events": list(r.normalized_events)}
            for r in results
        ],
    }
    for r in results:
        report["counts"][r.classification] = report["counts"].get(r.classification, 0) + 1

    with open(path, "w") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Stage 8 acceptance-test harness")
    parser.add_argument("--fixtures", required=True, help="Path to fixtures JSON (public-fixtures.json schema)")
    parser.add_argument("--junit-out", default="regression-results.xml")
    parser.add_argument("--json-out", default="harness-report.json")
    args = parser.parse_args()

    results = run_harness(args.fixtures)
    h = result_hash(results)

    write_junit_xml(results, args.junit_out)
    write_json_report(results, h, args.json_out)

    counts = {}
    for r in results:
        counts[r.classification] = counts.get(r.classification, 0) + 1

    print(f"{len(results)} cases evaluated, result_hash={h}")
    for k in sorted(counts):
        print(f"  {k}: {counts[k]}")
    print(f"wrote {args.junit_out}")
    print(f"wrote {args.json_out}")

    mismatches = [r for r in results if r.classification in ("rule_miss", "unexpected_alert", "parse_failure")]
    if mismatches:
        print(f"\n{len(mismatches)} verdict mismatch(es) — exiting non-zero per brief.md requirement")
        sys.exit(1)
    sys.exit(0)
