"""
tools/build_coverage_matrix.py
 
Generates coverage-matrix.csv as a per-case source-normalized-alert triple
table (source locator, normalized fields, verdict)
 
Pulls from:
  - harness-report.json (generated, enriched per-case triples for
    all 36 public-fixtures.json cases)
  - fixtures/synthetic/*.jsonl (the 6 self-constructed technique fixtures),
    run individually through their matching rule
 
Deterministic: same inputs always produce the same output rows in the
same order (sorted by source_locator).
"""
 
from __future__ import annotations
 
import csv
import json
import sys
 
sys.path.insert(0, ".")
 
from pipeline.adapter import load_normalized
from pipeline.rules import t1053_005, t1087_001, t1057, t1136_001, t1555, t1027
 
SYNTHETIC_RULE_MAP = {
    "fixtures/synthetic/t1053_005.jsonl": ("T1053.005", t1053_005),
    "fixtures/synthetic/t1087_001.jsonl": ("T1087.001", t1087_001),
    "fixtures/synthetic/t1057.jsonl": ("T1057", t1057),
    "fixtures/synthetic/t1136_001.jsonl": ("T1136.001", t1136_001),
    "fixtures/synthetic/t1555.jsonl": ("T1555", t1555),
    "fixtures/synthetic/t1027.jsonl": ("T1027", t1027),
}
 
 
def rows_from_harness_report(path: str) -> list[dict]:
    with open(path) as f:
        report = json.load(f)
 
    rows = []
    for case in report["cases"]:
        for ev in case["normalized_events"]:
            rows.append({
                "source_locator": f"{case['source_locator']}#{ev['event_id']}",
                "technique_hint": "see fired_rules" if not case["fired_rules"] else case["fired_rules"][0].split("-")[0],
                "raw_channel": ev["channel"],
                "normalized_image": ev["image"],
                "normalized_parent_image": ev["parent_image"],
                "normalized_event_code": ev["event_code"],
                "expected": case["expected"],
                "actual_classification": case["classification"],
                "fired_rule_ids": ";".join(case["fired_rules"]),
                "evidence_artifact": "harness-report.json",
            })
    return rows
 
 
def rows_from_synthetic_fixtures() -> list[dict]:
    rows = []
    for path, (technique_id, rule_module) in SYNTHETIC_RULE_MAP.items():
        events, _ = load_normalized(path)
        for event in events:
            v = rule_module.evaluate(event, events)
            classification = v.result if v is not None else "not_in_scope"
            rows.append({
                "source_locator": f"{path}#{event.event_id}",
                "technique_hint": technique_id,
                "raw_channel": event.channel,
                "normalized_image": event.image,
                "normalized_parent_image": event.parent_image,
                "normalized_event_code": event.event_code,
                "expected": "n/a -- see fixtures/synthetic/PROVENANCE.md for per-case expected outcome",
                "actual_classification": classification,
                "fired_rule_ids": v.rule_id if (v is not None and v.result == "alerted") else "",
                "evidence_artifact": path,
            })
    return rows
 
 
def main():
    rows = rows_from_harness_report("harness-report.json") + rows_from_synthetic_fixtures()
    rows.sort(key=lambda r: r["source_locator"])
 
    fieldnames = [
        "source_locator", "technique_hint", "raw_channel",
        "normalized_image", "normalized_parent_image", "normalized_event_code",
        "expected", "actual_classification", "fired_rule_ids", "evidence_artifact",
    ]
 
    with open("coverage-matrix.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
 
    print(f"wrote coverage-matrix.csv with {len(rows)} per-case triple rows")
 
 
if __name__ == "__main__":
    main()
