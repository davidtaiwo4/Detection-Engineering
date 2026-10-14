"""
cli.py — deterministic regression runner.

Usage:
    python -m pipeline.cli run --input raw-events/windows-replay.jsonl

Loads the replay, runs every registered rule against every event, and
prints verdicts sorted by event_id (sort order is what makes two runs
produce identical output — dict/set iteration order is not trustworthy
across runs otherwise). Also prints a sha256 result hash of the full
verdict set, so two clean runs can be diffed by hash alone.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

from pipeline.adapter import load_normalized
from pipeline.rules import (
    t1059_001, t1105, t1547_001, t1059_003, t1218_011, t1003_001,
    t1053_005, t1087_001, t1057, t1136_001, t1555, t1027,
)

# Registry of active rules — all 12 technique-matrix rows.
# Correlation/sequence rules (>= 6 required by brief.md): t1053_005,
# t1087_001, t1057 (v2.0.0, retrofitted), t1136_001, t1555, t1027 = 6.
RULES = [
    t1059_001, t1105, t1547_001, t1059_003, t1218_011, t1003_001,
    t1053_005, t1087_001, t1057, t1136_001, t1555, t1027,
]


def run(input_path: str) -> list[dict]:
    events, _ground_truth = load_normalized(input_path)  # ground truth NOT passed to rules

    verdicts = []
    for event in events:
        for rule_module in RULES:
            try:
                v = rule_module.evaluate(event, events)
            except TypeError:
                v = rule_module.evaluate(event)
            if v is not None:
                verdicts.append({
                    "event_id": v.event_id,
                    "rule_id": v.rule_id,
                    "result": v.result,
                    "reason_code": v.reason_code
                })
    return verdicts


def result_hash(verdicts: list[dict]) -> str:
    canonical = json.dumps(verdicts, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Stage 8 deterministic regression runner")
    parser.add_argument("command", choices=["run"])
    parser.add_argument("--input", required=True, help="Path to windows-replay.jsonl")
    parser.add_argument("--out", help="Optional path to write verdicts as JSON")
    args = parser.parse_args()

    verdicts = run(args.input)
    h = result_hash(verdicts)

    print(f"events evaluated -> {len(verdicts)} verdicts produced")
    print(f"result_hash: {h}")

    counts = {}
    for v in verdicts:
        counts[v["result"]] = counts.get(v["result"], 0) + 1
    for result, count in sorted(counts.items()):
        print(f"  {result}: {count}")

    if args.out:
        with open(args.out, "w") as f:
            json.dump({"result_hash": h, "verdicts": verdicts}, f, indent=2)
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
