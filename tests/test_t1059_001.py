"""
Validates T1059.001 rule output against ground-truth labels, using the full
replay directly.

Ground truth (marker/mitre_technique) is loaded ONLY here, for assertion
purposes — never passed into adapter output or rule evaluation itself.
"""

import os
import sys
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from pipeline.adapter import load_normalized
from pipeline.rules import t1059_001
 
 
REPLAY_PATH = os.path.join(os.path.dirname(__file__), "..", "raw-events", "windows-replay.jsonl")
 
 
def test_rule_matches_ground_truth_exactly_on_full_replay():
    events, ground_truth = load_normalized(REPLAY_PATH)
 
    positive_ids = {eid for eid, g in ground_truth.items() if g.mitre_technique == "T1059.001"}
    assert positive_ids, "expected at least one T1059.001 ground-truth event in the replay"
 
    alerted_ids = set()
    for event in events:
        v = t1059_001.evaluate(event, events)
        if v is not None and v.result == "alerted":
            alerted_ids.add(event.event_id)
 
    assert alerted_ids == positive_ids, (
        f"mismatch — false positives: {alerted_ids - positive_ids}, "
        f"false negatives: {positive_ids - alerted_ids}"
    )
 
 
def test_two_runs_produce_identical_result_hash():
    from pipeline.cli import run, result_hash
 
    verdicts_a = run(REPLAY_PATH)
    verdicts_b = run(REPLAY_PATH)
 
    assert result_hash(verdicts_a) == result_hash(verdicts_b)
