"""
Validates T1053.005 rule against the self-constructed synthetic fixture
(fixtures/synthetic/t1053_005.jsonl) — NOT the sealed replay, since no
T1053.005 telemetry exists there. See the fixture's PROVENANCE.md.
 
Checks all three branches: true positive (creation + correlated execution),
true negative / benign lookalike (creation from a trusted installer, must
suppress regardless of downstream execution), and incomplete sequence
(creation with no correlated execution -> rule_miss, not alerted).
"""
 
import os
import sys
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from pipeline.adapter import load_normalized
from pipeline.rules import t1053_005
 
 
FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "fixtures", "synthetic", "t1053_005.jsonl"
)
 
 
def test_true_positive_creation_plus_correlated_execution_alerts():
    events, _ = load_normalized(FIXTURE_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1053005-00001")
    v = t1053_005.evaluate(anchor, events)
    assert v is not None
    assert v.result == "alerted"
    assert v.correlated_event_id == "SYN-T1053005-00002"
 
 
def test_benign_installer_creation_is_suppressed_despite_downstream_execution():
    events, _ = load_normalized(FIXTURE_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1053005-00003")
    v = t1053_005.evaluate(anchor, events)
    assert v is not None
    assert v.result == "suppressed", (
        "benign installer-created task must be suppressed based on creation "
        "parent alone, even though a downstream svchost-parented execution "
        "exists nearby — proves the rule isn't just alerting on correlation presence"
    )
 
 
def test_incomplete_sequence_is_rule_miss_not_alerted():
    events, _ = load_normalized(FIXTURE_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1053005-00005")
    v = t1053_005.evaluate(anchor, events)
    assert v is not None
    assert v.result == "rule_miss"
    assert v.result != "alerted"
