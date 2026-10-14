"""Validates T1555 against the synthetic fixture."""
 
import os
import sys
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from pipeline.adapter import load_normalized
from pipeline.rules import t1555
 
 
FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "synthetic", "t1555.jsonl")
 
 
def test_enumerate_then_extract_pattern_alerts():
    events, _ = load_normalized(FIXTURE_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1555-00001")
    v = t1555.evaluate(anchor, events)
    assert v is not None
    assert v.result == "alerted"
    assert v.correlated_event_id == "SYN-T1555-00002"
 
 
def test_single_interactive_call_is_suppressed():
    events, _ = load_normalized(FIXTURE_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1555-00003")
    v = t1555.evaluate(anchor, events)
    assert v is not None
    assert v.result == "suppressed"
