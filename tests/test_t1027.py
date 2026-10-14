"""Validates T1027 against the synthetic fixture."""
 
import os
import sys
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from pipeline.adapter import load_normalized
from pipeline.rules import t1027
 
 
FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "synthetic", "t1027.jsonl")
 
 
def test_script_host_spawns_interpreter_alerts():
    events, _ = load_normalized(FIXTURE_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1027-00001")
    v = t1027.evaluate(anchor, events)
    assert v is not None
    assert v.result == "alerted"
    assert v.correlated_event_id == "SYN-T1027-00002"
 
 
def test_standalone_script_host_no_spawn_is_suppressed():
    events, _ = load_normalized(FIXTURE_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1027-00003")
    v = t1027.evaluate(anchor, events)
    assert v is not None
    assert v.result == "suppressed"
