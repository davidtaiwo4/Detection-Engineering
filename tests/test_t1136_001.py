"""Validates T1136.001 against the synthetic fixture."""
 
import os
import sys
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from pipeline.adapter import load_normalized
from pipeline.rules import t1136_001
 
 
FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "synthetic", "t1136_001.jsonl")
 
 
def test_create_then_privilege_pattern_alerts():
    events, _ = load_normalized(FIXTURE_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1136001-00001")
    v = t1136_001.evaluate(anchor, events)
    assert v is not None
    assert v.result == "alerted"
    assert v.correlated_event_id == "SYN-T1136001-00002"
 
 
def test_single_net_call_is_suppressed():
    events, _ = load_normalized(FIXTURE_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1136001-00003")
    v = t1136_001.evaluate(anchor, events)
    assert v is not None
    assert v.result == "suppressed"
 
 
def test_trusted_provisioning_tool_is_suppressed_despite_repeat():
    events, _ = load_normalized(FIXTURE_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1136001-00004")
    v = t1136_001.evaluate(anchor, events)
    assert v is not None
    assert v.result == "suppressed", (
        "two net.exe calls under a trusted provisioning tool must be "
        "suppressed based on parent context, even though a repeat exists"
    )
