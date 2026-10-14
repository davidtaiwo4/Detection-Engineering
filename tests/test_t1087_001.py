"""
Validates T1087.001 burst-correlation rule against the synthetic fixture.
Checks: burst alerts, single-call suppressed, out-of-window pair suppressed.
"""
 
import os
import sys
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from pipeline.adapter import load_normalized
from pipeline.rules import t1087_001
 
 
FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "fixtures", "synthetic", "t1087_001.jsonl"
)
 
 
def test_discovery_burst_alerts():
    events, _ = load_normalized(FIXTURE_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1087001-00001")
    v = t1087_001.evaluate(anchor, events)
    assert v is not None
    assert v.result == "alerted"
 
 
def test_single_discovery_call_is_suppressed():
    events, _ = load_normalized(FIXTURE_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1087001-00004")
    v = t1087_001.evaluate(anchor, events)
    assert v is not None
    assert v.result == "suppressed"
 
 
def test_out_of_window_pair_is_suppressed_not_alerted():
    events, _ = load_normalized(FIXTURE_PATH)
    for eid in ("SYN-T1087001-00005", "SYN-T1087001-00006"):
        anchor = next(e for e in events if e.event_id == eid)
        v = t1087_001.evaluate(anchor, events)
        assert v is not None
        assert v.result == "suppressed", (
            f"{eid}: same parent but 8 hours apart must not be treated as a burst"
        )
