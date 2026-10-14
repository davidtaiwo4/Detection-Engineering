"""
Validates T1057 rule against the synthetic fixture (true boundary test),
plus a sanity check against the 9 real public "T1057" benign fixtures
"""
 
import json
import os
import sys
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from pipeline.adapter import load_normalized, NormalizedEvent
from pipeline.rules import t1057
 
 
SYNTHETIC_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "synthetic", "t1057.jsonl")
PUBLIC_FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "public-fixtures.json")
 
 
def test_repeated_calls_same_parent_alerts():
    events, _ = load_normalized(SYNTHETIC_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1057-00001")
    v = t1057.evaluate(anchor, events)
    assert v is not None
    assert v.result == "alerted"
    assert v.correlated_event_id == "SYN-T1057-00002"
 
 
def test_single_call_is_suppressed():
    events, _ = load_normalized(SYNTHETIC_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1057-00003")
    v = t1057.evaluate(anchor, events)
    assert v is not None
    assert v.result == "suppressed"
 
 
def test_interactive_single_use_is_suppressed():
    events, _ = load_normalized(SYNTHETIC_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1057-00004")
    v = t1057.evaluate(anchor, events)
    assert v is not None
    assert v.result == "suppressed"
 
 
def test_management_tool_context_is_suppressed():
    events, _ = load_normalized(SYNTHETIC_PATH)
    anchor = next(e for e in events if e.event_id == "SYN-T1057-00005")
    v = t1057.evaluate(anchor, events)
    assert v is not None
    assert v.result == "suppressed"
 
 
def test_no_false_positives_on_real_public_t1057_benign_fixtures():
    with open(PUBLIC_FIXTURES_PATH) as f:
        data = json.load(f)
 
    t1057_cases = [
        fx for fx in data["fixtures"]
        if any(e.get("technique_id") == "T1057" for e in fx["events"])
    ]
    assert len(t1057_cases) == 9
 
    for fx in t1057_cases:
        for raw_event in fx["events"]:
            if raw_event.get("event_code") != 1:
                continue
            event = NormalizedEvent(
                event_id=str(raw_event.get("event_id", "unknown")),
                timestamp="1970-01-01T00:00:00Z",
                channel=raw_event.get("channel", ""),
                event_code=raw_event["event_code"],
                computer="unknown",
                user="unknown",
                image=raw_event["image"],
                parent_image=raw_event["parent_image"],
                command_line="",
                schema_version="fixture",
                source_line_hash="n/a",
            )
            v = t1057.evaluate(event, [])
            if v is not None:
                assert v.result != "alerted"
