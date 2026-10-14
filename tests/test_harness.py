"""
Validates the harness module itself: correct classification into all 6
required states, deterministic hashing, and the known/documented result
against the real public-fixtures.json (33/36 match, 3 documented
unexpected_alert collisions — see decision log).
"""
 
import os
import sys
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from pipeline.harness import run_harness, result_hash
 
 
PUBLIC_FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "public-fixtures.json")
EDGE_CASES_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "synthetic", "harness_edge_cases.json")
 
 
def test_public_fixtures_known_result():
    """
    Documents and locks in the known result: 33/36 match, 3 documented
    unexpected_alert collisions (P-DET-14, P-DET-33, P-DET-34 — see
    decision log for why these are unsolvable with permitted signal).
    If this test starts failing, either a rule regressed or the fixture
    file changed — both worth investigating, not silencing.
    """
    results = run_harness(PUBLIC_FIXTURES_PATH)
    assert len(results) == 36
 
    counts = {}
    for r in results:
        counts[r.classification] = counts.get(r.classification, 0) + 1
 
    assert counts.get("alerted", 0) == 12
    assert counts.get("suppressed", 0) == 21
    assert counts.get("unexpected_alert", 0) == 3
    assert counts.get("rule_miss", 0) == 0
    assert counts.get("parse_failure", 0) == 0
    assert counts.get("no_telemetry", 0) == 0
 
    known_collisions = {"P-DET-14", "P-DET-33", "P-DET-34"}
    actual_collisions = {r.case_id for r in results if r.classification == "unexpected_alert"}
    assert actual_collisions == known_collisions
 
 
def test_harness_is_deterministic():
    r1 = run_harness(PUBLIC_FIXTURES_PATH)
    r2 = run_harness(PUBLIC_FIXTURES_PATH)
    assert result_hash(r1) == result_hash(r2)
 
 
def test_no_telemetry_classification():
    results = run_harness(EDGE_CASES_PATH)
    case = next(r for r in results if r.case_id == "EDGE-NO-TELEMETRY-01")
    assert case.classification == "no_telemetry"
 
 
def test_parse_failure_classification():
    results = run_harness(EDGE_CASES_PATH)
    case = next(r for r in results if r.case_id == "EDGE-PARSE-FAILURE-01")
    assert case.classification == "parse_failure"
 
 
def test_suppressed_baseline_classification():
    results = run_harness(EDGE_CASES_PATH)
    case = next(r for r in results if r.case_id == "EDGE-VALID-BASELINE-01")
    assert case.classification == "suppressed"
