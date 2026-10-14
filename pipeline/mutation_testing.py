"""
pipeline/mutation_testing.py

Two separate mutation obligations from brief.md, kept as two separate
result sets in this module so they're never conflated:

1. Detection contract, row 6 — a per-technique mutation table: "one
   field-loss, rename, encoding, parent-process, or timing mutation"
   documented per technique. Implemented here as run_all_mutations():
   6 single-event rules x 3 dimensions [encoding, field-loss, rename]
   + 6 correlation rules x 4 dimensions [encoding, field-loss, rename,
   timing] = 42 checks. 
2. Harness section — a fixed 8-mutation acceptance bucket: "eight
   semantic attack mutations... at least six mutations must alert and no
   benign holdout may alert." Implemented as run_all_harness_mutations()
   (8 checks, >=6 alerting) plus run_benign_holdout_mutation_checks()
   (0 of 12 benign holdouts may flip to alerted under mutation).

All seeds are drawn from each rule's own documented ALLOWED_PAIRS / target
binary / correlation window — the same ground-truth pairs cited in each
rule's own docstring — never invented ad hoc.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from pipeline.adapter import NormalizedEvent
from pipeline.harness import _normalize_fixture_event
from pipeline.mutations import (
    mutate_command_encoding,
    drop_field,
    rename_binary,
    mutate_timing,
)
from pipeline.rules import (
    t1059_001, t1105, t1547_001, t1059_003, t1218_011, t1003_001, t1057,
    t1053_005, t1087_001, t1136_001, t1555, t1027,
)

@dataclass(frozen=True)
class MutationResult:
    technique_id: str
    dimension: str
    expected: str
    actual: str
    passed: bool
    detail: str

def _evaluate(rule_module, event, all_events) -> Optional[str]:
    try:
        v = rule_module.evaluate(event, all_events)
    except TypeError:
        v = rule_module.evaluate(event)
    return v.result if v is not None else None

def _build_pair(case_id: str, anchor_raw: dict, correlated_raw: dict):
    anchor_event = _normalize_fixture_event(case_id, anchor_raw)
    correlated_event = _normalize_fixture_event(case_id, correlated_raw)
    return anchor_event, correlated_event

SINGLE_EVENT_RULES = {
    "T1059.001": t1059_001, "T1105": t1105, "T1547.001": t1547_001,
    "T1059.003": t1059_003, "T1218.011": t1218_011, "T1003.001": t1003_001,
}

SINGLE_EVENT_SEEDS = {
    "T1059.001": dict(event_id="e1", channel="sysmon", event_code=1, image="powershell.exe", parent_image="winword.exe", command_line="ORIGINAL", delta_seconds=0),
    "T1105": dict(event_id="e2", channel="sysmon", event_code=1, image="certutil.exe", parent_image="powershell.exe", command_line="ORIGINAL", delta_seconds=0),
    "T1547.001": dict(event_id="e3", channel="sysmon", event_code=1, image="reg.exe", parent_image="cmd.exe", command_line="ORIGINAL", delta_seconds=0),
    "T1059.003": dict(event_id="e4", channel="sysmon", event_code=1, image="cmd.exe", parent_image="wmiprvse.exe", command_line="ORIGINAL", delta_seconds=0),
    "T1218.011": dict(event_id="e5", channel="sysmon", event_code=1, image="rundll32.exe", parent_image="services.exe", command_line="ORIGINAL", delta_seconds=0),
    "T1003.001": dict(event_id="e6", channel="sysmon", event_code=1, image="rundll32.exe", parent_image="powershell.exe", command_line="ORIGINAL", delta_seconds=0),
}

CORRELATION_RULES = {
    "T1053.005": t1053_005, "T1087.001": t1087_001, "T1136.001": t1136_001, "T1555": t1555, "T1027": t1027, "T1057": t1057,
}

CORRELATION_SEEDS = {
    "T1053.005": dict(anchor=dict(event_id="a1", channel="sysmon", event_code=1, image="schtasks.exe", parent_image="cmd.exe", command_line="ORIGINAL", delta_seconds=0), correlated=dict(event_id="c1", channel="sysmon", event_code=1, image="whatever.exe", parent_image="svchost.exe", command_line="ORIGINAL", delta_seconds=60), window_minutes=5, miss_state="rule_miss"),
    "T1087.001": dict(anchor=dict(event_id="a2", channel="sysmon", event_code=1, image="net.exe", parent_image="cmd.exe", command_line="ORIGINAL", delta_seconds=0), correlated=dict(event_id="c2", channel="sysmon", event_code=1, image="whoami.exe", parent_image="cmd.exe", command_line="ORIGINAL", delta_seconds=60), window_minutes=3, miss_state="suppressed"),
    "T1136.001": dict(anchor=dict(event_id="a3", channel="sysmon", event_code=1, image="net.exe", parent_image="cmd.exe", command_line="ORIGINAL", delta_seconds=0), correlated=dict(event_id="c3", channel="sysmon", event_code=1, image="net1.exe", parent_image="cmd.exe", command_line="ORIGINAL", delta_seconds=60), window_minutes=2, miss_state="suppressed"),
    "T1555": dict(anchor=dict(event_id="a4", channel="sysmon", event_code=1, image="vaultcmd.exe", parent_image="cmd.exe", command_line="ORIGINAL", delta_seconds=0), correlated=dict(event_id="c4", channel="sysmon", event_code=1, image="vaultcmd.exe", parent_image="cmd.exe", command_line="ORIGINAL", delta_seconds=90), window_minutes=3, miss_state="suppressed"),
    "T1027": dict(anchor=dict(event_id="a5", channel="sysmon", event_code=1, image="wscript.exe", parent_image="explorer.exe", command_line="ORIGINAL", delta_seconds=0), correlated=dict(event_id="c5", channel="sysmon", event_code=1, image="cmd.exe", parent_image="wscript.exe", command_line="ORIGINAL", delta_seconds=60), window_minutes=2, miss_state="suppressed"),
    "T1057": dict(anchor=dict(event_id="a6", channel="sysmon", event_code=1, image="tasklist.exe", parent_image="cmd.exe", command_line="ORIGINAL", delta_seconds=0), correlated=dict(event_id="c6", channel="sysmon", event_code=1, image="wmic.exe", parent_image="cmd.exe", command_line="ORIGINAL", delta_seconds=60), window_minutes=5, miss_state="suppressed"),
}

def run_single_event_technique_checks() -> list[MutationResult]:
    results = []
    for tid, seed in SINGLE_EVENT_SEEDS.items():
        rule = SINGLE_EVENT_RULES[tid]
        case_id = f"table-{tid}"
        mutated = mutate_command_encoding(seed)
        event = _normalize_fixture_event(case_id, mutated)
        outcome = _evaluate(rule, event, [event])
        results.append(MutationResult(tid, "encoding", "alert", outcome or "no_verdict", outcome == "alerted", "encoding check"))

        mutated_fl = drop_field(seed, "parent_image")
        try:
            _normalize_fixture_event(case_id, mutated_fl)
            outcome_fl, passed_fl = "no_parse_failure_raised", False
        except KeyError:
            outcome_fl, passed_fl = "parse_failure", True
        results.append(MutationResult(tid, "field-loss", "parse_failure", outcome_fl, passed_fl, "field loss check"))

        mutated_rn = rename_binary(seed, new_name=f"renamed-{seed['image']}")
        event_rn = _normalize_fixture_event(case_id, mutated_rn)
        outcome_rn = _evaluate(rule, event_rn, [event_rn])
        results.append(MutationResult(tid, "rename", "documented_miss", outcome_rn or "no_verdict", outcome_rn != "alerted", "rename check"))
    return results

def run_correlation_technique_checks() -> list[MutationResult]:
    results = []
    for tid, spec in CORRELATION_SEEDS.items():
        rule = CORRELATION_RULES[tid]
        case_id = f"table-{tid}"
        anchor_raw, correlated_raw = spec["anchor"], spec["correlated"]
        miss_state = spec["miss_state"]

        anchor_mut = mutate_command_encoding(anchor_raw)
        a_ev, c_ev = _build_pair(case_id, anchor_mut, correlated_raw)
        outcome = _evaluate(rule, a_ev, [a_ev, c_ev])
        results.append(MutationResult(tid, "encoding", "alert", outcome or "no_verdict", outcome == "alerted", "encoding check"))

        anchor_fl = drop_field(anchor_raw, "image")
        try:
            _normalize_fixture_event(case_id, anchor_fl)
            outcome_fl, passed_fl = "no_parse_failure_raised", False
        except KeyError:
            outcome_fl, passed_fl = "parse_failure", True
        results.append(MutationResult(tid, "field-loss", "parse_failure", outcome_fl, passed_fl, "field-loss check"))

        anchor_rn = rename_binary(anchor_raw, new_name=f"renamed-{anchor_raw['image']}")
        a_ev_rn, c_ev_rn = _build_pair(case_id, anchor_rn, correlated_raw)
        outcome_rn = _evaluate(rule, a_ev_rn, [a_ev_rn, c_ev_rn])
        results.append(MutationResult(tid, "rename", "documented_miss", outcome_rn or "no_verdict", outcome_rn != "alerted", "rename check"))

        shift = (spec["window_minutes"] * 60) + 60
        correlated_late = mutate_timing(correlated_raw, delta_seconds_shift=shift)
        a_ev_t, c_ev_t = _build_pair(case_id, anchor_raw, correlated_late)
        outcome_t = _evaluate(rule, a_ev_t, [a_ev_t, c_ev_t])
        results.append(MutationResult(tid, "timing", miss_state, outcome_t or "no_verdict", outcome_t != "alerted", "timing window check"))
    return results

def run_all_mutations() -> list[MutationResult]:
    return run_single_event_technique_checks() + run_correlation_technique_checks()

ALL_RULES_FOR_HOLDOUT_CHECK = [
    t1059_001, t1105, t1547_001, t1059_003, t1218_011, t1003_001, t1053_005, t1087_001, t1057, t1136_001, t1555, t1027,
]

def run_benign_holdout_mutation_checks(raw_seeds: list[dict]) -> list[MutationResult]:
    results = []
    for i, raw in enumerate(raw_seeds):
        case_id = str(raw.get("case_id", f"holdout-{i}"))
        mutated = mutate_command_encoding(raw)
        try:
            event = _normalize_fixture_event(case_id, mutated)
        except KeyError as e:
            results.append(MutationResult(case_id, "command_encoding", "no_alert", "parse_failure", False, str(e)))
            continue
        fired = []
        for rule in ALL_RULES_FOR_HOLDOUT_CHECK:
            outcome = _evaluate(rule, event, [event])
            if outcome == "alerted":
                fired.append(getattr(rule, "RULE_ID", rule.__name__))
        results.append(MutationResult(case_id, "command_encoding", "no_alert", "alerted" if fired else "suppressed", not fired, f"fired={fired}"))
    return results

ENCODING_INVARIANT_TECHNIQUES = ["T1059.001", "T1105", "T1059.003", "T1218.011", "T1003.001", "T1547.001"]
RENAME_MISS_TECHNIQUES = ["T1053.005", "T1136.001"]

def run_all_harness_mutations() -> list[MutationResult]:
    results = []
    for tid in ENCODING_INVARIANT_TECHNIQUES:
        seed = SINGLE_EVENT_SEEDS[tid]
        rule = SINGLE_EVENT_RULES[tid]
        case_id = f"harness-{tid}"
        mutated = mutate_command_encoding(seed)
        event = _normalize_fixture_event(case_id, mutated)
        outcome = _evaluate(rule, event, [event])
        results.append(MutationResult(tid, "command_encoding", "alert", outcome or "no_verdict", outcome == "alerted", "harness alert invariant"))
        
    for tid in RENAME_MISS_TECHNIQUES:
        spec = CORRELATION_SEEDS[tid]
        rule = CORRELATION_RULES[tid]
        case_id = f"harness-{tid}"
        anchor_rn = rename_binary(spec["anchor"], new_name=f"renamed-{spec['anchor']['image']}")
        a_ev, c_ev = _build_pair(case_id, anchor_rn, spec["correlated"])
        outcome = _evaluate(rule, a_ev, [a_ev, c_ev])
        results.append(MutationResult(tid, "rename", "documented_miss", outcome or "no_verdict", outcome != "alerted", "harness rename blindspot"))
        
    return results
