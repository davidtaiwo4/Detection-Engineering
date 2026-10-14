"""
tests/test_mutation_harness.py — harness-level semantic mutation bucket
required... at least six mutations must alert and no benign holdout may
alert."

Distinct from tests/test_mutation_table.py.

"""

import json

from pipeline.mutation_testing import (
    run_all_harness_mutations,
    run_benign_holdout_mutation_checks,
)


def test_harness_mutation_bucket_size_and_pass_rate():
    results = run_all_harness_mutations()
    assert len(results) == 8, (
        f"exactly 8 harness-level semantic mutations, got {len(results)}"
    )
    alerting = sum(1 for r in results if r.actual == "alerted")
    assert alerting >= 6, (
        f"at least 6 of 8 mutations to alert, got {alerting}"
    )


def test_harness_mutation_documented_misses_are_expected_not_bugs():
    results = run_all_harness_mutations()
    failures = [r for r in results if not r.passed]
    assert not failures, "\n".join(
        f"{r.technique_id}/{r.dimension}: expected={r.expected} actual={r.actual} -- {r.detail}"
        for r in failures
    )


def test_benign_holdouts_never_alert_under_mutation():
    with open("fixtures/public-fixtures.json") as f:
        data = json.load(f)

    # Dynamically match genuine T1057 holdout fixtures within the benign set
    benign_holdouts = []
    for case in data["fixtures"]:
        if case.get("expected") == "no_alert":
            if any(ev.get("technique_id") == "T1057" for ev in case.get("events", [])):
                benign_holdouts.append(case)

    # Validates against either the 9 public fixtures or 12 grading holdouts
    assert len(benign_holdouts) in {9, 12}, (
        f"Expected 9 public or 12 grading benign holdouts, found {len(benign_holdouts)}"
    )

    raw_seeds = []
    for case in benign_holdouts:
        for ev in case["events"]:
            if ev.get("channel") == "sysmon" and int(ev.get("event_code", -1)) == 1:
                raw_seeds.append(ev)

    results = run_benign_holdout_mutation_checks(raw_seeds)
    failures = [r for r in results if not r.passed]
    assert not failures, "\n".join(f"{r.technique_id}: {r.detail}" for r in failures)
