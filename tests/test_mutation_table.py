"""
tests/test_mutation_table.py — per-technique mutation table required
("one field-loss, rename, encoding, parent-process, or timing mutation" 
per technique).

Distinct from tests/test_mutation_harness.py, which covers the separate
harness-level 8-mutation acceptance bucket.
"""

from pipeline.mutation_testing import run_all_mutations


def test_all_mutation_checks_pass():
    results = run_all_mutations()
    failures = [r for r in results if not r.passed]
    assert not failures, "\n".join(
        f"{r.technique_id}/{r.dimension}: expected={r.expected} actual={r.actual} -- {r.detail}"
        for r in failures
    )


def test_mutation_table_check_count():
    results = run_all_mutations()
    # 6 single-event rules (T1059.001, T1105, T1547.001, T1059.003, T1218.011,
    # T1003.001) x 3 dimensions [encoding, field-loss, rename]
    # + 6 correlation rules (T1053.005, T1087.001, T1136.001, T1555, T1027, T1057)
    # x 4 dimensions [encoding, field-loss, rename, timing] = 41.
    #This is 6/6
    assert len(results) == 42, (
        f"expected 42 mutation checks, got {len(results)} -- "
        "a rule or seed was added/removed without updating this count"
    )


def test_every_technique_covered():
    results = run_all_mutations()
    covered = {r.technique_id for r in results}
    expected = {
        "T1059.001", "T1105", "T1547.001", "T1059.003", "T1218.011", "T1003.001",
        "T1057", "T1053.005", "T1087.001", "T1136.001", "T1555", "T1027",
    }
    assert covered == expected, f"missing: {expected - covered}, unexpected: {covered - expected}"
