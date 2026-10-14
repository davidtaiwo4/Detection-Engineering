# Detection Engineering Under Adversary Pressure

Detection-as-code for 12 MITRE ATT&CK techniques, built as a portable Python
pipeline with a deterministic regression harness.
A portable detection engine for twelve attack techniques,built from a given signed replay of Windows security activity.
The engine proves it catches changed versions of the attacks without flagging normal activity, explains every failure state and reproduce the same results twice
## What it does

- Normalizes Windows process-creation telemetry (Sysmon Event 1 / Security 4688) from a 250,000-event replay into a stable internal event shape.
- Runs 12 semantic detection rules, six of which correlate multiple events or enforce a time window.
- Classifies every case into `alerted`, `suppressed`, `rule_miss`, `no_telemetry`, `parse_failure`, or `unexpected_alert`, writes JUnit XML and JSON reports, and exits non-zero on any mismatch.
- Includes a mutation generator and tests for field loss, command re-encoding, and binary renames.

## Design principles

- **No literal matching.** Rules use process lineage, `(image, parent_image)` relationships, sequences, and time windows. They never read `command_line`, which is scrubbed in this dataset and a weak signal anyway.
- **Ground-truth isolation.** Answer-key fields in the replay (`marker`, `mitre_technique`) are stripped by the adapter. Rules never see them, and they appear only in test assertions.
- **Evidence before coverage.** Every candidate `(image, parent)` pair was checked against the full replay for false positives before inclusion. A blanket "any proxy binary under any suspicious parent" rule produced 61 false positives on legitimate signed-update traffic and was rejected.
- **Determinism.** Two clean runs produce identical result hashes.

## Results

| Check | Result |
|---|---|
| Replay-covered techniques (6) | Exact match against ground truth: 0 false positives, 0 false negatives across 250,000 events |
| Public acceptance fixtures (36) | 33 pass; 3 documented collisions |
| Correlation/sequence rules | 6 of 12 |

The 3 failing fixtures (`P-DET-14`, `P-DET-33`, `P-DET-34`) are structurally identical to alert-case fixtures in every permitted field. Only the technique label differs, so no non-prohibited signal can separate them. See `decision-log.md`.

Six techniques (T1053.005, T1087.001, T1057, T1136.001, T1555, T1027) have no telemetry in the replay and are validated against self-constructed fixtures. See `fixtures/synthetic/PROVENANCE.md`.

## Repository layout

```
pipeline/            adapter, rules (one module per technique), correlation helper, harness, mutations
pipeline/rules/      12 detection rules
tests/               per-rule tests, harness tests, mutation tests
fixtures/            public fixtures and synthetic fixtures with provenance
raw-events/          source manifest (the replay itself is not included)
tools/               coverage-matrix generator
decision-log.md      judgment calls, rejected alternatives, and evidence
coverage-matrix.csv  per-case source -> normalized -> verdict triples
rules/, decoders/    earlier Wazuh XML work, kept as a compatibility adapter
```

## Running it

Requires Python 3.11+.

```bash
python3 -m venv venv && source venv/bin/activate
pip install pytest

# The replay is staff-supplied and not redistributed. Place it at
# raw-events/windows-replay.jsonl and verify:
sha256sum raw-events/windows-replay.jsonl
# expected: ea7f96497f9275ccdc47fdb026480558547db5bfaa7aa8bf3a806a2bc9272838

make test
python3 -m pipeline.cli run --input raw-events/windows-replay.jsonl
python3 -m pipeline.harness --fixtures fixtures/public-fixtures.json \
  --junit-out regression-results.xml --json-out harness-report.json
```

