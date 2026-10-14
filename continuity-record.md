# Continuity Record — Stage 8

## 1. Previous-stage commit and exact component reused

Stage 7 (Network Range) handoff was evaluated, not consumed as data. Stage 8's assigned input is a separately sealed, hash-verified archive (windows-replay.jsonl, evidence marker UBI-A8-8E354A788F17, private assignment set D3) — not evidence/stage8-handoff.jsonl from Stage 7. 

*What genuinely carries forward is design pattern, not data:*

**Stage 5 (Hunt Engine)** 
Component reused: the COALESCE-style, version-aware field normalization pattern (branch explicitly per schema version rather than assume one fixed shape). pipeline/adapter.py's normalize() cites this directly — "per the Stage 6 lesson" in its own docstring, tracing back to the Stage 5-established practice — and branches on schema_version even though all three observed versions in this replay happen to share one field set, because a hidden fixture may not.
Stage 5 Commit: `30036cc9ab3a7e580d6a5c80f0605f7d192f5bbb`

From **Stage 6 (Honeypot Pipeline) via Stage 7's own adoption of it**
Component reused: the principle of deriving a stable identifier from a structurally reliable source rather than a fixture-supplied label that isn't guaranteed stable across a hidden holdout (Stage 6's canonical_session_id, reused by Stage 7 for its zone-pair/service identifier). Stage 8 applies the same principle in harness.py and adapter.py's fixture normalizers: each fixture case is namespaced to a synthetic computer/event_id prefix derived from case_id, so correlation rules cannot contaminate across cases even under a relabeled or hidden fixture set.
Stage 6 Commit: d1113b96ec56512e7d2e42ce890b1279b0bc4f5f


## 2. Interface consumed and backward-compatible extension

No Stage 5/6/7 evidence-record interface is consumed at runtime this stage. The track's expected progression ("detection engineering consumes the verified behaviours") assumes network-range findings feed forward as detection input; Stage 8's actual assignment substitutes a sealed Windows/Sysmon replay as its input instead.

What Stage 8 does extend, backward-compatibly, is its own internal interface: adapter.py separates every event into a NormalizedEvent (passed to rule evaluation) and an optional GroundTruth (validation-only, never passed to rules) — established as decision-log D-005 and held constant across every rule file and the harness. mutation_testing.py and the harness-level mutation bucket added this stage extend that same NormalizedEvent contract with no change to its required fields; a rule written before mutation testing existed still runs unmodified against a mutated event.

## 3. Evidence that prior raw-to-result provenance remains intact

This stage did not read, copy, or modify any Stage 5, 6, or 7 raw artifact, archive, or repository. Stage 7's soc-analysis-stage-7-shared-b1.tar.gz and its generated evidence/stage8-handoff.jsonl are untouched. Stage 8 operates entirely on its own independently assigned archive (`soc-analysis-stage-8-shared-b2.tar.gz`, SHA-256 `75c476baac8b1c123522006e53053f766bd36baad4e3238223da67e12a53843c`) plus its own public fixtures and self-constructed synthetic fixtures. Provenance intact by construction: no shared file paths, no shared database, no in-place edits to any prior-stage output.

## 4. Migration record for every incompatible change

Incompatible change: Stage 8 does not consume the Stage 5/6/7 normalized evidence-record schema as its detection input, despite the track's stated progression implying it would.

Why: Stage 8's actual brief assigns a separately sealed, hash-verified replay as "the complete scored source," to be processed as immutable evidence in its own right — not as a downstream consumer of Stage 7's network-finding schema. Substituting Stage 7's schema for the assigned replay would mean scoring against the wrong evidence entirely, which is a worse failure than a documented interface gap.

Migration: none performed, because there is nothing to migrate — no Stage 5/6/7 field was renamed, removed, or reused incorrectly; the interface was simply not applicable to this stage's assigned input.

## 5. Component, schema, evidence, and decision record handed to the next stage

- **Portable detection engine:** pipeline/adapter.py (versioned normalizer, ground-truth separation), pipeline/rules/ (12 techniques, 6 correlation/sequence rules meeting the brief's minimum), pipeline/sequence.py (shared correlation helper).
- **Verified detections:** 6 rules validated with exact-match results against real sealed-replay ground truth (T1059.001, T1105, T1547.001, T1059.003, T1218.011, T1003.001); 6 rules validated only against self-constructed synthetic fixtures, with provenance recorded in fixtures/synthetic/provenance.md — handed forward explicitly as unverified-against-real-telemetry, not silently presented as equivalent.
- **Deterministic acceptance harness:** pipeline/harness.py, six-state verdict classification, stable result hashes across repeated runs, JUnit and JSON report output.
- **Mutation robustness evidence:** pipeline/mutations.py (reusable generator), pipeline/mutation_testing.py and mutation-test-report.csv — the per-technique table (42 checks, one mutation dimension per technique) and the harness-level bucket (8 semantic mutations, 6 alerting, 2 documented rename blind spots, 0 benign-holdout false positives under mutation).
- **Named, unresolved blind spots handed forward:** the static-image-allowlist rename blind spot reproduced for T1053.005 and T1136.001; the 3 of 36 public fixtures (P-DET-14, P-DET-33, P-DET-34) that produce an unsolvable unexpected_alert under the schema's permitted signal (decision-log D-008); the 6 self-constructed rules' total dependence on synthetic rather than real telemetry.
- **Decision record:** decision-log.md in full, covering the route change from live Wazuh lab to portable replay pipeline, the D-005 ground-truth separation rule, the D-002/D-004 schema-version findings, and the D-008 unsolvable-fixture finding — handed forward so the next stage does not assume verification depth this stage did not actually achieve.
