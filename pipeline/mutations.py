"""
pipeline/mutations.py — reusable mutation generator.

Required deliverable per brief.md: "Detection source, tests, mutation
generator, and deterministic CLI runner." This module is that generator —
importable and reusable, not buried inside test functions.

Every function takes a raw event dict (the pre-normalization JSON shape,
matching either the sealed replay's schema or a fixture's schema) and
returns a NEW dict — never mutates the input in place, so a test can
always compare mutated vs. original side by side.
"""

from __future__ import annotations

import copy


def mutate_command_encoding(raw: dict) -> dict:
    """
    Changes command_line and command_family to arbitrary different values.
    Used to prove a rule's verdict is invariant to these fields — i.e. the
    rule genuinely never reads them, not just that it happens not to today.
    """
    mutated = copy.deepcopy(raw)
    mutated["command_line"] = "MUTATED-" + str(raw.get("command_line", "")) + "-ENCODED-DIFFERENTLY"
    mutated["command_family"] = "native"  # deliberately flip to whatever the original wasn't
    return mutated


def drop_field(raw: dict, field: str) -> dict:
    """
    Removes a field entirely (not just blanks it) — simulates a collector
    or decoder failing to capture that attribute at all.
    """
    mutated = copy.deepcopy(raw)
    mutated.pop(field, None)
    return mutated


def rename_binary(raw: dict, new_name: str, field: str = "image") -> dict:
    """
    Renames the target binary (default: the `image` field) to something a
    rule's static allowlist won't recognize. Used to demonstrate a rule's
    documented rename-evasion blind spot actually reproduces as described,
    not just claimed in a docstring.
    """
    mutated = copy.deepcopy(raw)
    mutated[field] = new_name
    return mutated


def mutate_parent_process(raw: dict, new_parent: str, field: str = "parent_image") -> dict:
    """
    Changes the parent-process field to a different value. Used to prove a
    rule's (image, parent) pair matching is genuinely parent-sensitive, not
    accidentally keying off the image field alone.
    """
    mutated = copy.deepcopy(raw)
    mutated[field] = new_parent
    return mutated


def mutate_timing(raw: dict, delta_seconds_shift: float) -> dict:
    """
    Shifts a fixture-schema event's `delta_seconds` field by the given
    amount (schema per public-fixtures.json / harness.py: events carry
    delta_seconds relative to a fixed base time, reconstructed into a
    timestamp by the harness's normalizer). Used to push a correlated
    event outside a rule's stated correlation window and confirm the rule
    actually enforces that window rather than ignoring timestamps
    entirely.
    """
    mutated = copy.deepcopy(raw)
    mutated["delta_seconds"] = raw.get("delta_seconds", 0) + delta_seconds_shift
    return mutated
