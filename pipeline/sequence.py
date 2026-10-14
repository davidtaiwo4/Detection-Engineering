"""
sequence.py — shared time-window correlation helper.

Used by rules that must satisfy "correlate multiple events or enforce a
sequence/time window" (brief.md detection contract), as opposed to the
single-event rules built for the six replay-covered techniques.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Callable, Optional

from pipeline.adapter import NormalizedEvent


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def find_correlated_event(
    anchor: NormalizedEvent,
    all_events: list[NormalizedEvent],
    predicate: Callable[[NormalizedEvent], bool],
    window_minutes: int,
    same_host_only: bool = True,
    after_only: bool = True,
) -> Optional[NormalizedEvent]:
    """
    Finds the first event matching `predicate` within `window_minutes` of
    `anchor`, optionally constrained to the same host and to only after
    the anchor's timestamp (the common "step 2 follows step 1" case).

    Returns None if no match — callers treat that as "sequence incomplete,"
    not as an automatic alert. A rule requiring correlation must not fire
    on the anchor event alone.
    """
    anchor_t = _parse_ts(anchor.timestamp)
    window = timedelta(minutes=window_minutes)

    candidates = []
    for event in all_events:
        if event.event_id == anchor.event_id:
            continue
        if same_host_only and event.computer != anchor.computer:
            continue
        event_t = _parse_ts(event.timestamp)
        delta = event_t - anchor_t
        if after_only and delta.total_seconds() < 0:
            continue
        if abs(delta) > window:
            continue
        if not predicate(event):
            continue
        candidates.append((event_t, event))

    if not candidates:
        return None

    candidates.sort(key=lambda pair: pair[0])
    return candidates[0][1]
