#!/usr/bin/env python3
"""Bounded state-transition model for the Obsidian Clock ring lifetime bug.

The small-width model makes generation wrap reachable during exhaustive BFS.
It is a bounded verification aid, not a universal proof of kernel correctness.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass, replace
from enum import IntEnum
from typing import Iterable


class SlotState(IntEnum):
    FREE = 0
    RESERVED = 1
    READY = 2
    CONSUMING = 3
    CANCELLED = 4


class TerminalActor(IntEnum):
    NONE = 0
    NORMAL = 1
    CANCEL = 2
    STALE_CANCEL = 3


@dataclass(frozen=True)
class Ticket:
    irp_id: int
    slot_index: int
    generation: int
    owner_id: int
    full_sequence: int

    def truncated_match(self, state: "RingState") -> bool:
        return self.slot_index == 0 and (
            self.generation == state.generation and self.owner_id == state.owner_id
        )

    def full_match(self, state: "RingState") -> bool:
        return self.truncated_match(state) and (
            self.full_sequence == state.slot_sequence and self.irp_id == state.occupant
        )


@dataclass(frozen=True)
class RingState:
    slot_state: SlotState
    generation: int
    owner_id: int
    connected: bool
    slot_sequence: int
    next_sequence: int
    occupant: int
    next_irp: int
    payload_published: bool
    terminal_actor: TerminalActor
    stale_cancel_hit: bool
    pending_cancels: tuple[Ticket, ...]
    completions: tuple[int, ...]


@dataclass(frozen=True)
class ModelConfig:
    fixed: bool
    generation_bits: int = 1
    owner_bits: int = 1
    max_irps: int = 3
    max_depth: int = 18

    def __post_init__(self) -> None:
        if not 1 <= self.generation_bits <= 16:
            raise ValueError("generation_bits must be in 1..16")
        if not 1 <= self.owner_bits <= 32:
            raise ValueError("owner_bits must be in 1..32")
        if self.max_irps < 1 or self.max_depth < 0:
            raise ValueError("max_irps must be positive and max_depth nonnegative")

    @property
    def generation_mask(self) -> int:
        return (1 << self.generation_bits) - 1

    @property
    def owner_mask(self) -> int:
        return (1 << self.owner_bits) - 1


@dataclass(frozen=True)
class TraceStep:
    action: str
    state: RingState


@dataclass(frozen=True)
class SearchResult:
    violation: str | None
    trace: tuple[TraceStep, ...]
    explored_states: int
    depth_bound: int


@dataclass(frozen=True)
class EvidenceReplay:
    old_ticket: Ticket
    new_generation: int
    new_owner_id: int
    new_full_sequence: int
    reuse_count: int
    truncated_match: bool
    full_identity_match: bool


def initial_state(config: ModelConfig) -> RingState:
    return RingState(
        slot_state=SlotState.FREE,
        generation=0,
        owner_id=0,
        connected=True,
        slot_sequence=0,
        next_sequence=1,
        occupant=0,
        next_irp=1,
        payload_published=False,
        terminal_actor=TerminalActor.NONE,
        stale_cancel_hit=False,
        pending_cancels=(),
        completions=(0,) * (config.max_irps + 1),
    )


def _increment_completion(state: RingState, irp_id: int) -> RingState:
    counts = list(state.completions)
    counts[irp_id] += 1
    return replace(state, completions=tuple(counts))


def invariant_violation(state: RingState, config: ModelConfig) -> str | None:
    for irp_id, count in enumerate(state.completions):
        if count > 1:
            return f"IRP {irp_id} completed {count} times"
    if state.slot_state in (SlotState.READY, SlotState.CONSUMING) and not state.payload_published:
        return "consumer-visible state published before payload"
    if state.slot_state == SlotState.FREE and state.occupant != 0:
        return "FREE slot retains an occupant"
    if state.slot_state != SlotState.FREE and state.occupant == 0:
        return "non-FREE slot has no occupant"
    if config.fixed and state.stale_cancel_hit:
        return "corrected model allowed stale cancellation authority"
    return None


def successors(state: RingState, config: ModelConfig) -> tuple[tuple[str, RingState], ...]:
    """Return every enabled transition from ``state`` in deterministic order."""

    result: list[tuple[str, RingState]] = []

    if (
        state.connected
        and state.slot_state == SlotState.FREE
        and state.next_irp <= config.max_irps
        and (not config.fixed or not state.pending_cancels)
    ):
        result.append(
            (
                "reserve",
                replace(
                    state,
                    slot_state=SlotState.RESERVED,
                    generation=(state.generation + 1) & config.generation_mask,
                    slot_sequence=state.next_sequence,
                    next_sequence=state.next_sequence + 1,
                    occupant=state.next_irp,
                    next_irp=state.next_irp + 1,
                    payload_published=False,
                    terminal_actor=TerminalActor.NONE,
                    stale_cancel_hit=False,
                ),
            )
        )

    if state.slot_state == SlotState.RESERVED and state.occupant:
        result.append(("publish", replace(state, slot_state=SlotState.READY, payload_published=True)))

    if state.slot_state in (SlotState.RESERVED, SlotState.READY, SlotState.CONSUMING):
        if state.occupant and not state.pending_cancels:
            ticket = Ticket(
                irp_id=state.occupant,
                slot_index=0,
                generation=state.generation,
                owner_id=state.owner_id,
                full_sequence=state.slot_sequence,
            )
            result.append(("queue_cancel", replace(state, pending_cancels=(ticket,))))

    if state.slot_state == SlotState.READY and state.payload_published:
        result.append(("begin_consume", replace(state, slot_state=SlotState.CONSUMING)))

    if state.pending_cancels:
        ticket = state.pending_cancels[0]
        result.append(("detach_cancel", replace(state, pending_cancels=state.pending_cancels[1:])))

        after_pop = replace(state, pending_cancels=state.pending_cancels[1:])
        if config.fixed:
            if ticket.full_match(state) and state.terminal_actor == TerminalActor.NONE:
                cancelled = replace(
                    after_pop,
                    slot_state=SlotState.CANCELLED,
                    terminal_actor=TerminalActor.CANCEL,
                )
                cancelled = _increment_completion(cancelled, state.occupant)
                result.append(("execute_cancel", cancelled))
            else:
                result.append(("execute_cancel", after_pop))
        elif ticket.truncated_match(state) and state.occupant:
            if ticket.irp_id == state.occupant and state.terminal_actor == TerminalActor.NONE:
                cancelled = replace(
                    after_pop,
                    slot_state=SlotState.CANCELLED,
                    terminal_actor=TerminalActor.CANCEL,
                )
                cancelled = _increment_completion(cancelled, state.occupant)
                result.append(("execute_cancel", cancelled))
            elif ticket.irp_id != state.occupant and state.slot_state in (
                SlotState.READY,
                SlotState.CONSUMING,
            ):
                # ABA: the stale ticket completes the current slot occupant.
                cancelled = replace(
                    after_pop,
                    slot_state=SlotState.CANCELLED,
                    terminal_actor=TerminalActor.STALE_CANCEL,
                    stale_cancel_hit=True,
                )
                cancelled = _increment_completion(cancelled, state.occupant)
                result.append(("execute_cancel", cancelled))
            else:
                result.append(("execute_cancel", after_pop))
        else:
            result.append(("execute_cancel", after_pop))

    if state.occupant and state.slot_state in (
        SlotState.READY,
        SlotState.CONSUMING,
        SlotState.CANCELLED,
    ):
        if config.fixed:
            if state.terminal_actor == TerminalActor.NONE:
                completed = replace(state, terminal_actor=TerminalActor.NORMAL)
                completed = _increment_completion(completed, state.occupant)
                result.append(("normal_complete", completed))
        elif state.terminal_actor == TerminalActor.NONE or state.stale_cancel_hit:
            completed = replace(state, terminal_actor=TerminalActor.NORMAL)
            completed = _increment_completion(completed, state.occupant)
            result.append(("normal_complete", completed))

    if state.occupant and state.terminal_actor != TerminalActor.NONE:
        cancellation_attached = any(t.irp_id == state.occupant for t in state.pending_cancels)
        if not config.fixed or not cancellation_attached:
            result.append(
                (
                    "free_slot",
                    replace(
                        state,
                        slot_state=SlotState.FREE,
                        occupant=0,
                        payload_published=False,
                        terminal_actor=TerminalActor.NONE,
                        stale_cancel_hit=False,
                    ),
                )
            )

    if state.connected and state.slot_state == SlotState.FREE:
        result.append(("disconnect", replace(state, connected=False)))
    if not state.connected and state.slot_state == SlotState.FREE:
        result.append(
            (
                "reconnect",
                replace(state, connected=True, owner_id=(state.owner_id + 1) & config.owner_mask),
            )
        )

    return tuple(result)


def run_actions(config: ModelConfig, actions: Iterable[str]) -> RingState:
    """Execute a deterministic named trace, primarily for regression tests."""

    state = initial_state(config)
    for action in actions:
        matches = [candidate for name, candidate in successors(state, config) if name == action]
        if len(matches) != 1:
            enabled = sorted(name for name, _ in successors(state, config))
            raise ValueError(f"action {action!r} not uniquely enabled; enabled={enabled}")
        state = matches[0]
    return state


def search(config: ModelConfig) -> SearchResult:
    """Breadth-first search for the shortest invariant counterexample."""

    start = initial_state(config)
    queue = deque([(start, tuple())])
    seen = {start}
    explored = 0

    while queue:
        state, trace = queue.popleft()
        explored += 1
        violation = invariant_violation(state, config)
        if violation:
            return SearchResult(violation, trace, explored, config.max_depth)
        if len(trace) >= config.max_depth:
            continue
        for action, candidate in successors(state, config):
            if candidate in seen:
                continue
            seen.add(candidate)
            queue.append((candidate, trace + (TraceStep(action, candidate),)))
    return SearchResult(None, tuple(), explored, config.max_depth)


def reproduce_evidence_identity_collision() -> EvidenceReplay:
    """Calculate the exact identity collision described by `[E-RING-04]`."""

    old = Ticket(
        irp_id=1,
        slot_index=37,
        generation=0xFFFE,
        owner_id=0x2A,
        full_sequence=0x000000000000FFFE,
    )
    reuse_count = 65_536
    new_generation = (old.generation + reuse_count) & 0xFFFF
    new_owner = 0x2A
    new_sequence = 0x000000000001FFFE
    return EvidenceReplay(
        old_ticket=old,
        new_generation=new_generation,
        new_owner_id=new_owner,
        new_full_sequence=new_sequence,
        reuse_count=reuse_count,
        truncated_match=(old.generation == new_generation and old.owner_id == new_owner),
        full_identity_match=(
            old.generation == new_generation
            and old.owner_id == new_owner
            and old.full_sequence == new_sequence
        ),
    )


def _format_trace(result: SearchResult) -> str:
    lines = [
        f"explored states: {result.explored_states}",
        f"depth bound:     {result.depth_bound}",
        f"violation:       {result.violation or 'none within bound'}",
    ]
    if result.trace:
        lines.append("counterexample:")
        for index, step in enumerate(result.trace, 1):
            state = step.state
            lines.append(
                f"  {index:02d}. {step.action:16s} state={state.slot_state.name:10s} "
                f"gen={state.generation} owner={state.owner_id} seq={state.slot_sequence} "
                f"irp={state.occupant} completions={state.completions[1:]}"
            )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generation-bits", type=int, default=1)
    parser.add_argument("--owner-bits", type=int, default=1)
    parser.add_argument("--max-irps", type=int, default=3)
    parser.add_argument("--max-depth", type=int, default=18)
    args = parser.parse_args(argv)

    defective = ModelConfig(
        fixed=False,
        generation_bits=args.generation_bits,
        owner_bits=args.owner_bits,
        max_irps=args.max_irps,
        max_depth=args.max_depth,
    )
    fixed = replace(defective, fixed=True)
    print("Defective model (bounded BFS)")
    print(_format_trace(search(defective)))
    print("\nCorrected model (bounded BFS)")
    print(_format_trace(search(fixed)))

    replay = reproduce_evidence_identity_collision()
    print("\n16-bit evidence replay")
    print(f"  reuse count:             {replay.reuse_count}")
    print(f"  truncated ticket match:  {replay.truncated_match}")
    print(f"  full identity match:     {replay.full_identity_match}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
