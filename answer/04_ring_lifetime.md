# Ring identity, cancellation, and IRP lifetime

## Evidence facts

- A slot metadata word contains state, a 16-bit generation, and a 32-bit owner
  ID `[E-RING-01]`.
- A cancellation ticket retains slot index, generation, and owner ID but not
  the ring's 64-bit `FullSequence` `[E-RING-02]`.
- Cancellation compares only generation and owner `[E-RING-03]`.
- Owner IDs can be reused after reconnect, and a slot can return to `FREE`
  before every old cancellation context is detached `[E-RING-04]`,
  `[E-RING-06]`.
- Driver Verifier reports the same logical failure reaching two
  `IofCompleteRequest` stacks `[E-RING-05]`.

## Identity collision

The effective historical identity is:

```text
(slot_index, generation mod 2^16, owner_id mod 2^32)
```

It is not unique over time.  In the supplied trace:

```text
old generation = 0xFFFE
reuse count     = 65,536 = 2^16
new generation = (0xFFFE + 2^16) mod 2^16 = 0xFFFE
old owner       = 0x2A
new owner       = 0x2A after allocator reuse
```

The truncated ticket matches even though:

```text
old FullSequence = 0x000000000000FFFE
new FullSequence = 0x000000000001FFFE
```

That is the ABA condition: the visible identity returns to A while the object
occupying the slot is different.

## Cause-to-effect chain

1. Request A occupies slot 37 and queues a cancellation actor.
2. A different terminal path completes A.
3. The slot is freed even though A's cancellation actor remains authoritative.
4. Reuse wraps the 16-bit generation; reconnect reuses the owner ID.
5. Request B now presents the same truncated metadata as A.
6. A's delayed cancellation passes the generation/owner check and transitions
   B's slot.
7. The cancel path completes B.
8. The normal drain path also completes B, producing `[E-RING-05]`.

Compare-and-exchange does not by itself solve ABA.  CAS can atomically confirm
that the bits equal A; it cannot determine whether those same bits describe the
same lifetime that was observed earlier.

## Executable bounded model

`answer/tools/model_ring.py` represents reserve, publish, queue/detach/execute
cancel, consume, terminal completion, free, disconnect, and reconnect as
immutable transitions.  Breadth-first search discovers a counterexample rather
than returning a prepared result.

For practical exhaustive exploration, regression tests use a one-bit
generation and at most three IRPs.  The shortest discovered pattern is:

```text
reserve A -> publish -> queue A cancel -> normal complete A -> unsafe free
reserve intermediate -> publish -> complete -> free
reserve B after wrap -> publish
execute A cancel against B -> normal complete B -> invariant violation
```

The separate 16-bit replay performs the exact `65,536`-reuse arithmetic from
the capsule.  This combination demonstrates the mechanism; it is not a
universal proof about all possible kernel schedules.

## Required invariants

1. An IRP has at most one terminal completion.
2. Each terminal transition has one linearization point.
3. A slot is not reusable while any actor retains cancellation authority for
   its occupant.
4. A ticket names one occupant for its entire validity interval.
5. Owner reconnect cannot revive old authority.
6. Generation wrap cannot turn a stale ticket into a current ticket.
7. Payload bytes become visible before `READY` becomes visible.
8. Final reference release occurs after cancel detachment and terminal winner
   selection.

## Corrected design

A robust correction combines identity and lifetime; merely widening the
generation is insufficient.

```text
Ticket = {
    slot_index,
    full_occupant_sequence,
    session_epoch,
    request_reference
}
```

- Reservation assigns a monotonically increasing 64-bit occupant sequence.
- A session epoch is not immediately reused after reconnect.
- Publication writes payload first and then performs a release transition to
  `READY`; consumption observes state with acquire semantics.
- Normal and cancellation paths compete for one atomic terminal state.
- The winner owns the only IRP completion.
- Every queued cancel actor holds an explicit request/slot reference.
- A slot may return to `FREE` only after terminal completion and cancellation
  detachment/rundown both reach zero.
- A stale full-sequence mismatch only detaches its actor; it cannot touch the
  current occupant.

The corrected bounded model enforces these rules.  Within the declared search
bound it finds no repeated completion, while the defective model finds one.

## Regression evidence

`answer/tests/test_ring_model.py` checks:

- automatic counterexample discovery;
- presence of a stale-ticket step;
- absence of a bounded violation in the corrected model;
- blocked reuse while cancel authority is attached;
- losing terminal actor behaviour;
- reduced-width generation and owner wrap;
- exact 16-bit evidence arithmetic;
- payload publication ordering.

Residual risk remains: a Python state model does not establish the exact
Windows memory barriers, cancel-spin-lock protocol, or IRP reference operations
of source code that is not available.
