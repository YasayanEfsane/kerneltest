# Defensive patch design

These are semantic source-level designs.  No original source or binary is
available, so offsets cannot be patched and the pseudocode cannot be claimed to
compile against a specific WDK project.

## 1. Preserve the V2 wire contract

```c
bool ParseHelloV2(
    const uint8_t *input,
    size_t inputLength,
    OC_HELLO_VALUE *out)
{
    if (input == NULL || out == NULL || inputLength != 0x1C)
        return false;
    if (ReadLe32(input + 0x00) != OCLK_MAGIC ||
        ReadLe16(input + 0x04) != 2 ||
        ReadLe16(input + 0x06) != 0x1C)
        return false;

    out->ProcessId    = ReadLe32(input + 0x08);
    out->ClientNonce  = ReadLe64(input + 0x0C);
    out->Capabilities = ReadLe32(input + 0x14);
    out->HeaderCrc    = ReadLe32(input + 0x18);
    return true;
}
```

The dispatch routine passes the IRP stack's actual input length, never a system
buffer allocation length.  CRC validation is added only after its wire
algorithm is specified.  A 32-byte format requires `Version == 3` and a new
documented layout.

Telemetry: version, declared size, actual input length, rejection reason, and a
nonsecret correlation ID.  Do not log nonce or raw policy contents.

## 2. Couple ring identity to lifetime

Conceptual objects:

```c
typedef struct {
    uint64_t OccupantSequence;
    uint64_t SessionEpoch;
    REQUEST *Request;              // referenced while cancel actor exists
    uint32_t SlotIndex;
} CANCEL_TICKET;

typedef enum {
    TERMINAL_NONE,
    TERMINAL_NORMAL,
    TERMINAL_CANCEL
} TERMINAL_OWNER;
```

Reservation:

```c
slot->Sequence = InterlockedIncrement64(&ring->NextSequence);
slot->Request = ReferenceRequest(request);
slot->TerminalOwner = TERMINAL_NONE;
WritePayload(slot);
PublishReadyWithRelease(slot);
```

Terminal paths:

```c
if (CompareExchange(&request->TerminalOwner, mine, TERMINAL_NONE)
        == TERMINAL_NONE) {
    CompleteRequestExactlyOnce(request, status);
}
```

Cancellation first compares slot index, full sequence, session epoch, and
request identity.  A mismatch only drops the cancel reference.  Slot reuse is
enabled after both conditions hold:

```text
terminal owner selected
AND cancellation/reference rundown is zero
```

Acquire/release state publication must be mapped to documented Windows
interlocked/barrier semantics during implementation.  A larger counter without
cancel detachment is not sufficient.

Telemetry: full sequence, state transition, terminal winner, cancel-reference
count, session epoch, and rejected stale-ticket count.

## 3. Close outside the session resource

```c
AcquireExclusive(SessionResource);
switch (session->State) {
case ACTIVE:
    session->State = CLOSING;
    BeginRundownAndRejectNewWork(session);
    TakeReference(session);
    QueueDrain(session);
    break;
case CLOSING:
    TakeReference(session);
    break;
case FINALIZED:
    Release(SessionResource);
    return already_closed;
}
Release(SessionResource);

wait = BoundedWaitForRundown(session);  // no ERESOURCE held

AcquireExclusive(SessionResource);
if (wait == complete && session->State == CLOSING &&
    session->Outstanding == 0 && TryBecomeFinalizer(session)) {
    session->State = FINALIZED;
    RemoveFromLookup(session);
}
Release(SessionResource);
ReleaseReference(session);
```

Timeout means “diagnose and preserve ownership”, not “free anyway”.  All
shutdown and service-disconnect paths must use the same state transition and
finalizer gate.

## 4. Share OCVM branch semantics

```c
bool CalculateTarget(
    size_t currentIndex,
    int32_t rel24,
    size_t instructionCount,
    size_t *targetIndex)
{
    checked_signed target = currentIndex + 1 + rel24;
    if (target < 0 || target >= instructionCount)
        return false;
    *targetIndex = (size_t)target;
    return true;
}
```

The verifier calls this function for every branch.  Execution uses the
validated index and multiplies by instruction width only when locating bytes.
Program length, instruction count, opcode, branch target, and execution fuel
are all fail-closed.  No separate byte-relative implementation remains.

Telemetry: policy version, instruction count, validator rejection category,
runtime fault category, and executed-step count without policy payload bytes.

## 5. Dispatch relocation types explicitly

```c
for each block {
    ValidateBlockHeaderAndBounds(block);
    for each entry {
        switch (entry.Type) {
        case IMAGE_REL_BASED_ABSOLUTE:
            continue;
        case IMAGE_REL_BASED_DIR64:
            site = CheckedMappedRva(block.PageRva, entry.Offset, 8);
            RejectDuplicateOrOverlap(site);
            NormalizeQwordModulo64(site, imageDelta);
            break;
        default:
            return unsupported_relocation;
        }
    }
}
```

Hash only a documented mapped representation and explicit ranges.  Baseline
generation and runtime calculation must use the same section selection,
zero-fill, ordering, and relocation rules.

Telemetry: relocation block/entry counts, skipped padding, normalized DIR64
count, first structural error RVA, selected-range identifiers, and digest match
result.  Avoid logging raw executable pages.

## IRQL and synchronization review gate

| Operation | Semantic requirement before implementation |
|---|---|
| Buffer parsing and policy validation | Run where pageable parser code and required allocations are permitted |
| Ring publication/cancel transition | Nonblocking operations appropriate to actual caller IRQL; documented atomic ordering |
| IRP completion | Exactly one terminal owner; obey cancel routine protocol |
| Session rundown wait | PASSIVE-level blocking context and no driver-owned resource held |
| Image parsing/hash | Stable mapped-image lifetime and a context where hashing work is legal |

Exact IRQL annotations are **UNKNOWN** without source and call sites; they must
be established in the real project rather than copied from this model.

## Compatibility and rollout

1. Ship the V2 parser fix without changing its bytes.
2. Gate an optional V3 format through explicit negotiation.
3. Add diagnostic counters before enabling the new ring lifetime protocol.
4. Stress old/new service reconnect and cancel behaviour in an isolated VM.
5. Compare integrity results in report-only mode before enforcing them.
6. Enable enforcement only after verifier, shutdown, and upgrade tests pass.
