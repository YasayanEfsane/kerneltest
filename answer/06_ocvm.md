# OCVM2 validator/interpreter reconstruction

## Supplied format

**FACT — `[E-VM-01]`:** instructions are eight bytes.  Opcode is byte zero.
Opcode `0x31` is a relative branch whose signed 24-bit displacement occupies
bytes two through four.

Only these opcodes are identified by the capsules and safe model:

| Opcode | Analyst mnemonic | Model behaviour |
|---:|---|---|
| `0x00` | `NOP` | Advance one instruction |
| `0x10` | `LOAD` | Operand semantics unknown; advance for control-flow model |
| `0x31` | `BRANCH` | Relative signed branch |
| `0x7F` | `HALT` | Normal termination |

The full VM header, registers, memory model, and remaining opcode set are
**UNKNOWN**.

## Unit disagreement

The validator uses instruction indices `[E-VM-02]`:

```text
target_index = current_index + 1 + sign_extend24(rel)
```

The historical interpreter uses bytes `[E-VM-03]`:

```text
target_byte = current_byte + 8 + sign_extend24(rel)
```

For the branch at instruction index 1 (`byte 0x08`) with `rel = +1`:

```text
validator: 1 + 1 + 1 = instruction 3 = byte 0x18
interpreter: 0x08 + 8 + 1 = byte 0x11
```

Byte `0x11` is inside the instruction beginning at `0x10`, matching the
reported invalid-opcode fault `[E-VM-04]`.

## Canonical semantics

`answer/tools/ocvm_common.py` supplies one target function used during full
program validation.  The reference interpreter executes the validated target
index stored on each branch instruction.  Required checks are:

1. Program is nonempty and length is divisible by eight.
2. Instruction count does not exceed 1,024 in the model.
3. Every opcode is known to the reconstructed subset.
4. A 24-bit field is read from exactly three bytes.
5. Sign extension maps `0x800000` to `-0x800000` and `0xFFFFFF` to `-1`.
6. Every branch target is in the instruction-index range before execution.
7. Execution has a fuel limit.
8. HALT is normal status, distinct from faults.

The disassembler parses the complete static program even if an earlier HALT is
present; stopping at the first HALT would hide trailing bytes that a branch
might reach.

## Benign evidence program

```text
index 0, byte 0x00: LOAD
index 1, byte 0x08: BRANCH +1
index 2, byte 0x10: NOP
index 3, byte 0x18: HALT
```

The corrected reference execution is `LOAD -> BRANCH -> HALT`, takes three
steps, and terminates at byte `0x18`.  The historical byte calculation is shown
for comparison only; no unsafe policy is generated.

## Validation coverage

`answer/tests/test_ocvm.py` covers exact three-byte reads, signed boundaries,
positive and negative targets, before-start and beyond-end branches, unknown
opcodes, malformed lengths, instruction limits, trailing instructions after
HALT, falling off the program, and fuel exhaustion on a benign loop.

Passing these tests validates the reconstructed subset and the proposed shared
semantics.  It does not establish behaviour for opcodes or headers absent from
the evidence.
