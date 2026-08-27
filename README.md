# Project Obsidian Clock

Obsidian Clock is a **synthetic evidence-capsule benchmark** for Windows kernel
reverse-engineering reasoning.  It contains no Windows driver, PDB, crash dump,
ETL trace, certificate, or production target.  The repository turns the textual
case evidence into auditable reports, safe parsers, bounded state models, and
regression tests.

The project is defensive and educational.  It does not contain exploit code,
kernel shellcode, a loader, a privilege-escalation primitive, persistence, or a
security-control bypass.

## What the case tests

The supplied capsules describe five independent defect classes:

| Area | Evidence-backed defect |
|---|---|
| V2 control protocol | A packed 28-byte WOW64 packet is read with 32-byte native offsets, and backing-buffer size is confused with actual input length. |
| Ring lifetime | A 16-bit generation plus reusable owner ID permits an ABA identity collision while stale cancellation authority remains attached. |
| Session close | The close path waits for a drain event while holding the resource required by the only thread that can signal it. |
| OCVM2 policy VM | Validation interprets a signed relative displacement in instruction units; execution uses it as bytes. |
| Image integrity | `IMAGE_REL_BASED_ABSOLUTE` padding is processed as if it were a `DIR64` relocation. |

The three suspicious observations in `[E-RH-*]` are deliberately insufficient
to establish malware or tampering.

## Evidence boundary

All conclusions are limited to the textual evidence catalogued in
[`answer/01_evidence_ledger.md`](answer/01_evidence_ledger.md).  In particular:

- no binary was disassembled;
- no WinDbg, IDA, or Ghidra session was performed;
- no input-artifact SHA-256 values can be verified;
- generated Python models validate the stated mechanics, not an unseen driver;
- bounded state exploration is not a universal formal proof.

Statements in the reports are labelled `FACT`, `DERIVED`, `INFERENCE`,
`HYPOTHESIS`, or `UNKNOWN` according to that boundary.

## Repository map

```text
answer/
├── 00_case_intake.md
├── 01_evidence_ledger.md
├── 02_architecture.md
├── 03_ioctl_abi.md
├── 04_ring_lifetime.md
├── 05_deadlock.md
├── 06_ocvm.md
├── 07_integrity.md
├── 08_root_cause_matrix.md
├── 09_patch_design.md
├── 10_validation_plan.md
├── final_report_tr.md
├── tools/
│   ├── decode_ioctl.py
│   ├── decode_hello.py
│   ├── model_ring.py
│   ├── ocvm_common.py
│   ├── ocvm_disasm.py
│   ├── ocvm_reference.py
│   └── normalize_relocations.py
└── tests/
    ├── test_ioctl.py
    ├── test_hello.py
    ├── test_ring_model.py
    ├── test_ocvm.py
    └── test_relocations.py
```

The consolidated Turkish analysis is
[`answer/final_report_tr.md`](answer/final_report_tr.md).

## Quick start

Python 3.10 or newer is sufficient; runtime tools use only the standard library.

```bash
python3 -m compileall -q answer
python3 -m unittest discover -s answer/tests -p "test_*.py" -v
```

The same commands run in GitHub Actions on Python 3.10, 3.11, and 3.12.

## Tool examples

Decode all four case IOCTLs:

```bash
python3 answer/tools/decode_ioctl.py
```

Compare the canonical V2 packet with the evidence-defined defective reads:

```bash
python3 answer/tools/decode_hello.py --simulate-defective
```

Search the reduced ring model and replay the exact 16-bit identity collision:

```bash
python3 answer/tools/model_ring.py
```

Disassemble and execute the benign OCVM2 evidence program:

```bash
python3 answer/tools/ocvm_disasm.py
python3 answer/tools/ocvm_reference.py
```

Compare correct and defective relocation normalization on synthetic mapped bytes:

```bash
python3 answer/tools/normalize_relocations.py
```

Each command supports `--help`.  Malformed-input examples and boundary cases are
covered by the regression suite.

## Model interpretation

The tools intentionally separate three kinds of result:

1. **Evidence reproduction:** deterministic calculations directly implied by a
   capsule, such as IOCTL fields or the misread nonce.
2. **Synthetic validation:** safe byte arrays and state models used to show the
   described mechanism.
3. **Proposed repair:** a design whose regression properties are checked in the
   model, but which cannot be claimed as a compiled driver patch without source.

This distinction prevents a passing Python test from being presented as proof
about an artifact that is not present.

## License

The repository is available under the [MIT License](LICENSE).
