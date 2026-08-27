# Validation plan

## Reproducible local gate

From the repository root:

```bash
python3 -m compileall -q answer
python3 -m unittest discover -s answer/tests -p "test_*.py" -v
git diff --check
```

The suite has no network, Windows, driver, timing, or absolute-path dependency.
GitHub Actions repeats the compile and test commands on Python 3.10, 3.11, and
3.12.

## Requirement-to-test mapping

| Requirement | Primary test module |
|---|---|
| CTL_CODE field extraction and construction | `test_ioctl.py` |
| V2 offsets, bounds, versions, backing/input distinction | `test_hello.py` |
| ABA counterexample and corrected bounded invariants | `test_ring_model.py` |
| OCVM format, branch targets, faults, and fuel | `test_ocvm.py` |
| Relocation parsing, byte normalization, and digest equality | `test_relocations.py` |

## Tool smoke tests

Valid vectors:

```bash
python3 answer/tools/decode_ioctl.py 0x8337E404
python3 answer/tools/decode_hello.py --simulate-defective
python3 answer/tools/model_ring.py
python3 answer/tools/ocvm_disasm.py
python3 answer/tools/ocvm_reference.py
python3 answer/tools/normalize_relocations.py --delta 0x12345000
```

Representative malformed vectors must fail nonzero and explain the rejected
contract:

```bash
python3 answer/tools/decode_ioctl.py 0x100000000
python3 answer/tools/decode_hello.py --hex 4f434c4b
python3 answer/tools/ocvm_disasm.py --hex 00
```

## Model interpretation gate

Before publishing results, verify that language matches what was tested:

- defective ring model: “counterexample found within bound”;
- corrected ring model: “no violation found within stated bound”;
- never “universally proven safe”;
- relocation digest values belong to generated synthetic bytes;
- VM results cover only supplied opcodes;
- no claim of real binary execution, dump analysis, or artifact hashing.

## Windows source-integration plan

If source and a signed lab build later become available, add a separate,
isolated Windows VM pipeline:

1. Build with warnings-as-errors and static analysis.
2. Run user/kernel protocol tests from native x64 and WOW64 clients.
3. Enable Driver Verifier only for the synthetic target driver.
4. Stress cancellation, reconnect, generation wrap simulation, shutdown, and
   concurrent close.
5. Capture kernel dumps for any verifier or timeout failure.
6. Compare integrity baselines across preferred and randomized image bases.
7. Verify policy rejection and fuel behaviour with benign programs.

This future plan does not authorize testing on a production endpoint or an
unrelated driver.

## Exit criteria

- All Python sources compile.
- Every regression test passes from an arbitrary clone path.
- Every valid smoke tool exits zero.
- Every malformed smoke vector exits nonzero.
- `git diff --check` reports no whitespace errors.
- Documentation contains `0x901`–`0x904`, not the former incorrect IOCTL
  function values.
- No hard-coded `/workspace` import remains.
- All missing reports and the Turkish final report exist.
- Repository status contains only intentional source/documentation changes.

Exact command output and test count are recorded in the change handoff rather
than fabricated in advance.
