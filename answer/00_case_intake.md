# 00_case_intake.md - Obsidian Clock Case Intake

## 1. Operating Mode

**EVIDENCE-CAPSULE MODE**

The directory `/case/obsidian_clock/` does not exist. All analysis must proceed using only the evidence capsules provided in the case prompt. No actual binary execution, WinDbg sessions, IDA/Ghidra disassembly, or direct artifact inspection has been performed. All observations are derived from the textual evidence capsules `[E-PE-*]`, `[E-IO-*]`, `[E-RING-*]`, `[E-LOCK-*]`, `[E-VM-*]`, `[E-INT-*]`, and `[E-RH-*]`.

## 2. Available Evidence

### Available (from evidence capsules):
- **PE Metadata**: Machine type, subsystem, image size, GuardCF/CET status, relocation/exception directories `[E-PE-01]`
- **Import Table**: ntoskrnl.exe and fltmgr.sys imports `[E-PE-02]`
- **Initialization Behavior**: Device creation, symbolic link, minifilter registration, ring allocation `[E-PE-03]`
- **Compilation Characteristics**: Tail merging, inlining, CFG dispatch `[E-PE-04]`
- **IOCTL Jump Table**: Four codes with RVAs `[E-IO-01]`
- **IOCTL Semantics**: High-level behavior descriptions `[E-IO-02]`
- **V2 Wire Declaration**: 32-bit WOW64 client structure `[E-IO-03]`
- **Negotiation Packet**: Raw bytes and service interpretation `[E-IO-04]`
- **Driver-side Decompilation**: Version check, field extraction logic `[E-IO-05]`
- **Correlated Trace**: Input/output lengths, observed driver field values `[E-IO-06]`
- **Ring Slot Metadata**: 64-bit layout, states, CAS operations `[E-RING-01]`
- **Ticket Format**: SlotIndex, Generation, OwnerId `[E-RING-02]`
- **Cancellation Comparison**: Logic without FullSequence check `[E-RING-03]`
- **Stress Timeline**: Slot 37 reuse scenario `[E-RING-04]`
- **Verifier Summary**: Double completion bugcheck paths `[E-RING-05]`
- **Implementation Property**: Slot reuse without cancel detachment `[E-RING-06]`
- **Close Thread State**: T41 holds exclusive lock, waits on drain event `[E-LOCK-01]`
- **Drain Worker State**: T73 waits for shared lock to decrement counter `[E-LOCK-02]`
- **Close Behavior**: Pseudocode showing lock-hold-while-waiting `[E-LOCK-03]`
- **User-mode State**: Service blocked in DeviceIoControl `[E-LOCK-04]`
- **VM Instruction Observations**: 8-byte instructions, opcode 0x31 branch `[E-VM-01]`
- **VM Validator Decompilation**: Target index calculation `[E-VM-02]`
- **VM Interpreter Decompilation**: Byte offset calculation `[E-VM-03]`
- **Minimal Accepted Policy**: Raw bytes, validator vs interpreter divergence `[E-VM-04]`
- **Integrity Algorithm**: Normalization approach, ASLR delta `[E-INT-01]`
- **Relocation Block**: Page RVA, entries `[E-INT-02]`
- **Normalizer Fragment**: Type checking logic `[E-INT-03]`
- **Integrity Trace**: Divergence conditions `[E-INT-04]`
- **Red Herrings**: Three suspicious but unproven observations `[E-RH-01]` through `[E-RH-03]`

### Missing Evidence:
- Actual binary files for hash verification
- Raw crash dump contents beyond summaries
- Full ETL trace data beyond correlated excerpts
- Complete PE section headers and relocation tables
- Source code for any component
- Registry hive contents beyond file existence
- Public protocol header file content

## 3. Integrity Verification Status

**NOT APPLICABLE TO INPUT ARTIFACTS** - No physical case artifacts exist to
hash.  All case evidence is provided as textual capsules, so an input
chain-of-custody digest cannot be reconstructed.  Repository files remain
versioned by Git; that is not a substitute for missing evidence hashes.

## 4. Initial Architecture Hypothesis

Based on evidence capsules, `ObsidianClock.sys` appears to be a Windows kernel-mode telemetry/policy driver with:

1. **Device Control Plane**: A standard WDM device (`\Device\ObClock`) with four primary IOCTLs for session management, policy submission, counter retrieval, and session closure.

2. **Minifilter Communication Plane**: Uses FLTMGR for filesystem filtering or communication, with a user-mode port for message passing.

3. **Session Management**: Tracks client sessions with a shared resource lock (`g_SessionResource`) and supports concurrent access via an ERESOURCE.

4. **Event Ring Buffer**: A 256-slot lock-free ring buffer for high-throughput event publication, using CAS operations for state transitions and ticket-based cancellation.

5. **Policy Virtual Machine**: An embedded bytecode interpreter (OCVM2) for executing uploaded policy programs, with separate validation and execution paths.

6. **Self-Integrity Mechanism**: Runtime hashing of relocated image sections to detect tampering, comparing against a baseline generated at preferred base.

**Primary Defect Hypotheses:**
- **H1 (ABI Drift)**: WOW64 struct packing mismatch causes session identifier corruption `[E-IO-03]` through `[E-IO-06]`
- **H2 (ABA Problem)**: Ring slot reuse with insufficient ticket identity causes double IRP completion `[E-RING-02]` through `[E-RING-05]`
- **H3 (Lock Ordering)**: Close path holds exclusive lock while waiting for operation that requires shared lock `[E-LOCK-01]` through `[E-LOCK-04]`
- **H4 (Unit Mismatch)**: VM validator uses instruction indices while interpreter uses byte offsets for branch targets `[E-VM-02]` through `[E-VM-04]`
- **H5 (Type Handling)**: Relocation normalizer incorrectly processes padding entries as data `[E-INT-02]` through `[E-INT-04]`

## 5. Investigation Plan

### Phase A - Evidence Intake (Completed)
- Document operating mode and evidence availability
- Create evidence ledger with all capsule references
- Establish initial architecture hypothesis

### Phase B - Architecture Reconstruction (Completed)
- Document driver lifecycle from entry to unload
- Map device control dispatch table
- Document session state machine
- Document ring buffer state machine
- Produce Mermaid diagrams for components

### Phase C - IOCTL/ABI Analysis (Completed)
- Decode all four IOCTL codes mathematically
- Reconstruct V2 negotiation packet byte-by-byte
- Explain WOW64 packing effects
- Implement decode_ioctl.py and decode_hello.py
- Write comprehensive tests

### Phase D - Ring Lifetime Analysis (Completed as bounded model)
- Define formal invariants
- Construct failing interleaving trace
- Implement model_ring.py with ABA reproduction
- Design corrected ownership/cancellation protocol
- Verify that the corrected model has no violation within its declared bound

### Phase E - Deadlock Analysis (Completed as design analysis)
- Construct wait-for graph
- Prove cycle existence
- Design corrected close protocol
- Specify regression tests

### Phase F - OCVM2 Reconstruction (Completed for supplied opcode subset)
- Implement ocvm_disasm.py
- Implement ocvm_reference.py
- Demonstrate validator/interpreter divergence
- Write test_ocvm.py

### Phase G - Integrity Analysis (Completed on synthetic mapped bytes)
- Model relocation parsing
- Demonstrate normalization defect
- Implement normalize_relocations.py
- Write test_relocations.py

### Phase H - Red Herring Control (Completed)
- Address each `[E-RH-*]` item
- Justify classification

### Final Deliverables
- Root cause matrix
- Patch designs
- Validation plan
- Turkish final report

## 6. Completion status

The evidence ledger, focused reports, safe tools, regression tests, patch design,
validation plan, and Turkish final report are present.  Their conclusions remain
bounded by the missing-artifact statement above.

---
*All case evidence is sourced from the provided capsules. No external case
artifacts were accessed.*
