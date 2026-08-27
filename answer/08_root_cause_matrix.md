# Root-cause proof matrix

The five symptoms do not require one hidden adversary.  The evidence supports
five defect classes in separate protocol, lifetime, synchronization, VM, and
image-normalization paths.

| Defect | Trigger | Incorrect contract or transition | Cause-to-effect mechanism | Evidence | Weaker alternative rejected | Corrective design | Regression evidence | Residual risk | Confidence |
|---|---|---|---|---|---|---|---|---|---:|
| V2 ABI and length | Packed 28-byte V2 input with larger buffered-I/O backing allocation | Native offsets `0x10/0x18/0x1C` are used for fields at `0x0C/0x14/0x18`; allocation size substitutes for input length | Upper nonce bytes and capabilities form the observed nonce; CRC becomes capabilities; bytes outside input become CRC | `[E-IO-03]`–`[E-IO-06]` | Random corruption does not predict all three exact values or the 64-bit diagnostic difference | Preserve explicit 28-byte V2 serialization; validate actual input length; version any 32-byte successor | `test_hello.py`, `test_ioctl.py` | CRC algorithm and other request structures unknown | High |
| Ring ABA and cancel lifetime | Stale cancel survives slot reuse; generation wraps; owner ID is reused | Slot returns to `FREE` before cancel detachment; ticket omits full occupant identity | Old ticket matches B's truncated metadata, cancel completes B, normal path completes B again | `[E-RING-01]`–`[E-RING-06]` | CAS atomicity alone cannot distinguish equal bits from different lifetimes | 64-bit occupant sequence, session epoch, explicit request reference, one terminal CAS, defer reuse until rundown | `test_ring_model.py` automatic counterexample and corrected bounded search | Python model cannot establish exact WDM cancellation barriers | High |
| Close/drain deadlock | Close while one record remains | T41 waits while holding the resource required by T73 | T41 waits event; only T73 can signal; T73 waits resource held by T41 | `[E-LOCK-01]`–`[E-LOCK-04]` | A slow worker would eventually progress; this worker is structurally unable to acquire its prerequisite | Mark closing under lock, begin rundown, release lock, wait outside, single finalizer | Regression matrix in `05_deadlock.md` | Exact reference primitive and all lock orders unknown | High |
| OCVM unit mismatch | Accepted branch with nonzero relative displacement | Validator uses instruction indices; interpreter adds displacement as bytes | Branch `+1` validates to index 3/byte `0x18` but executes at byte `0x11`, producing invalid opcode | `[E-VM-01]`–`[E-VM-04]` | Corrupt policy bytes do not explain deterministic validator/interpreter calculations | Shared instruction-index target helper, full prevalidation, alignment by construction, execution fuel | `test_ocvm.py` | Full opcode and header format absent | High |
| Relocation false positive | Nonzero ASLR delta and block padding | Predicate `type <= DIR64` treats `ABSOLUTE` as a qword relocation | Two zero padding entries normalize page RVA `0xA000`; digest diverges only when delta is nonzero | `[E-INT-01]`–`[E-INT-04]` | External code modification is weakened by correct-relocation equality and preferred-base behaviour | Strict block bounds, explicit type dispatch, skip ABSOLUTE, normalize only unique DIR64 sites | `test_relocations.py` | Real hash and selected sections unknown | High |

## Red-herring control

| Evidence | Weakest justified statement | Evidence needed for a stronger claim | Why it is not a root cause |
|---|---|---|---|
| `[E-RH-01]` constant `0x9E3779B9` | An unreachable diagnostic routine contains a constant also seen in several arithmetic constructions | Reachable call graph, inputs/outputs, known-answer vectors, and runtime trace | A constant alone does not establish TEA, encryption, malware, or relevance to any symptom |
| `[E-RH-02]` guarded indirect calls | The PE enables GuardCF and routes indirect calls through the standard guard dispatcher | Evidence of a separate bytecode dispatcher, opaque state, or nonstandard control-flow transformer | CFG dispatch is expected compiler/platform instrumentation and explains the observed thunk |
| `[E-RH-03]` pool tag `KCAH` | One allocation uses four bytes that display as `HACK` under a reversed convention | Allocation semantics, reachable misuse, malicious data flow, and corroborating behaviour | Pool tags are developer-selected diagnostics; suggestive text has no causal path to a symptom |

Misclassifying these observations would divert investigation from reproducible
mechanisms and turn an evidence-capsule exercise into unsupported attribution.

## Proof limitations

The static support in this matrix is capsule pseudocode, not independently
recovered disassembly.  Dynamic support is capsule trace/dump summaries plus
local synthetic models.  Every conclusion should be retested against actual
artifacts if they become available.
