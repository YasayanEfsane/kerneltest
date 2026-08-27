# 01_evidence_ledger.md - Obsidian Clock Evidence Ledger

## Evidence Classification Key

| Label | Meaning |
|-------|---------|
| **FACT** | Directly observable in an artifact or evidence capsule |
| **DERIVED** | Mechanically calculated from facts |
| **INFERENCE** | Best explanation supported by multiple facts |
| **HYPOTHESIS** | Plausible but not yet sufficiently proven |
| **UNKNOWN** | Cannot be determined from available evidence |

---

## PE and Architecture Evidence

### [E-PE-01] PE Metadata
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  - File: ObsidianClock.sys
  - Machine: AMD64
  - Subsystem: Native
  - Preferred ImageBase: 0x140000000
  - SizeOfImage: 0x1D000 (118,784 bytes)
  - Link timestamp: 0
  - Private symbols: absent
  - Rich header: absent
  - GuardCF: enabled
  - CET compatibility: enabled
  - Relocation directory: present
  - Exception directory: present
- **Relevance:** Confirms 64-bit kernel driver with CFG/CET protections, ASLR support via relocations

### [E-PE-02] Relevant Imports
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  - ntoskrnl.exe: IoCreateDevice, IoCreateSymbolicLink, IoCompleteRequest, IoSetCancelRoutine, IoAcquireCancelSpinLock, IoReleaseCancelSpinLock, ExAllocatePool2, ExFreePool, ExInitializeResourceLite, ExAcquireResourceExclusiveLite, ExAcquireResourceSharedLite, ExReleaseResourceLite, KeInitializeEvent, KeSetEvent, KeWaitForSingleObject, KeQueryPerformanceCounter, RtlImageNtHeader, RtlLookupFunctionEntry, __guard_dispatch_icall_fptr
  - fltmgr.sys: FltRegisterFilter, FltStartFiltering, FltCreateCommunicationPort, FltSendMessage
- **Relevance:** Confirms device creation, ERESOURCE synchronization, cancel routine support, minifilter communication

### [E-PE-03] Reachable Initialization Behavior
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:** Entry path creates `\Device\ObClock`, publishes `\DosDevices\ObClock`, installs device-control dispatch routine, registers a minifilter, creates one user-mode communication port, initializes an `ERESOURCE`, allocates a 256-slot shared event ring, and registers a shutdown callback.
- **Relevance:** Establishes driver architecture components

### [E-PE-04] Compilation Characteristics
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:** Control-flow graph contains extensive tail merging, function outlining, inlining, and calls through `__guard_dispatch_icall_fptr`. No evidence establishes that these indirect calls are an obfuscator or anti-analysis mechanism.
- **Relevance:** Explains presence of indirect calls as CFG, not obfuscation

---

## IOCTL and ABI Evidence

### [E-IO-01] Device-control Jump Table
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```
  IOCTL         Target RVA
  0x8337E404    0x000067D0
  0x8337E409    0x00006AE0
  0x8337E40E    0x000071B0
  0x8337E410    0x00007770
  ```
- **Relevance:** Four IOCTL handlers identified; requires mathematical decoding

### [E-IO-02] Observed Behavior
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  - 0x8337E404: establishes or negotiates a session
  - 0x8337E409: submits a policy buffer
  - 0x8337E40E: obtains counters and health information
  - 0x8337E410: closes a session and requests draining
- **Relevance:** Semantic mapping of IOCTL codes

### [E-IO-03] Service-side V2 Wire Declaration
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```c
  #pragma pack(push, 1)
  typedef struct _OC_HELLO_V2_CLIENT {
      uint32_t Magic;        // offset 0x00
      uint16_t Version;      // offset 0x04
      uint16_t HeaderSize;   // offset 0x06
      uint32_t ProcessId;    // offset 0x08
      uint64_t ClientNonce;  // offset 0x0C
      uint32_t Capabilities; // offset 0x14
      uint32_t HeaderCrc;    // offset 0x18
  } OC_HELLO_V2_CLIENT;
  #pragma pack(pop)
  ```
  - Service sends `HeaderSize = 0x1C` (28 bytes)
  - Client is 32-bit WOW64 process
- **Relevance:** Defines wire format; packing directive ensures no padding

### [E-IO-04] Negotiation Packet
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```
  Offset  Bytes
  00      4f 43 4c 4b        ("OCLK" magic)
  04      02 00              (Version = 2)
  06      1c 00              (HeaderSize = 0x1C)
  08      d2 04 00 00        (ProcessId = 1234)
  0c      88 77 66 55 44 33 22 11 (ClientNonce = 0x1122334455667788)
  14      05 00 00 00        (Capabilities = 5)
  18      9a 6d 2e 41        (HeaderCrc = 0x412E6D9A)
  ```
  - Total packet size: 0x1C (28 bytes)
- **Relevance:** Actual transmitted bytes for analysis

### [E-IO-05] Relevant Driver-side Decompilation
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```c
  if (header->Version == 2) {
      if (header->HeaderSize < 0x1C)
          return STATUS_INFO_LENGTH_MISMATCH;

      pid   = *(uint32_t *)(buffer + 0x08);
      nonce = *(uint64_t *)(buffer + 0x10);
      caps  = *(uint32_t *)(buffer + 0x18);
      crc   = *(uint32_t *)(buffer + 0x1C);

      return CreateSession(pid, nonce, caps, crc);
  }
  ```
  - Dispatch validates allocated buffered-I/O system buffer size (max of input/output lengths)
  - Does NOT validate every read against actual input length
- **Relevance:** Driver reads at different offsets than client structure; potential ABI mismatch

### [E-IO-06] Correlated Trace
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```
  InputBufferLength       = 0x1C
  OutputBufferLength      = 0x40
  Packet ClientNonce      = 0x1122334455667788
  Driver observed nonce   = 0x0000000511223344
  Driver observed caps    = 0x412E6D9A
  Driver observed crc     = 0x00000000
  IRP status              = STATUS_SUCCESS
  ```
  - 64-bit diagnostic client using naturally aligned fields does not reproduce the anomaly
- **Relevance:** Demonstrates field misinterpretation; WOW64 vs native alignment issue

---

## Ring Buffer and Cancellation Evidence

### [E-RING-01] Recovered Slot Metadata
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  - 256 slots, each with 64-bit metadata word
  - bits 0..15: state
  - bits 16..31: generation
  - bits 32..63: owner_id
  - States: 0=FREE, 1=RESERVED, 2=READY, 3=CONSUMING, 4=CANCELLED
  - Terminal-state changes use 64-bit CAS
- **Relevance:** Lock-free ring design; limited identity space

### [E-RING-02] Ticket Format
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```c
  typedef struct _OC_TICKET {
      uint16_t SlotIndex;
      uint16_t Generation;
      uint32_t OwnerId;
  } OC_TICKET;
  ```
  - Ring maintains monotonically increasing 64-bit `FullSequence`
  - `FullSequence` NOT stored in ticket, NOT checked by cancellation path
- **Relevance:** Ticket lacks full sequence; ABA vulnerability

### [E-RING-03] Cancellation Comparison
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```c
  slot = &Ring[ticket->SlotIndex];
  meta = ReadMeta(slot);

  if (MetaGeneration(meta) == ticket->Generation &&
      MetaOwner(meta)      == ticket->OwnerId) {
      CompareExchangeState(slot, CANCELLED);
  }
  ```
  - Owner-ID allocator may reuse ID after service disconnect/reconnect
- **Relevance:** Identity collision possible with generation wrap + owner reuse

### [E-RING-04] Stress Timeline for Slot 37
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```
  Old request:
    slot            = 37
    owner_id        = 0x0000002A
    generation      = 0xFFFE
    full_sequence   = 0x000000000000FFFE
    cancellation work item queued but delayed

  During delay:
    slot 37 is reused 65,536 times
    service disconnects and reconnects
    owner_id 0x2A is reused

  New request:
    slot            = 37
    owner_id        = 0x0000002A
    generation      = 0xFFFE  (wrapped)
    full_sequence   = 0x000000000001FFFE
    state           = READY

  Delayed old cancellation work item now executes.
  ```
- **Relevance:** Exact ABA scenario causing double completion

### [E-RING-05] Verifier Summary
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```
  Bugcheck family: DRIVER_VERIFIER_DETECTED_VIOLATION
  Summary: an IRP was completed more than once

  First terminal path:
    nt!IofCompleteRequest
    ObsidianClock!OcCompleteCancelledRequest+0x6A
    ObsidianClock!OcCancelWorkItem+0x141

  Second terminal path:
    nt!IofCompleteRequest
    ObsidianClock!OcCompleteReadySlot+0x91
    ObsidianClock!OcDrainDpc+0x208
  ```
- **Relevance:** Confirms double completion via two distinct code paths

### [E-RING-06] Important Implementation Property
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:** Returning a ring slot to `FREE` is not presently coupled to proof that every cancellation context referring to the previous occupant has been detached or invalidated.
- **Relevance:** Lifetime management defect; slot reuse before cancel detachment

---

## Shutdown Hang Evidence

### [E-LOCK-01] Closing Thread
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```
  Thread T41
    ObsidianClock!OcCloseSession+0x17B
    ObsidianClock!OcDeviceControl+0x2A0
    nt!IofCallDriver

  State:
    owns g_SessionResource exclusively
    waits on g_DrainEvent
    timeout = infinite
  ```
- **Relevance:** Thread holds exclusive lock while waiting

### [E-LOCK-02] Drain Worker
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```
  Thread T73
    nt!ExpWaitForResource
    ObsidianClock!OcDrainFinalRecord+0xD4
    ObsidianClock!OcDrainWorker+0x188

  State:
    waiting to acquire g_SessionResource shared
    this is the only remaining path capable of decrementing
    OutstandingRecords from 1 to 0 and setting g_DrainEvent
  ```
- **Relevance:** Worker needs shared lock to complete drain and signal event

### [E-LOCK-03] Recovered Close Behavior
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```c
  AcquireExclusive(&g_SessionResource);
  session->State = CLOSING;
  QueueDrainWork(session);
  KeWaitForSingleObject(
      &g_DrainEvent,
      Executive,
      KernelMode,
      FALSE,
      NULL  // infinite timeout
  );
  FinalizeSession(session);
  Release(&g_SessionResource);
  ```
- **Relevance:** Classic lock-holder-waiting-for-lock-dependent-operation pattern

### [E-LOCK-04] User-mode State
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:** The service thread that issued the close IOCTL is blocked inside `DeviceIoControl`. No independent watchdog or timeout can complete the operation.
- **Relevance:** No external actor can break the cycle

---

## Policy Virtual Machine Evidence

### [E-VM-01] Instruction Observations
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  - Instructions are 8 bytes wide
  - Opcode is byte 0
  - Most instructions advance IP by 8
  - Opcode 0x31 is signed relative branch
  - Signed branch displacement occupies bytes 2-4 as 24-bit two's-complement integer
- **Relevance:** Fixed-width instruction encoding

### [E-VM-02] Validator Decompilation
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```c
  int32_t rel = SignExtend24(ReadU24(instruction + 2));
  int64_t target_index = current_index + 1 + rel;

  if (target_index < 0 || target_index >= instruction_count)
      return STATUS_INVALID_IMAGE_FORMAT;
  ```
- **Relevance:** Validator calculates target in **instruction indices**

### [E-VM-03] Interpreter Decompilation
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```c
  case 0x31:
      rel = SignExtend24(ReadU24(ip + 2));
      ip = ip + 8 + rel;
      break;
  ```
- **Relevance:** Interpreter calculates target in **byte offsets**

### [E-VM-04] Minimal Accepted Policy
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```
  Byte offset  Raw instruction
  0x00         10 01 00 00 00 00 00 00
  0x08         31 00 01 00 00 00 00 00  ; branch instruction at index 1
  0x10         00 00 00 00 00 00 00 00  ; instruction index 2
  0x18         7f 00 00 00 00 00 00 00  ; instruction index 3 (HALT?)
  ```
  - Validator accepts branch at instruction index 1, records target as instruction index 3
  - At runtime, execution reaches byte offset 0x11 and raises `OCVM_FAULT_INVALID_OPCODE`
- **Relevance:** Demonstrates validator/interpreter divergence

### [E-VM-05] Safety Restriction
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:** Do not create a malicious policy program or attempt to turn this semantic disagreement into code execution. Demonstrate it only with the supplied benign program and rejection/unit tests.
- **Relevance:** Analysis boundary constraint

---

## Self-Integrity Evidence

### [E-INT-01] Intended Algorithm
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  - Driver hashes selected mapped-image sections after normalizing base relocations
  - Expected digest generated from image normalized to preferred base
  - Runtime ASLR delta: `MappedBase - PreferredBase`
- **Relevance:** Normalization required for correct hashing under ASLR

### [E-INT-02] Relevant Relocation Block
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```
  Page RVA:  0x0000A000
  BlockSize: 0x10 (16 bytes)

  16-bit entries:
    0xA118
    0xA2F0
    0x0000
    0x0000
  ```
  - PE32+ AMD64: type 0xA = IMAGE_REL_BASED_DIR64, type 0 = IMAGE_REL_BASED_ABSOLUTE (padding)
- **Relevance:** Two DIR64 entries, two ABSOLUTE padding entries

### [E-INT-03] Decompiler Fragment
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```c
  type   = entry >> 12;
  offset = entry & 0x0FFF;

  if (type <= IMAGE_REL_BASED_DIR64) {
      uint64_t *p = (uint64_t *)(image + page_rva + offset);
      normalized = *p - image_delta;
      HashBytes(&hash, &normalized, sizeof(normalized));
  }
  ```
- **Relevance:** Type check `type <= DIR64` incorrectly includes ABSOLUTE (type 0)

### [E-INT-04] Integrity Trace
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  ```
  Entries in block             = 4
  DIR64 entries                = 2
  Normalizer-reported entries  = 4
  First divergent hash page    = RVA 0xA000
  Tamper alert disappears when image loads at preferred base
  No divergent executable byte remains after correct relocation handling
  ```
- **Relevance:** Confirms normalization defect, not tampering

---

## Red Herring Evidence

### [E-RH-01] Constant 0x9E3779B9
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  - Function contains constant `0x9E3779B9` and rotate/XOR operations
  - Only known cross-reference is unregistered diagnostic self-test descriptor
  - No reachable production path to this function has been established
- **Relevance:** Suggestive but not proven malicious; likely TEA-related diagnostic code

### [E-RH-02] CFG Indirect Calls
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  - Many indirect calls pass through `__guard_dispatch_icall_fptr`
  - GuardCF is enabled in PE load configuration
- **Relevance:** Standard Windows CFG, not obfuscation

### [E-RH-03] Pool Tag KCAH
- **Classification:** FACT
- **Source:** Evidence capsule
- **Content:**
  - One allocation uses pool tag `KCAH`
  - Appears as `HACK` under one display convention
- **Relevance:** Suggestive but not proof of malicious intent

---

## Evidence Summary Matrix

| Evidence ID | Classification | Defect Class | Confidence |
|-------------|----------------|--------------|------------|
| E-PE-01 | FACT | Architecture | High |
| E-PE-02 | FACT | Architecture | High |
| E-PE-03 | FACT | Architecture | High |
| E-PE-04 | FACT | Architecture | High |
| E-IO-01 | FACT | ABI/IOCTL | High |
| E-IO-02 | FACT | ABI/IOCTL | High |
| E-IO-03 | FACT | ABI/IOCTL | High |
| E-IO-04 | FACT | ABI/IOCTL | High |
| E-IO-05 | FACT | ABI/IOCTL | High |
| E-IO-06 | FACT | ABI/IOCTL | High |
| E-RING-01 | FACT | Concurrency | High |
| E-RING-02 | FACT | Concurrency | High |
| E-RING-03 | FACT | Concurrency | High |
| E-RING-04 | FACT | Concurrency | High |
| E-RING-05 | FACT | Concurrency | High |
| E-RING-06 | FACT | Concurrency | High |
| E-LOCK-01 | FACT | Deadlock | High |
| E-LOCK-02 | FACT | Deadlock | High |
| E-LOCK-03 | FACT | Deadlock | High |
| E-LOCK-04 | FACT | Deadlock | High |
| E-VM-01 | FACT | VM | High |
| E-VM-02 | FACT | VM | High |
| E-VM-03 | FACT | VM | High |
| E-VM-04 | FACT | VM | High |
| E-VM-05 | FACT | VM | High |
| E-INT-01 | FACT | Integrity | High |
| E-INT-02 | FACT | Integrity | High |
| E-INT-03 | FACT | Integrity | High |
| E-INT-04 | FACT | Integrity | High |
| E-RH-01 | FACT | Red Herring | High |
| E-RH-02 | FACT | Red Herring | High |
| E-RH-03 | FACT | Red Herring | High |

---
*End of Evidence Ledger*
