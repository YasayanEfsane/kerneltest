# 03_ioctl_abi.md - IOCTL and ABI Reconstruction

## IOCTL Mathematical Decoding

Windows IOCTL codes follow the `CTL_CODE` format:

```
CTL_CODE(DeviceType, Function, Method, Access) = 
    (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
```

Where:
- **DeviceType**: bits 16-31 (FILE_DEVICE_* values)
- **Access**: bits 14-15 (FILE_ANY_ACCESS=0, FILE_READ_ACCESS=1, FILE_WRITE_ACCESS=2, FILE_READ_DATA|FILE_WRITE_DATA=3)
- **Function**: bits 2-13 (0-0xFFF, vendor-defined codes typically start at 0x800)
- **Method**: bits 0-1 (METHOD_BUFFERED=0, METHOD_IN_DIRECT=1, METHOD_OUT_DIRECT=2, METHOD_NEITHER=3)

### Decoding Table

| IOCTL (hex) | Binary Breakdown | Device Type | Access | Function | Method | Semantic Name |
|-------------|------------------|-------------|--------|----------|--------|---------------|
| 0x8337E404 | `10000011001101111110010000000100` | 0x8337 | 0x03 | 0x901 | 0x00 | IOCTL_OC_CREATE_SESSION |
| 0x8337E409 | `10000011001101111110010000001001` | 0x8337 | 0x03 | 0x902 | 0x01 | IOCTL_OC_SUBMIT_POLICY |
| 0x8337E40E | `10000011001101111110010000001110` | 0x8337 | 0x03 | 0x903 | 0x02 | IOCTL_OC_GET_COUNTERS |
| 0x8337E410 | `10000011001101111110010000010000` | 0x8337 | 0x03 | 0x904 | 0x00 | IOCTL_OC_CLOSE_SESSION |

### Detailed Decoding

#### IOCTL 0x8337E404

```
Raw:      0x8337E404
Binary:   10000011 00110111 11100100 00000100

DeviceType:  0x8337 (bits 16-31) = 33591 (vendor-specific)
Access:      0x03  (bits 14-15) = FILE_READ_ACCESS | FILE_WRITE_ACCESS
Function:    0x901 (bits 2-13)  = 2305
Method:      0x00  (bits 0-1)   = METHOD_BUFFERED
```

**Semantic:** `IOCTL_OC_CREATE_SESSION`
**Input Contract:** OC_HELLO_V2_CLIENT structure (28 bytes minimum)
**Output Contract:** Session handle or status (size varies)
**Failure Modes:** STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_PARAMETER, STATUS_ACCESS_DENIED
**Session State Precondition:** None (creates new session)

#### IOCTL 0x8337E409

```
Raw:      0x8337E409
Binary:   10000011 00110111 11100100 00001001

DeviceType:  0x8337 (bits 16-31) = 33591
Access:      0x03  (bits 14-15) = FILE_READ_ACCESS | FILE_WRITE_ACCESS
Function:    0x902 (bits 2-13)  = 2306
Method:      0x01  (bits 0-1)   = METHOD_IN_DIRECT
```

**Semantic:** `IOCTL_OC_SUBMIT_POLICY`
**Input Contract:** Policy buffer (OCVM2 bytecode)
**Output Contract:** Validation status
**Failure Modes:** STATUS_INVALID_IMAGE_FORMAT, STATUS_BUFFER_TOO_SMALL
**Session State Precondition:** ACTIVE session required

#### IOCTL 0x8337E40E

```
Raw:      0x8337E40E
Binary:   10000011 00110111 11100100 00001110

DeviceType:  0x8337 (bits 16-31) = 33591
Access:      0x03  (bits 14-15) = FILE_READ_ACCESS | FILE_WRITE_ACCESS
Function:    0x903 (bits 2-13)  = 2307
Method:      0x02  (bits 0-1)   = METHOD_OUT_DIRECT
```

**Semantic:** `IOCTL_OC_GET_COUNTERS`
**Input Contract:** Optional query parameters
**Output Contract:** Counter structure with health information
**Failure Modes:** STATUS_BUFFER_TOO_SMALL
**Session State Precondition:** ACTIVE session required

#### IOCTL 0x8337E410

```
Raw:      0x8337E410
Binary:   10000011 00110111 11100100 00010000

DeviceType:  0x8337 (bits 16-31) = 33591
Access:      0x03  (bits 14-15) = FILE_READ_ACCESS | FILE_WRITE_ACCESS
Function:    0x904 (bits 2-13)  = 2308
Method:      0x00  (bits 0-1)   = METHOD_BUFFERED
```

**Semantic:** `IOCTL_OC_CLOSE_SESSION`
**Input Contract:** Session handle or identifier
**Output Contract:** Close status
**Failure Modes:** STATUS_INVALID_HANDLE, STATUS_PENDING (if drain in progress), deadlock
**Session State Precondition:** ACTIVE or CLOSING session

---

## V2 Negotiation Packet Byte-by-Byte Reconstruction

### Client Structure (WOW64, packed)

**FACT** from [E-IO-03]:

```c
#pragma pack(push, 1)
typedef struct _OC_HELLO_V2_CLIENT {
    uint32_t Magic;        // offset 0x00, size 4
    uint16_t Version;      // offset 0x04, size 2
    uint16_t HeaderSize;   // offset 0x06, size 2
    uint32_t ProcessId;    // offset 0x08, size 4
    uint64_t ClientNonce;  // offset 0x0C, size 8
    uint32_t Capabilities; // offset 0x14, size 4
    uint32_t HeaderCrc;    // offset 0x18, size 4
} OC_HELLO_V2_CLIENT;     // total: 0x1C (28 bytes)
#pragma pack(pop)
```

### Driver Expected Layout (64-bit native interpretation)

**FACT** from [E-IO-05]:

```c
// Driver reads from raw buffer at these offsets:
pid   = *(uint32_t *)(buffer + 0x08);   // ProcessId
nonce = *(uint64_t *)(buffer + 0x10);   // ClientNonce (NOTE: offset 0x10, not 0x0C!)
caps  = *(uint32_t *)(buffer + 0x18);   // Capabilities
crc   = *(uint32_t *)(buffer + 0x1C);   // HeaderCrc (NOTE: offset 0x1C, past end!)
```

### Wire Packet Bytes

**FACT** from [E-IO-04]:

```
Offset  Bytes                   Interpretation (client)
00      4f 43 4c 4b            Magic = "OCLK"
04      02 00                  Version = 2
06      1c 00                  HeaderSize = 0x1C (28)
08      d2 04 00 00            ProcessId = 1234
0c      88 77 66 55 44 33 22 11 ClientNonce = 0x1122334455667788
14      05 00 00 00            Capabilities = 5
18      9a 6d 2e 41            HeaderCrc = 0x412E6D9A
```

### Driver's Observed Values (Little-Endian Reads)

**FACT** from [E-IO-06]:

```
Driver observed nonce = 0x0000000511223344
Driver observed caps  = 0x412E6D9A
Driver observed crc   = 0x00000000
```

### Root Cause Analysis: Why WOW64 Matters

**INFERENCE** from [E-IO-03] through [E-IO-06]:

The issue is **NOT** simply that the client is 32-bit. The `#pragma pack(push, 1)` directive ensures identical layout regardless of compilation target. The real defect is:

1. **Driver uses incorrect offsets** for 64-bit field extraction
2. **Client sends** `ClientNonce` at offset 0x0C
3. **Driver reads** `ClientNonce` from offset 0x10
4. This causes a **4-byte shift** in all subsequent field interpretations

### Field Misalignment Calculation

```
Packet layout (bytes transmitted):
Offset  0x0C-0x0F: 88 77 66 55  (lower 32 bits of nonce)
Offset  0x10-0x13: 44 33 22 11  (upper 32 bits of nonce)
Offset  0x14-0x17: 05 00 00 00  (capabilities)
Offset  0x18-0x1B: 9a 6d 2e 41  (header CRC)
Offset  0x1C-0x1F: (past packet end, undefined/zero)

Driver reads nonce from 0x10 as uint64_t:
  Bytes at 0x10-0x17: 44 33 22 11 05 00 00 00
  Little-endian interpretation: 0x0000000511223344 ✓ MATCHES [E-IO-06]

Driver reads caps from 0x18 as uint32_t:
  Bytes at 0x18-0x1B: 9a 6d 2e 41
  Little-endian interpretation: 0x412E6D9A ✓ MATCHES [E-IO-06]

Driver reads crc from 0x1C as uint32_t:
  Bytes at 0x1C-0x1F: (past 28-byte packet)
  If buffer zero-padded or uninitialized: 0x00000000 ✓ MATCHES [E-IO-06]
```

### Why 64-bit Diagnostic Client Does Not Reproduce

**FACT** from [E-IO-06]: "A 64-bit diagnostic client using naturally aligned fields does not reproduce the session-identifier anomaly."

**INFERENCE:** A properly implemented 64-bit client would use the driver's expected wire format (explicit offsets, explicit serialization) rather than struct casting. The diagnostic client likely sends:

```c
// Correct wire serialization (endianness-aware):
buffer[0x08] = pid;
buffer[0x10] = nonce;  // Matches driver expectation
buffer[0x18] = caps;
buffer[0x1C] = crc;
```

This confirms the defect is **not** about 32-bit vs 64-bit, but about **implicit struct casting vs explicit wire protocol**.

---

## Canonical Serialization Contract

**PROPOSED** fix for ABI stability:

```c
// Wire format specification (independent of compiler ABI)
#define OC_WIRE_MAGIC_OFFSET      0x00
#define OC_WIRE_VERSION_OFFSET    0x04
#define OC_WIRE_HEADERSIZE_OFFSET 0x06
#define OC_WIRE_PID_OFFSET        0x08
#define OC_WIRE_NONCE_OFFSET      0x10  // Explicit offset, not struct member
#define OC_WIRE_CAPS_OFFSET       0x18
#define OC_WIRE_CRC_OFFSET        0x1C
#define OC_WIRE_MIN_SIZE          0x20  // 32 bytes minimum

// Compile-time layout assertions
static_assert(sizeof(OC_HELLO_V2_CLIENT) == 0x1C, "Client struct size mismatch");

// Runtime validation
if (InputBufferLength < OC_WIRE_MIN_SIZE)
    return STATUS_INFO_LENGTH_MISMATCH;

// Explicit deserialization (no struct casting)
uint32_t magic = READ_UNALIGNED_UINT32(buffer + OC_WIRE_MAGIC_OFFSET);
uint16_t version = READ_UNALIGNED_UINT16(buffer + OC_WIRE_VERSION_OFFSET);
uint16_t headerSize = READ_UNALIGNED_UINT16(buffer + OC_WIRE_HEADERSIZE_OFFSET);
uint32_t pid = READ_UNALIGNED_UINT32(buffer + OC_WIRE_PID_OFFSET);
uint64_t nonce = READ_UNALIGNED_UINT64(buffer + OC_WIRE_NONCE_OFFSET);
uint32_t caps = READ_UNALIGNED_UINT32(buffer + OC_WIRE_CAPS_OFFSET);
uint32_t crc = READ_UNALIGNED_UINT32(buffer + OC_WIRE_CRC_OFFSET);
```

---

## Summary of Defect Class

| Aspect | Observation |
|--------|-------------|
| **Defect Type** | ABI drift / implicit struct casting |
| **Root Cause** | Driver reads fields at wrong offsets due to assuming natural alignment |
| **Trigger** | WOW64 client sends packed struct; driver interprets with shifted offsets |
| **Symptom** | Session identifiers receive "impossible" values (nonce/caps/crc misinterpreted) |
| **Evidence** | [E-IO-03] through [E-IO-06] |
| **Fix** | Explicit wire format with compile-time assertions and runtime bounds checks |

---
*End of IOCTL/ABI Reconstruction*
