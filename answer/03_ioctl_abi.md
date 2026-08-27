# IOCTL and V2 ABI reconstruction

## Mathematical decoding

Windows control codes use:

```text
CTL_CODE(DeviceType, Function, Method, Access)
  = (DeviceType << 16)
  | (Access << 14)
  | (Function << 2)
  | Method
```

The function field occupies bits 2–13 and therefore ranges from `0x000` to
`0xFFF`; vendor-defined values conventionally begin at `0x800`.

**DERIVED — `[E-IO-01]`:**

| Raw code | Device type | Access | Function | Method | Evidence-backed purpose |
|---:|---:|---|---:|---|---|
| `0x8337E404` | `0x8337` | read + write (`3`) | `0x901` | `METHOD_BUFFERED` | Negotiate session |
| `0x8337E409` | `0x8337` | read + write (`3`) | `0x902` | `METHOD_IN_DIRECT` | Submit policy |
| `0x8337E40E` | `0x8337` | read + write (`3`) | `0x903` | `METHOD_OUT_DIRECT` | Query counters/health |
| `0x8337E410` | `0x8337` | read + write (`3`) | `0x904` | `METHOD_BUFFERED` | Close and drain session |

The bit fields are calculated by `answer/tools/decode_ioctl.py` and locked by
`answer/tests/test_ioctl.py`.  The capsules do not supply complete structures
for policy, counters, or close, so their precise sizes and all possible status
codes remain **UNKNOWN**.

## Canonical V2 wire layout

**FACT — `[E-IO-03]`:** the WOW64 client uses a one-byte-packed declaration.
Packing produces this stable 28-byte byte sequence:

| Offset | Size | Field |
|---:|---:|---|
| `0x00` | 4 | `Magic` |
| `0x04` | 2 | `Version` |
| `0x06` | 2 | `HeaderSize` |
| `0x08` | 4 | `ProcessId` |
| `0x0C` | 8 | `ClientNonce` |
| `0x14` | 4 | `Capabilities` |
| `0x18` | 4 | `HeaderCrc` |
| | `0x1C` | total |

The evidence packet is:

```text
4f 43 4c 4b 02 00 1c 00 d2 04 00 00
88 77 66 55 44 33 22 11 05 00 00 00
9a 6d 2e 41
```

Canonical little-endian interpretation:

```text
Magic          = "OCLK"
Version        = 2
HeaderSize     = 0x1C
ProcessId      = 1234
ClientNonce    = 0x1122334455667788
Capabilities   = 0x00000005
HeaderCrc      = 0x412E6D9A
```

The capsules give CRC bytes but no CRC polynomial, initialization, reflection,
or coverage rule.  A decoder may preserve this value but cannot honestly claim
to validate it.

## Defective driver interpretation

**FACT — `[E-IO-05]`:** V2 accepts `HeaderSize >= 0x1C`, then uses native-style
offsets `0x08`, `0x10`, `0x18`, and `0x1C`.  It validates the allocated buffered
I/O backing size rather than the actual input length.  Because buffered I/O may
allocate the larger of input and output lengths, a 28-byte input can have bytes
available beyond its logical end.

Byte derivation:

```text
read QWORD at 0x10:
  44 33 22 11 05 00 00 00 -> 0x0000000511223344

read DWORD at 0x18:
  9a 6d 2e 41             -> 0x412E6D9A

read DWORD at 0x1C:
  outside InputBufferLength; evidence backing bytes are zero -> 0
```

These values exactly match `[E-IO-06]`.  The successful IRP status in that
capsule establishes observed acceptance; it does not make the out-of-contract
bytes part of V2.

## Why WOW64 is relevant but not the root cause by itself

The 32-bit service happens to send the packed declaration while a 64-bit
diagnostic client sends naturally aligned fields that match the defective
driver offsets.  Cross-bitness is therefore the trigger context.  The actual
defect is an undocumented, compiler-dependent wire contract plus validation of
the wrong length.

`#pragma pack(1)` is not intrinsically a 32-bit layout; it would produce the
same bytes in a 64-bit client.  Conversely, a 32-bit program can serialize a
32-byte version explicitly.  The protocol must be defined as bytes, not as the
native layout of either participant.

## Compatible repair

V2 is already identified by `Version == 2` and `HeaderSize == 0x1C`.  A
compatible repair must preserve its 28-byte offsets:

```c
if (InputBufferLength != 0x1C)
    return length_error;
if (read_u32_le(buffer + 0x00) != OCLK_MAGIC)
    return format_error;
if (read_u16_le(buffer + 0x04) != 2 ||
    read_u16_le(buffer + 0x06) != 0x1C)
    return version_error;

pid   = read_u32_le(buffer + 0x08);
nonce = read_u64_le(buffer + 0x0C);
caps  = read_u32_le(buffer + 0x14);
crc   = read_u32_le(buffer + 0x18);
```

If a naturally aligned 32-byte representation is desired, it must receive a
new version and its own explicit byte specification.  Silently redefining V2
as 32 bytes would break the existing service and conceal the original contract
error.

## Executable reproduction

`answer/tools/decode_hello.py` deliberately separates:

- `decode_v2_wire`: canonical fail-closed 28-byte parser;
- `simulate_defective_driver_view`: analysis-only reproduction that requires
  the caller to supply backing bytes through offset `0x1F` explicitly.

Regression tests cover every truncated input length, magic/version/header
validation, trailing-byte policy, input length versus allocation length,
round-trip serialization, and the evidence-defined misread values.

## Root-cause statement

**INFERENCE — confidence high:** a packed V2 packet, native-offset extraction,
and allocated-buffer length validation combine to read the nonce, capabilities,
and CRC from the wrong logical fields.  This explains the impossible session
identifiers without requiring memory tampering `[E-IO-03]`–`[E-IO-06]`.
