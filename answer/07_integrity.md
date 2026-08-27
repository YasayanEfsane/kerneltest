# Image-integrity relocation normalization

## Evidence

The driver compares a mapped-image hash with a preferred-base representation
after attempting to undo base relocations `[E-INT-01]`.

The supplied relocation block is `[E-INT-02]`:

```text
PageRVA  = 0xA000
BlockSize= 0x10
Entries  = A118, A2F0, 0000, 0000
```

Entry high nibbles identify two AMD64 `IMAGE_REL_BASED_DIR64` entries followed
by two `IMAGE_REL_BASED_ABSOLUTE` padding entries.  Correct normalized sites are
therefore `0xA118` and `0xA2F0`; the zero entries do not designate relocation
sites.

## Defect

`[E-INT-03]` uses:

```c
if (type <= IMAGE_REL_BASED_DIR64)
    normalize_qword(page + offset);
```

Relocation types are an enumeration, not an ordered permission range.  The
predicate includes type zero and causes both padding entries to process the
qword at page offset zero (`RVA 0xA000`).  The trace reports four normalized
entries even though only two are DIR64 `[E-INT-04]`.

With a zero ASLR delta, incorrectly subtracting zero does not change the digest.
With a nonzero delta, page `0xA000` diverges.  This explains why loading at the
preferred base suppresses the alert without requiring an external patch.

## Strict algorithm

`answer/tools/normalize_relocations.py` models mapped-image bytes and performs:

1. Validate every eight-byte relocation-block header.
2. Require `BlockSize >= 8`, an even entry payload, and containment inside the
   directory.
3. Skip type `ABSOLUTE`.
4. Accept only `DIR64` in the reconstructed AMD64 model.
5. Check `PageRVA + offset` for 32-bit overflow and eight-byte image bounds.
6. Reject duplicate or overlapping DIR64 sites.
7. Subtract the 64-bit delta modulo `2^64` on a copy of the mapped image.
8. Hash an explicitly validated range using SHA-256 in the synthetic model.

SHA-256 is a test-model choice.  The capsule does not identify the real
driver's digest algorithm or exact selected sections, so the report does not
attribute SHA-256 to the unseen driver.

## Executable comparison

The demonstration builds preferred synthetic bytes, adds a relocation delta at
the two DIR64 sites, and then normalizes the mapped copy:

```text
correct normalized digest  == preferred digest
defective normalized digest != preferred digest, when delta != 0
```

The caller's input bytes remain unchanged.  A separate defective function
models the `type <= 10` predicate and processes `RVA 0xA000` twice.

## File image versus mapped image

A PE file's raw section offsets, alignments, and zero-filled virtual tails are
not interchangeable with mapped RVAs.  The model accepts already mapped bytes;
it does not pretend to map an arbitrary PE file.  A production implementation
would additionally need validated NT headers, section ranges, discardable-page
policy, hash ordering, and a documented baseline representation.

## Regression coverage

`answer/tests/test_relocations.py` covers:

- preferred/mapped digest equality after correct normalization;
- nonzero and zero delta behaviour;
- ABSOLUTE padding;
- truncated and malformed blocks;
- odd payloads and directory overrun;
- out-of-image sites;
- unsupported types;
- duplicate and overlapping sites;
- 64-bit modular subtraction;
- multiple blocks and hash-range bounds.

Residual uncertainty is limited to facts not supplied by the capsules: the
real section selection, baseline-generation process, digest, and handling of
other architecture-specific relocation types.
