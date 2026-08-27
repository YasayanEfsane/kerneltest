#!/usr/bin/env python3
"""Strict AMD64 PE relocation normalization and digest model.

The code operates on synthetic mapped-image bytes only.  It neither loads nor
modifies a Windows driver.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import struct


IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_DIR64 = 10
UINT64_MASK = 0xFFFFFFFFFFFFFFFF


class RelocationError(ValueError):
    """Raised when a relocation directory fails strict validation."""


@dataclass(frozen=True)
class RelocationEntry:
    type_: int
    offset: int
    raw: int

    @classmethod
    def from_uint16(cls, value: int) -> "RelocationEntry":
        if not 0 <= value <= 0xFFFF:
            raise ValueError("relocation entry must fit in 16 bits")
        return cls(type_=(value >> 12) & 0xF, offset=value & 0xFFF, raw=value)


@dataclass(frozen=True)
class RelocationBlock:
    directory_offset: int
    page_rva: int
    block_size: int
    entries: tuple[RelocationEntry, ...]


@dataclass(frozen=True)
class RelocationResult:
    normalized_image: bytes
    digest: str
    normalized_sites: tuple[int, ...]
    skipped_absolute: int
    block_count: int


def parse_relocation_block(data: bytes, offset: int = 0) -> tuple[RelocationBlock, int]:
    """Parse one complete block and return ``(block, next_offset)``."""

    if isinstance(offset, bool) or not isinstance(offset, int):
        raise TypeError("offset must be an integer")
    if offset < 0 or offset + 8 > len(data):
        raise RelocationError(f"truncated relocation header at offset 0x{offset:X}")
    page_rva, block_size = struct.unpack_from("<II", data, offset)
    if block_size < 8:
        raise RelocationError(f"BlockSize {block_size} is smaller than the 8-byte header")
    payload_size = block_size - 8
    if payload_size % 2:
        raise RelocationError(f"BlockSize {block_size} has an odd entry payload")
    end = offset + block_size
    if end > len(data):
        raise RelocationError(
            f"block at 0x{offset:X} ends at 0x{end:X}, beyond directory size 0x{len(data):X}"
        )
    entries = tuple(
        RelocationEntry.from_uint16(struct.unpack_from("<H", data, item_offset)[0])
        for item_offset in range(offset + 8, end, 2)
    )
    return RelocationBlock(offset, page_rva, block_size, entries), end


def parse_relocation_directory(data: bytes) -> tuple[RelocationBlock, ...]:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("relocation directory must be bytes-like")
    data = bytes(data)
    if not data:
        raise RelocationError("relocation directory is empty")
    blocks: list[RelocationBlock] = []
    offset = 0
    while offset < len(data):
        block, offset = parse_relocation_block(data, offset)
        blocks.append(block)
    return tuple(blocks)


def _checked_site(page_rva: int, entry_offset: int, image_size: int) -> int:
    site = page_rva + entry_offset
    if site > 0xFFFFFFFF:
        raise RelocationError(f"relocation RVA overflows 32 bits: 0x{site:X}")
    if site < 0 or site + 8 > image_size:
        raise RelocationError(
            f"DIR64 site 0x{site:X}..0x{site + 7:X} is outside image size 0x{image_size:X}"
        )
    return site


def collect_dir64_sites(
    blocks: tuple[RelocationBlock, ...], image_size: int
) -> tuple[tuple[int, ...], int]:
    """Return validated, unique DIR64 sites and the ABSOLUTE padding count."""

    sites: list[int] = []
    absolute_count = 0
    for block in blocks:
        for entry in block.entries:
            if entry.type_ == IMAGE_REL_BASED_ABSOLUTE:
                absolute_count += 1
                continue
            if entry.type_ != IMAGE_REL_BASED_DIR64:
                raise RelocationError(
                    f"unsupported AMD64 relocation type {entry.type_} at block "
                    f"0x{block.directory_offset:X}"
                )
            site = _checked_site(block.page_rva, entry.offset, image_size)
            for existing in sites:
                if site < existing + 8 and existing < site + 8:
                    raise RelocationError(
                        f"overlapping relocation sites 0x{existing:X} and 0x{site:X}"
                    )
            sites.append(site)
    return tuple(sites), absolute_count


def _hash_range(image: bytes, start: int, size: int | None) -> str:
    if isinstance(start, bool) or not isinstance(start, int):
        raise TypeError("hash_start must be an integer")
    if start < 0 or start > len(image):
        raise RelocationError("hash_start is outside the mapped image")
    if size is None:
        end = len(image)
    else:
        if isinstance(size, bool) or not isinstance(size, int):
            raise TypeError("hash_size must be an integer")
        if size < 0 or start + size > len(image):
            raise RelocationError("hash range is outside the mapped image")
        end = start + size
    return hashlib.sha256(image[start:end]).hexdigest()


def normalize_mapped_image(
    mapped_image: bytes,
    relocation_directory: bytes,
    image_delta: int,
    *,
    hash_start: int = 0,
    hash_size: int | None = None,
) -> RelocationResult:
    """Subtract ``image_delta`` at validated DIR64 sites and hash the copy."""

    if isinstance(image_delta, bool) or not isinstance(image_delta, int):
        raise TypeError("image_delta must be an integer")
    original = bytes(mapped_image)
    blocks = parse_relocation_directory(relocation_directory)
    sites, absolute_count = collect_dir64_sites(blocks, len(original))
    normalized = bytearray(original)
    delta = image_delta & UINT64_MASK
    for site in sites:
        value = int.from_bytes(normalized[site : site + 8], "little")
        normalized[site : site + 8] = ((value - delta) & UINT64_MASK).to_bytes(8, "little")
    output = bytes(normalized)
    return RelocationResult(
        normalized_image=output,
        digest=_hash_range(output, hash_start, hash_size),
        normalized_sites=sites,
        skipped_absolute=absolute_count,
        block_count=len(blocks),
    )


def apply_relocation_delta(
    preferred_image: bytes,
    relocation_directory: bytes,
    image_delta: int,
) -> bytes:
    """Construct synthetic mapped bytes by adding delta at valid DIR64 sites."""

    if isinstance(image_delta, bool) or not isinstance(image_delta, int):
        raise TypeError("image_delta must be an integer")
    original = bytes(preferred_image)
    blocks = parse_relocation_directory(relocation_directory)
    sites, _ = collect_dir64_sites(blocks, len(original))
    mapped = bytearray(original)
    delta = image_delta & UINT64_MASK
    for site in sites:
        value = int.from_bytes(mapped[site : site + 8], "little")
        mapped[site : site + 8] = ((value + delta) & UINT64_MASK).to_bytes(8, "little")
    return bytes(mapped)


def defective_normalize_mapped_image(
    mapped_image: bytes,
    relocation_directory: bytes,
    image_delta: int,
) -> RelocationResult:
    """Model `[E-INT-03]`: every type ``<= DIR64`` is treated as a qword site."""

    original = bytes(mapped_image)
    blocks = parse_relocation_directory(relocation_directory)
    normalized = bytearray(original)
    sites: list[int] = []
    absolute_count = 0
    delta = image_delta & UINT64_MASK
    for block in blocks:
        for entry in block.entries:
            if entry.type_ <= IMAGE_REL_BASED_DIR64:
                site = _checked_site(block.page_rva, entry.offset, len(original))
                value = int.from_bytes(normalized[site : site + 8], "little")
                normalized[site : site + 8] = ((value - delta) & UINT64_MASK).to_bytes(
                    8, "little"
                )
                sites.append(site)
                absolute_count += entry.type_ == IMAGE_REL_BASED_ABSOLUTE
    output = bytes(normalized)
    return RelocationResult(
        normalized_image=output,
        digest=hashlib.sha256(output).hexdigest(),
        normalized_sites=tuple(sites),
        skipped_absolute=absolute_count,
        block_count=len(blocks),
    )


def evidence_relocation_block() -> bytes:
    return struct.pack("<IIHHHH", 0xA000, 0x10, 0xA118, 0xA2F0, 0, 0)


def _demo(delta: int) -> tuple[str, str, str]:
    directory = evidence_relocation_block()
    preferred = bytearray(0xB000)
    preferred[0xA000 : 0xA008] = (0x0123456789ABCDEF).to_bytes(8, "little")
    preferred[0xA118 : 0xA120] = (0x140001000).to_bytes(8, "little")
    preferred[0xA2F0 : 0xA2F8] = (0x140002000).to_bytes(8, "little")
    preferred = bytes(preferred)
    mapped = apply_relocation_delta(preferred, directory, delta)
    correct = normalize_mapped_image(mapped, directory, delta)
    defective = defective_normalize_mapped_image(mapped, directory, delta)
    return hashlib.sha256(preferred).hexdigest(), correct.digest, defective.digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--delta", type=lambda value: int(value, 0), default=0x12345000)
    args = parser.parse_args(argv)
    try:
        expected, correct, defective = _demo(args.delta)
    except (TypeError, ValueError) as exc:
        parser.error(str(exc))
    print(f"preferred digest:  {expected}")
    print(f"correct digest:    {correct}")
    print(f"defective digest:  {defective}")
    print(f"correct matches:   {correct == expected}")
    print(f"defective matches: {defective == expected}")
    return 0 if correct == expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
