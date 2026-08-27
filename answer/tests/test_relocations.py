from __future__ import annotations

import hashlib
import struct
import unittest

from answer.tools.normalize_relocations import (
    RelocationError,
    apply_relocation_delta,
    defective_normalize_mapped_image,
    evidence_relocation_block,
    normalize_mapped_image,
    parse_relocation_directory,
)


def block(page_rva: int, *entries: int, block_size: int | None = None) -> bytes:
    size = 8 + len(entries) * 2 if block_size is None else block_size
    return struct.pack("<II", page_rva, size) + b"".join(
        struct.pack("<H", entry) for entry in entries
    )


class RelocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = evidence_relocation_block()
        image = bytearray(0xB000)
        image[0xA000 : 0xA008] = (0x0123456789ABCDEF).to_bytes(8, "little")
        image[0xA118 : 0xA120] = (0x140001000).to_bytes(8, "little")
        image[0xA2F0 : 0xA2F8] = (0x140002000).to_bytes(8, "little")
        self.preferred = bytes(image)
        self.delta = 0x12345000

    def test_evidence_block_parses_exactly(self) -> None:
        blocks = parse_relocation_directory(self.directory)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].page_rva, 0xA000)
        self.assertEqual(blocks[0].block_size, 0x10)
        self.assertEqual([entry.raw for entry in blocks[0].entries], [0xA118, 0xA2F0, 0, 0])

    def test_mapped_image_normalizes_to_preferred_digest(self) -> None:
        mapped = apply_relocation_delta(self.preferred, self.directory, self.delta)
        mapped_snapshot = bytes(mapped)
        result = normalize_mapped_image(mapped, self.directory, self.delta)
        self.assertEqual(result.normalized_image, self.preferred)
        self.assertEqual(result.digest, hashlib.sha256(self.preferred).hexdigest())
        self.assertEqual(result.normalized_sites, (0xA118, 0xA2F0))
        self.assertEqual(result.skipped_absolute, 2)
        self.assertEqual(mapped, mapped_snapshot, "normalizer must not mutate caller bytes")

    def test_defective_algorithm_changes_padding_page_for_nonzero_delta(self) -> None:
        mapped = apply_relocation_delta(self.preferred, self.directory, self.delta)
        correct = normalize_mapped_image(mapped, self.directory, self.delta)
        defective = defective_normalize_mapped_image(mapped, self.directory, self.delta)
        self.assertNotEqual(defective.digest, correct.digest)
        self.assertEqual(defective.normalized_sites, (0xA118, 0xA2F0, 0xA000, 0xA000))

    def test_zero_delta_hides_defective_padding_handling(self) -> None:
        correct = normalize_mapped_image(self.preferred, self.directory, 0)
        defective = defective_normalize_mapped_image(self.preferred, self.directory, 0)
        self.assertEqual(defective.digest, correct.digest)

    def test_truncated_header_rejected(self) -> None:
        with self.assertRaisesRegex(RelocationError, "truncated"):
            parse_relocation_directory(b"\x00" * 7)

    def test_block_smaller_than_header_rejected(self) -> None:
        with self.assertRaisesRegex(RelocationError, "smaller"):
            parse_relocation_directory(struct.pack("<II", 0, 4))

    def test_odd_entry_payload_rejected(self) -> None:
        with self.assertRaisesRegex(RelocationError, "odd"):
            parse_relocation_directory(struct.pack("<II", 0, 9) + b"\x00")

    def test_block_beyond_directory_rejected(self) -> None:
        with self.assertRaisesRegex(RelocationError, "beyond"):
            parse_relocation_directory(struct.pack("<II", 0, 0x10))

    def test_site_outside_image_rejected(self) -> None:
        directory = block(0x1000, 0xA000)
        with self.assertRaisesRegex(RelocationError, "outside image"):
            normalize_mapped_image(bytes(0x100), directory, 1)

    def test_unknown_amd64_type_rejected(self) -> None:
        directory = block(0, 0x3000)
        with self.assertRaisesRegex(RelocationError, "unsupported"):
            normalize_mapped_image(bytes(0x100), directory, 1)

    def test_duplicate_and_overlapping_sites_rejected(self) -> None:
        for directory in (block(0, 0xA010, 0xA010), block(0, 0xA010, 0xA014)):
            with self.subTest(directory=directory.hex()), self.assertRaisesRegex(
                RelocationError, "overlapping"
            ):
                normalize_mapped_image(bytes(0x100), directory, 1)

    def test_uint64_subtraction_wraps_deterministically(self) -> None:
        directory = block(0, 0xA000)
        mapped = (1).to_bytes(8, "little") + bytes(8)
        result = normalize_mapped_image(mapped, directory, 2)
        self.assertEqual(int.from_bytes(result.normalized_image[:8], "little"), 0xFFFFFFFFFFFFFFFF)

    def test_invalid_hash_range_rejected(self) -> None:
        mapped = apply_relocation_delta(self.preferred, self.directory, self.delta)
        with self.assertRaisesRegex(RelocationError, "hash range"):
            normalize_mapped_image(
                mapped,
                self.directory,
                self.delta,
                hash_start=len(mapped) - 4,
                hash_size=8,
            )

    def test_multiple_blocks_are_processed(self) -> None:
        directory = block(0, 0xA010) + block(0x1000, 0xA020)
        preferred = bytearray(0x2000)
        preferred[0x10:0x18] = (0x1000).to_bytes(8, "little")
        preferred[0x1020:0x1028] = (0x2000).to_bytes(8, "little")
        mapped = apply_relocation_delta(bytes(preferred), directory, 0x100)
        result = normalize_mapped_image(mapped, directory, 0x100)
        self.assertEqual(result.normalized_image, bytes(preferred))
        self.assertEqual(result.block_count, 2)


if __name__ == "__main__":
    unittest.main()
