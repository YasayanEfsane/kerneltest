#!/usr/bin/env python3
"""
normalize_relocations.py - PE relocation normalizer for ObsidianClock.sys

Models correct base relocation parsing and normalization.
Demonstrates the defect in type checking from [E-INT-03].
"""

from dataclasses import dataclass
from typing import List, Tuple
import struct


@dataclass
class RelocationEntry:
    """Single relocation entry."""
    offset: int       # Offset within page (12 bits)
    type_: int        # Relocation type (4 bits)
    
    @classmethod
    def from_uint16(cls, value: int) -> "RelocationEntry":
        """Parse from 16-bit entry."""
        return cls(
            type_=(value >> 12) & 0xF,
            offset=value & 0xFFF,
        )


@dataclass 
class RelocationBlock:
    """Base relocation block."""
    page_rva: int          # Base RVA for this block
    block_size: int        # Total block size including header
    entries: List[RelocationEntry]
    
    @classmethod
    def from_bytes(cls, data: bytes, offset: int) -> Tuple["RelocationBlock", int]:
        """
        Parse relocation block from data.
        Returns (block, bytes_consumed).
        """
        if len(data) < offset + 8:
            raise ValueError("Insufficient data for block header")
        
        page_rva = struct.unpack_from("<I", data, offset)[0]
        block_size = struct.unpack_from("<I", data, offset + 4)[0]
        
        if block_size < 8:
            raise ValueError(f"Invalid block size: {block_size}")
        
        # Calculate number of entries
        num_entries = (block_size - 8) // 2
        
        entries = []
        for i in range(num_entries):
            entry_offset = offset + 8 + (i * 2)
            if entry_offset + 2 > len(data):
                break
            entry_value = struct.unpack_from("<H", data, entry_offset)[0]
            entries.append(RelocationEntry.from_uint16(entry_value))
        
        return cls(page_rva=page_rva, block_size=block_size, entries=entries), block_size


# Relocation types per PE spec
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGH = 1
IMAGE_REL_BASED_LOW = 2
IMAGE_REL_BASED_HIGHADJ = 3
IMAGE_REL_BASED_DIR64 = 10  # AMD64


def normalize_dir64(value: int, delta: int) -> int:
    """Normalize a DIR64 relocation by subtracting ASLR delta."""
    return (value - delta) & 0xFFFFFFFFFFFFFFFF


def defective_normalize(data: bytes, block_offset: int, image_delta: int) -> dict:
    """
    DEFECTIVE normalization matching [E-INT-03].
    
    BUG: Uses `type <= IMAGE_REL_BASED_DIR64` which incorrectly includes
    ABSOLUTE (type 0) entries as valid relocations to normalize.
    """
    block, _ = RelocationBlock.from_bytes(data, block_offset)
    
    result = {
        'total_entries': len(block.entries),
        'dir64_entries': 0,
        'absolute_entries': 0,
        'normalized_count': 0,  # Bug: counts ALL entries with type <= DIR64
        'hash_sites': [],
    }
    
    for entry in block.entries:
        # DEFECTIVE CHECK: type <= DIR64 includes ABSOLUTE!
        if entry.type_ <= IMAGE_REL_BASED_DIR64:
            result['normalized_count'] += 1
            
            site_rva = block.page_rva + entry.offset
            result['hash_sites'].append({
                'rva': site_rva,
                'type': entry.type_,
                'is_absolute': entry.type_ == IMAGE_REL_BASED_ABSOLUTE,
            })
            
            if entry.type_ == IMAGE_REL_BASED_DIR64:
                result['dir64_entries'] += 1
            elif entry.type_ == IMAGE_REL_BASED_ABSOLUTE:
                result['absolute_entries'] += 1
    
    return result


def correct_normalize(data: bytes, block_offset: int, image_delta: int) -> dict:
    """
    CORRECT normalization with explicit type dispatch.
    
    Only processes actual relocation types, ignores ABSOLUTE padding.
    """
    block, _ = RelocationBlock.from_bytes(data, block_offset)
    
    result = {
        'total_entries': len(block.entries),
        'dir64_entries': 0,
        'absolute_entries': 0,
        'normalized_count': 0,
        'hash_sites': [],
    }
    
    for entry in block.entries:
        if entry.type_ == IMAGE_REL_BASED_ABSOLUTE:
            # Padding entry - skip entirely
            result['absolute_entries'] += 1
            continue
        elif entry.type_ == IMAGE_REL_BASED_DIR64:
            # Actual relocation - normalize
            result['dir64_entries'] += 1
            result['normalized_count'] += 1
            
            site_rva = block.page_rva + entry.offset
            result['hash_sites'].append({
                'rva': site_rva,
                'type': entry.type_,
                'is_absolute': False,
            })
        else:
            # Unknown type - should handle error
            pass
    
    return result


def main():
    """Demonstrate normalization defect with [E-INT-02] data."""
    # Relocation block from [E-INT-02]
    # Page RVA: 0xA000, BlockSize: 0x10, Entries: 0xA118, 0xA2F0, 0x0000, 0x0000
    block_data = bytes([
        0x00, 0xA0, 0x00, 0x00,  # Page RVA = 0xA000
        0x10, 0x00, 0x00, 0x00,  # Block Size = 0x10 (16 bytes)
        0x18, 0xA1,              # Entry 1: type=0xA, offset=0x118
        0xF0, 0xA2,              # Entry 2: type=0xA, offset=0x2F0
        0x00, 0x00,              # Entry 3: type=0x0, offset=0x0 (ABSOLUTE padding)
        0x00, 0x00,              # Entry 4: type=0x0, offset=0x0 (ABSOLUTE padding)
    ])
    
    print("=" * 70)
    print("PE Relocation Normalizer - Test with [E-INT-02]")
    print("=" * 70)
    print()
    
    print("Input block:")
    print("  Page RVA:   0xA000")
    print("  Block Size: 0x10 (16 bytes)")
    print("  Entries:    0xA118, 0xA2F0, 0x0000, 0x0000")
    print()
    
    print("Entry breakdown:")
    print("  0xA118: type = 0xA (DIR64), offset = 0x118")
    print("  0xA2F0: type = 0xA (DIR64), offset = 0x2F0")
    print("  0x0000: type = 0x0 (ABSOLUTE), offset = 0x0 (padding)")
    print("  0x0000: type = 0x0 (ABSOLUTE), offset = 0x0 (padding)")
    print()
    
    # Run defective normalization
    defective_result = defective_normalize(block_data, 0, 0)
    
    print("DEFECTIVE NORMALIZER [E-INT-03]:")
    print("-" * 50)
    print(f"  Total entries:      {defective_result['total_entries']}")
    print(f"  DIR64 entries:      {defective_result['dir64_entries']}")
    print(f"  ABSOLUTE entries:   {defective_result['absolute_entries']}")
    print(f"  Normalized count:   {defective_result['normalized_count']} ← BUG!")
    print()
    print("  Hash sites (INCORRECT):")
    for site in defective_result['hash_sites']:
        marker = "← PADDING!" if site['is_absolute'] else ""
        print(f"    RVA 0x{site['rva']:X} (type {site['type']}) {marker}")
    print()
    
    # Run correct normalization
    correct_result = correct_normalize(block_data, 0, 0)
    
    print("CORRECT NORMALIZER:")
    print("-" * 50)
    print(f"  Total entries:      {correct_result['total_entries']}")
    print(f"  DIR64 entries:      {correct_result['dir64_entries']}")
    print(f"  ABSOLUTE entries:   {correct_result['absolute_entries']}")
    print(f"  Normalized count:   {correct_result['normalized_count']} ← CORRECT")
    print()
    print("  Hash sites (CORRECT):")
    for site in correct_result['hash_sites']:
        print(f"    RVA 0x{site['rva']:X} (type {site['type']})")
    print()
    
    # Compare
    print("=" * 70)
    print("COMPARISON:")
    print("-" * 50)
    print(f"  Defective reports {defective_result['normalized_count']} hash sites")
    print(f"  Correct reports   {correct_result['normalized_count']} hash sites")
    print()
    print(f"  Discrepancy: {defective_result['normalized_count'] - correct_result['normalized_count']} extra sites")
    print(f"  These are ABSOLUTE padding entries incorrectly hashed!")
    print()
    print("  This explains [E-INT-04]:")
    print(f"    'Entries in block = {defective_result['total_entries']}'")
    print(f"    'DIR64 entries = {correct_result['dir64_entries']}'")
    print(f"    'Normalizer-reported entries = {defective_result['normalized_count']}'")
    print("    'First divergent hash page = RVA 0xA000'")
    print()
    print("  When image loads at preferred base (delta=0), the incorrect")
    print("  normalization still produces consistent hashes, hiding the bug.")


if __name__ == "__main__":
    main()
