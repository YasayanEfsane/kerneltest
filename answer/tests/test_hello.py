#!/usr/bin/env python3
"""
test_hello.py - Tests for decode_hello.py

Tests V2 negotiation packet decoding with various cases:
- Valid packet from evidence
- Truncated packet
- Oversized packet
- Unknown version
- Cross-bitness scenarios
"""

import sys
sys.path.insert(0, '/workspace/answer/tools')

from decode_hello import (
    ClientHelloV2,
    DriverInterpretation,
    decode_packet,
    create_test_packet,
)


def test_evidence_packet():
    """Test with evidence [E-IO-04] packet."""
    packet = create_test_packet()
    assert len(packet) == 0x1C, f"Expected 0x1C bytes, got {len(packet)}"
    
    client, driver = decode_packet(packet)
    
    # Client view should match [E-IO-04] interpretation
    assert client.magic == 0x4B4C434F, "Magic should be 'OCLK'"
    assert client.version == 2, "Version should be 2"
    assert client.header_size == 0x1C, "HeaderSize should be 0x1C"
    assert client.process_id == 1234, "ProcessId should be 1234"
    assert client.client_nonce == 0x1122334455667788, "ClientNonce mismatch"
    assert client.capabilities == 5, "Capabilities should be 5"
    assert client.header_crc == 0x412E6D9A, "HeaderCRC mismatch"
    
    # Driver view should match [E-IO-06] observations
    assert driver.nonce == 0x0000000511223344, f"Driver nonce mismatch: {driver.nonce:#x}"
    assert driver.caps == 0x412E6D9A, f"Driver caps mismatch: {driver.caps:#x}"
    assert driver.crc == 0x00000000, f"Driver crc mismatch: {driver.crc:#x}"
    
    print("✓ test_evidence_packet passed")


def test_truncated_packet():
    """Test with truncated packet."""
    packet = create_test_packet()[:0x10]  # Only 16 bytes
    
    try:
        client = ClientHelloV2.from_bytes(packet)
        print("✗ test_truncated_packet failed - should have raised ValueError")
        return False
    except ValueError as e:
        print(f"✓ test_truncated_packet passed (raised ValueError: {e})")
        return True


def test_oversized_packet():
    """Test with oversized packet (extra padding)."""
    packet = create_test_packet() + b'\x00' * 16  # Extra 16 bytes
    
    client, driver = decode_packet(packet)
    
    # Should still parse correctly
    assert client.version == 2
    assert client.header_size == 0x1C
    
    # Driver should read CRC from actual offset now
    assert driver.crc != 0, "Driver should read valid CRC from extended buffer"
    
    print("✓ test_oversized_packet passed")


def test_unknown_version():
    """Test with unknown version number."""
    packet = bytearray(create_test_packet())
    packet[0x04] = 0x03  # Version 3
    packet[0x05] = 0x00
    
    client, driver = decode_packet(bytes(packet))
    assert client.version == 3, "Version should be 3"
    
    print("✓ test_unknown_version passed")


def test_roundtrip():
    """Test serialization roundtrip."""
    original = ClientHelloV2(
        magic=0x4B4C434F,
        version=2,
        header_size=0x1C,
        process_id=1234,
        client_nonce=0x1122334455667788,
        capabilities=5,
        header_crc=0x412E6D9A,
    )
    
    serialized = original.to_bytes()
    deserialized = ClientHelloV2.from_bytes(serialized)
    
    assert deserialized.magic == original.magic
    assert deserialized.version == original.version
    assert deserialized.header_size == original.header_size
    assert deserialized.process_id == original.process_id
    assert deserialized.client_nonce == original.client_nonce
    assert deserialized.capabilities == original.capabilities
    assert deserialized.header_crc == original.header_crc
    
    print("✓ test_roundtrip passed")


def main():
    """Run all tests."""
    print("=" * 60)
    print("OC_HELLO_V2 Decoder Tests")
    print("=" * 60)
    print()
    
    tests = [
        test_evidence_packet,
        test_truncated_packet,
        test_oversized_packet,
        test_unknown_version,
        test_roundtrip,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            result = test()
            if result is not False:  # None or True means pass
                passed += 1
        except AssertionError as e:
            print(f"✗ {test.__name__} failed: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test.__name__} error: {e}")
            failed += 1
    
    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
