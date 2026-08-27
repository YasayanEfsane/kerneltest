#!/usr/bin/env python3
"""
decode_hello.py - OC_HELLO_V2_CLIENT packet decoder for ObsidianClock.sys

Demonstrates the ABI mismatch between WOW64 client structure and driver interpretation.
Shows both client-side (packed struct) and driver-side (shifted offset) interpretations.
"""

from dataclasses import dataclass
from typing import List, Tuple
import struct


@dataclass
class ClientHelloV2:
    """OC_HELLO_V2_CLIENT structure as sent by WOW64 client."""
    magic: int          # 0x00, 4 bytes
    version: int        # 0x04, 2 bytes
    header_size: int    # 0x06, 2 bytes
    process_id: int     # 0x08, 4 bytes
    client_nonce: int   # 0x0C, 8 bytes
    capabilities: int   # 0x14, 4 bytes
    header_crc: int     # 0x18, 4 bytes
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "ClientHelloV2":
        """Parse from packed wire format (little-endian)."""
        if len(data) < 0x1C:
            raise ValueError(f"Packet too small: {len(data)} < 0x1C")
        
        magic = struct.unpack_from("<I", data, 0x00)[0]
        version = struct.unpack_from("<H", data, 0x04)[0]
        header_size = struct.unpack_from("<H", data, 0x06)[0]
        process_id = struct.unpack_from("<I", data, 0x08)[0]
        client_nonce = struct.unpack_from("<Q", data, 0x0C)[0]
        capabilities = struct.unpack_from("<I", data, 0x14)[0]
        header_crc = struct.unpack_from("<I", data, 0x18)[0]
        
        return cls(
            magic=magic,
            version=version,
            header_size=header_size,
            process_id=process_id,
            client_nonce=client_nonce,
            capabilities=capabilities,
            header_crc=header_crc,
        )
    
    def to_bytes(self) -> bytes:
        """Serialize to packed wire format (little-endian)."""
        return (
            struct.pack("<I", self.magic) +
            struct.pack("<H", self.version) +
            struct.pack("<H", self.header_size) +
            struct.pack("<I", self.process_id) +
            struct.pack("<Q", self.client_nonce) +
            struct.pack("<I", self.capabilities) +
            struct.pack("<I", self.header_crc)
        )


@dataclass
class DriverInterpretation:
    """How the driver interprets the buffer (with shifted offsets)."""
    pid: int            # read from offset 0x08
    nonce: int          # read from offset 0x10 (WRONG!)
    caps: int           # read from offset 0x18 (WRONG!)
    crc: int            # read from offset 0x1C (past end!)
    
    @classmethod
    def from_buffer(cls, data: bytes) -> "DriverInterpretation":
        """Parse using driver's incorrect offset assumptions."""
        if len(data) < 0x1C:
            # Driver may still attempt reads past end if buffer allocated larger
            pass
        
        # Driver reads at these offsets (from [E-IO-05])
        pid = struct.unpack_from("<I", data, 0x08)[0] if len(data) >= 0x0C else 0
        nonce = struct.unpack_from("<Q", data, 0x10)[0] if len(data) >= 0x18 else 0
        caps = struct.unpack_from("<I", data, 0x18)[0] if len(data) >= 0x1C else 0
        crc = struct.unpack_from("<I", data, 0x1C)[0] if len(data) >= 0x20 else 0
        
        return cls(pid=pid, nonce=nonce, caps=caps, crc=crc)


def decode_packet(raw_bytes: bytes) -> Tuple[ClientHelloV2, DriverInterpretation]:
    """
    Decode a negotiation packet showing both interpretations.
    
    Args:
        raw_bytes: Raw packet bytes
        
    Returns:
        Tuple of (client_interpretation, driver_interpretation)
    """
    client_view = ClientHelloV2.from_bytes(raw_bytes)
    driver_view = DriverInterpretation.from_buffer(raw_bytes)
    return client_view, driver_view


def format_comparison(client: ClientHelloV2, driver: DriverInterpretation) -> str:
    """Format side-by-side comparison of interpretations."""
    lines = [
        "=" * 70,
        "OC_HELLO_V2 Packet Interpretation Comparison",
        "=" * 70,
        "",
        "CLIENT VIEW (correct packed struct):",
        "-" * 40,
        f"  Magic:       0x{client.magic:08X} ({bytes_to_ascii(client.magic.to_bytes(4, 'little'))})",
        f"  Version:     {client.version}",
        f"  HeaderSize:  0x{client.header_size:04X} ({client.header_size} bytes)",
        f"  ProcessId:   {client.process_id}",
        f"  ClientNonce: 0x{client.client_nonce:016X}",
        f"  Capabilities: 0x{client.capabilities:08X}",
        f"  HeaderCrc:   0x{client.header_crc:08X}",
        "",
        "DRIVER VIEW (shifted offsets - DEFECTIVE):",
        "-" * 40,
        f"  PID (0x08):   {driver.pid}",
        f"  Nonce (0x10): 0x{driver.nonce:016X}  ← READS FROM WRONG OFFSET!",
        f"  Caps (0x18):  0x{driver.caps:08X}    ← INTERPRETS CRC AS CAPS!",
        f"  CRC (0x1C):   0x{driver.crc:08X}     ← READS PAST PACKET END!",
        "",
        "DISCREPANCY ANALYSIS:",
        "-" * 40,
    ]
    
    # Calculate discrepancies
    nonce_match = client.client_nonce == driver.nonce
    caps_match = client.capabilities == driver.caps
    crc_match = client.header_crc == driver.crc
    
    lines.append(f"  Nonce matches:    {nonce_match}")
    if not nonce_match:
        lines.append(f"    Expected: 0x{client.client_nonce:016X}")
        lines.append(f"    Observed: 0x{driver.nonce:016X}")
        lines.append(f"    Shift:    4 bytes (driver reads upper half of nonce + caps)")
    
    lines.append(f"  Capabilities matches: {caps_match}")
    if not caps_match:
        lines.append(f"    Expected: 0x{client.capabilities:08X}")
        lines.append(f"    Observed: 0x{driver.caps:08X}")
        lines.append(f"    Cause:    Driver reads header CRC field instead")
    
    lines.append(f"  HeaderCRC matches:  {crc_match}")
    if not crc_match:
        lines.append(f"    Expected: 0x{client.header_crc:08X}")
        lines.append(f"    Observed: 0x{driver.crc:08X}")
        lines.append(f"    Cause:    Driver reads past packet boundary")
    
    lines.append("")
    lines.append("=" * 70)
    
    return "\n".join(lines)


def bytes_to_ascii(data: bytes) -> str:
    """Convert bytes to ASCII string if printable, else hex."""
    try:
        decoded = data.decode('ascii')
        if all(c.isprintable() for c in decoded):
            return f'"{decoded}"'
    except (UnicodeDecodeError, AttributeError):
        pass
    return data.hex()


def create_test_packet() -> bytes:
    """Create the test packet from evidence [E-IO-04]."""
    return bytes([
        0x4f, 0x43, 0x4c, 0x4b,              # Magic = "OCLK"
        0x02, 0x00,                          # Version = 2
        0x1c, 0x00,                          # HeaderSize = 0x1C
        0xd2, 0x04, 0x00, 0x00,              # ProcessId = 1234
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,  # ClientNonce
        0x05, 0x00, 0x00, 0x00,              # Capabilities = 5
        0x9a, 0x6d, 0x2e, 0x41,              # HeaderCrc = 0x412E6D9A
    ])


def main():
    """Demonstrate the ABI mismatch with evidence packet."""
    print("ObsidianClock V2 Negotiation Packet Decoder")
    print("=" * 70)
    print()
    
    # Create test packet from evidence [E-IO-04]
    packet = create_test_packet()
    print(f"Test packet size: {len(packet)} bytes (0x{len(packet):X})")
    print(f"Packet hex: {packet.hex()}")
    print()
    
    # Decode both views
    client_view, driver_view = decode_packet(packet)
    
    # Show comparison
    print(format_comparison(client_view, driver_view))
    print()
    
    # Verify against evidence [E-IO-06]
    print("VERIFICATION AGAINST EVIDENCE [E-IO-06]:")
    print("-" * 40)
    expected_nonce = 0x0000000511223344
    expected_caps = 0x412E6D9A
    expected_crc = 0x00000000
    
    print(f"  Driver observed nonce: 0x{driver_view.nonce:016X}")
    print(f"  Evidence nonce:        0x{expected_nonce:016X}")
    print(f"  Match: {driver_view.nonce == expected_nonce}")
    print()
    print(f"  Driver observed caps:  0x{driver_view.caps:08X}")
    print(f"  Evidence caps:         0x{expected_caps:08X}")
    print(f"  Match: {driver_view.caps == expected_caps}")
    print()
    print(f"  Driver observed crc:   0x{driver_view.crc:08X}")
    print(f"  Evidence crc:          0x{expected_crc:08X}")
    print(f"  Match: {driver_view.crc == expected_crc}")
    print()
    
    if (driver_view.nonce == expected_nonce and 
        driver_view.caps == expected_caps and 
        driver_view.crc == expected_crc):
        print("✓ ALL VALUES MATCH EVIDENCE - DEFECT REPRODUCED")
    else:
        print("✗ MISMATCH - Check implementation")


if __name__ == "__main__":
    main()
