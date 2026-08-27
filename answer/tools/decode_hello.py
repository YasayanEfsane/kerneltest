#!/usr/bin/env python3
"""Decode the canonical OC_HELLO_V2 wire packet safely.

The canonical decoder and the historical defective-driver simulation are kept
separate so an out-of-input read can never be mistaken for accepted protocol
behaviour.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import struct


OC_MAGIC = 0x4B4C434F  # bytes: 4f 43 4c 4b ("OCLK")
OC_VERSION_V2 = 2
OC_V2_SIZE = 0x1C
OC_DRIVER_MIN_BACKING = 0x20
_V2 = struct.Struct("<IHHIQII")


class HelloDecodeError(ValueError):
    """Raised when a canonical wire packet fails closed validation."""


@dataclass(frozen=True)
class ClientHelloV2:
    magic: int
    version: int
    header_size: int
    process_id: int
    client_nonce: int
    capabilities: int
    header_crc: int

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        *,
        input_length: int | None = None,
        allow_trailing: bool = False,
    ) -> "ClientHelloV2":
        return decode_v2_wire(data, input_length=input_length, allow_trailing=allow_trailing)

    def to_bytes(self) -> bytes:
        return encode_v2_wire(self)


@dataclass(frozen=True)
class DriverInterpretation:
    """Values read by the evidence-defined incorrect native-offset decoder."""

    pid: int
    nonce: int
    caps: int
    crc: int
    input_length: int
    backing_length: int


def _checked_input(data: bytes, input_length: int | None) -> int:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    if input_length is None:
        input_length = len(data)
    if isinstance(input_length, bool) or not isinstance(input_length, int):
        raise TypeError("input_length must be an integer")
    if input_length < 0 or input_length > len(data):
        raise HelloDecodeError(
            f"input_length {input_length} is outside backing buffer of {len(data)} bytes"
        )
    return input_length


def decode_v2_wire(
    data: bytes,
    *,
    input_length: int | None = None,
    allow_trailing: bool = False,
) -> ClientHelloV2:
    """Decode V2 using its stable 28-byte wire contract.

    CRC bytes are preserved but not cryptographically checked because the
    evidence capsules do not define a CRC algorithm.
    """

    input_length = _checked_input(data, input_length)
    if input_length < OC_V2_SIZE:
        raise HelloDecodeError(f"truncated V2 packet: {input_length} < {OC_V2_SIZE}")
    if input_length > OC_V2_SIZE and not allow_trailing:
        raise HelloDecodeError(f"unexpected trailing bytes: {input_length - OC_V2_SIZE}")

    values = _V2.unpack_from(data, 0)
    hello = ClientHelloV2(*values)
    if hello.magic != OC_MAGIC:
        raise HelloDecodeError(f"invalid magic 0x{hello.magic:08X}")
    if hello.version != OC_VERSION_V2:
        raise HelloDecodeError(f"unsupported version {hello.version}")
    if hello.header_size != OC_V2_SIZE:
        raise HelloDecodeError(
            f"V2 HeaderSize must be 0x{OC_V2_SIZE:X}, got 0x{hello.header_size:X}"
        )
    return hello


def encode_v2_wire(hello: ClientHelloV2) -> bytes:
    """Serialize a validated V2 value without relying on native ABI layout."""

    if hello.magic != OC_MAGIC:
        raise HelloDecodeError("cannot encode V2 with invalid magic")
    if hello.version != OC_VERSION_V2:
        raise HelloDecodeError("cannot encode an unsupported version as V2")
    if hello.header_size != OC_V2_SIZE:
        raise HelloDecodeError("cannot encode V2 with a non-V2 HeaderSize")
    try:
        return _V2.pack(
            hello.magic,
            hello.version,
            hello.header_size,
            hello.process_id,
            hello.client_nonce,
            hello.capabilities,
            hello.header_crc,
        )
    except struct.error as exc:
        raise HelloDecodeError(f"field outside wire width: {exc}") from exc


def simulate_defective_driver_view(
    backing_buffer: bytes,
    *,
    input_length: int,
) -> DriverInterpretation:
    """Reproduce `[E-IO-05]` without performing an unsafe host-language read.

    The caller must explicitly supply the full system-buffer backing bytes.  The
    function records the shorter input length to make the contract violation
    visible rather than treating the backing allocation as valid input.
    """

    input_length = _checked_input(backing_buffer, input_length)
    if input_length < OC_V2_SIZE:
        raise HelloDecodeError("historical path first required HeaderSize >= 0x1C")
    if len(backing_buffer) < OC_DRIVER_MIN_BACKING:
        raise HelloDecodeError(
            "defective-driver simulation requires explicit backing bytes through offset 0x1F"
        )
    return DriverInterpretation(
        pid=struct.unpack_from("<I", backing_buffer, 0x08)[0],
        nonce=struct.unpack_from("<Q", backing_buffer, 0x10)[0],
        caps=struct.unpack_from("<I", backing_buffer, 0x18)[0],
        crc=struct.unpack_from("<I", backing_buffer, 0x1C)[0],
        input_length=input_length,
        backing_length=len(backing_buffer),
    )


def create_evidence_packet() -> bytes:
    return bytes.fromhex(
        "4f434c4b02001c00d20400008877665544332211050000009a6d2e41"
    )


# Backward-compatible name for the original demonstration.
create_test_packet = create_evidence_packet


def decode_packet(raw_bytes: bytes) -> tuple[ClientHelloV2, DriverInterpretation]:
    """Decode the evidence packet and simulate its zero-filled 0x40 backing buffer."""

    canonical = decode_v2_wire(raw_bytes)
    backing = raw_bytes + bytes(0x40 - len(raw_bytes))
    defective = simulate_defective_driver_view(backing, input_length=len(raw_bytes))
    return canonical, defective


def format_comparison(client: ClientHelloV2, driver: DriverInterpretation) -> str:
    return "\n".join(
        (
            "Canonical V2 wire view:",
            f"  pid          = {client.process_id}",
            f"  nonce        = 0x{client.client_nonce:016X}",
            f"  capabilities = 0x{client.capabilities:08X}",
            f"  crc bytes    = 0x{client.header_crc:08X} (algorithm unspecified)",
            "Historical defective driver view:",
            f"  pid          = {driver.pid}",
            f"  nonce        = 0x{driver.nonce:016X}",
            f"  capabilities = 0x{driver.caps:08X}",
            f"  crc          = 0x{driver.crc:08X}",
            f"  input/backing= {driver.input_length}/{driver.backing_length} bytes",
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hex", dest="packet_hex", help="wire packet as hexadecimal")
    parser.add_argument(
        "--allow-trailing", action="store_true", help="permit bytes after the 28-byte V2 header"
    )
    parser.add_argument(
        "--simulate-defective",
        action="store_true",
        help="also show the evidence-defined native-offset interpretation",
    )
    args = parser.parse_args(argv)
    try:
        packet = bytes.fromhex(args.packet_hex) if args.packet_hex else create_evidence_packet()
        canonical = decode_v2_wire(packet, allow_trailing=args.allow_trailing)
        print(f"V2 packet accepted: pid={canonical.process_id}, nonce=0x{canonical.client_nonce:016X}")
        if args.simulate_defective:
            backing = packet + bytes(max(0, 0x40 - len(packet)))
            defective = simulate_defective_driver_view(backing, input_length=len(packet))
            print(format_comparison(canonical, defective))
    except (ValueError, TypeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
