from __future__ import annotations

import unittest
from answer.tools.decode_hello import (
    ClientHelloV2,
    HelloDecodeError,
    OC_MAGIC,
    OC_V2_SIZE,
    create_evidence_packet,
    decode_packet,
    decode_v2_wire,
    encode_v2_wire,
    simulate_defective_driver_view,
)


class HelloV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.packet = create_evidence_packet()

    def test_evidence_packet_canonical_values(self) -> None:
        hello = decode_v2_wire(self.packet)
        self.assertEqual(hello.magic, OC_MAGIC)
        self.assertEqual(hello.version, 2)
        self.assertEqual(hello.header_size, 0x1C)
        self.assertEqual(hello.process_id, 1234)
        self.assertEqual(hello.client_nonce, 0x1122334455667788)
        self.assertEqual(hello.capabilities, 5)
        self.assertEqual(hello.header_crc, 0x412E6D9A)

    def test_every_truncated_input_length_fails_closed(self) -> None:
        for length in range(OC_V2_SIZE):
            with self.subTest(length=length):
                with self.assertRaises(HelloDecodeError):
                    decode_v2_wire(self.packet, input_length=length)

    def test_input_length_cannot_exceed_backing_buffer(self) -> None:
        with self.assertRaises(HelloDecodeError):
            decode_v2_wire(self.packet, input_length=len(self.packet) + 1)

    def test_trailing_bytes_rejected_by_default(self) -> None:
        with self.assertRaisesRegex(HelloDecodeError, "trailing"):
            decode_v2_wire(self.packet + b"\x00")

    def test_trailing_bytes_can_be_explicitly_allowed(self) -> None:
        decoded = decode_v2_wire(self.packet + b"\xAA\xBB", allow_trailing=True)
        self.assertEqual(decoded.process_id, 1234)

    def test_actual_input_length_not_backing_allocation_controls_parser(self) -> None:
        backing = self.packet + bytes(0x40 - len(self.packet))
        decoded = decode_v2_wire(backing, input_length=0x1C)
        self.assertEqual(decoded.client_nonce, 0x1122334455667788)
        with self.assertRaisesRegex(HelloDecodeError, "trailing"):
            decode_v2_wire(backing)

    def test_bad_magic_rejected(self) -> None:
        packet = bytearray(self.packet)
        packet[0] ^= 0xFF
        with self.assertRaisesRegex(HelloDecodeError, "magic"):
            decode_v2_wire(bytes(packet))

    def test_unknown_version_rejected(self) -> None:
        packet = bytearray(self.packet)
        packet[4:6] = (3).to_bytes(2, "little")
        with self.assertRaisesRegex(HelloDecodeError, "version"):
            decode_v2_wire(bytes(packet))

    def test_wrong_header_size_rejected(self) -> None:
        packet = bytearray(self.packet)
        packet[6:8] = (0x20).to_bytes(2, "little")
        with self.assertRaisesRegex(HelloDecodeError, "HeaderSize"):
            decode_v2_wire(bytes(packet))

    def test_round_trip_is_stable_wire_serialization(self) -> None:
        hello = ClientHelloV2(
            magic=OC_MAGIC,
            version=2,
            header_size=0x1C,
            process_id=0xFFFFFFFF,
            client_nonce=0xFEDCBA9876543210,
            capabilities=0x80000001,
            header_crc=0x12345678,
        )
        encoded = encode_v2_wire(hello)
        self.assertEqual(len(encoded), 28)
        self.assertEqual(decode_v2_wire(encoded), hello)

    def test_cross_bitness_invariance_is_byte_exact(self) -> None:
        # Explicit little-endian fields have no native pointer or padding width.
        self.assertEqual(encode_v2_wire(decode_v2_wire(self.packet)), self.packet)

    def test_historical_driver_view_matches_evidence(self) -> None:
        canonical, defective = decode_packet(self.packet)
        self.assertEqual(canonical.client_nonce, 0x1122334455667788)
        self.assertEqual(defective.nonce, 0x0000000511223344)
        self.assertEqual(defective.caps, 0x412E6D9A)
        self.assertEqual(defective.crc, 0)
        self.assertEqual(defective.input_length, 0x1C)
        self.assertEqual(defective.backing_length, 0x40)

    def test_defective_simulator_requires_explicit_backing_bytes(self) -> None:
        with self.assertRaisesRegex(HelloDecodeError, "backing"):
            simulate_defective_driver_view(self.packet, input_length=0x1C)

    def test_defective_simulator_reads_supplied_bytes_not_synthetic_zero(self) -> None:
        backing = self.packet + bytes.fromhex("78563412")
        defective = simulate_defective_driver_view(backing, input_length=0x1C)
        self.assertEqual(defective.crc, 0x12345678)


if __name__ == "__main__":
    unittest.main()
