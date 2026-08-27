from __future__ import annotations

import unittest

from answer.tools.decode_ioctl import KNOWN_IOCTLS, construct_ioctl, decode_ioctl


class IoctlTests(unittest.TestCase):
    EXPECTED = {
        0x8337E404: (0x8337, 0x901, 0, 3),
        0x8337E409: (0x8337, 0x902, 1, 3),
        0x8337E40E: (0x8337, 0x903, 2, 3),
        0x8337E410: (0x8337, 0x904, 0, 3),
    }

    def test_known_codes(self) -> None:
        self.assertEqual(set(KNOWN_IOCTLS), set(self.EXPECTED))
        for code, expected in self.EXPECTED.items():
            with self.subTest(code=f"0x{code:08X}"):
                decoded = decode_ioctl(code)
                self.assertEqual(
                    (decoded.device_type, decoded.function, decoded.method, decoded.access),
                    expected,
                )
                self.assertEqual(construct_ioctl(*expected), code)

    def test_round_trip_boundaries(self) -> None:
        for fields in ((0, 0, 0, 0), (0xFFFF, 0xFFF, 3, 3), (0x8337, 0x800, 2, 1)):
            with self.subTest(fields=fields):
                code = construct_ioctl(*fields)
                decoded = decode_ioctl(code)
                self.assertEqual(
                    (decoded.device_type, decoded.function, decoded.method, decoded.access),
                    fields,
                )

    def test_invalid_raw_codes(self) -> None:
        for value in (-1, 0x1_0000_0000):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode_ioctl(value)
        with self.assertRaises(TypeError):
            decode_ioctl(True)

    def test_invalid_fields(self) -> None:
        cases = (
            (-1, 0, 0, 0),
            (0x10000, 0, 0, 0),
            (0, -1, 0, 0),
            (0, 0x1000, 0, 0),
            (0, 0, 4, 0),
            (0, 0, 0, 4),
        )
        for fields in cases:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                construct_ioctl(*fields)


if __name__ == "__main__":
    unittest.main()
