#!/usr/bin/env python3
"""Decode and construct Windows ``CTL_CODE`` values.

The module is intentionally platform independent: it models the documented bit
layout and does not communicate with a driver.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Iterable


KNOWN_IOCTLS = {
    0x8337E404: "IOCTL_OC_CREATE_SESSION",
    0x8337E409: "IOCTL_OC_SUBMIT_POLICY",
    0x8337E40E: "IOCTL_OC_GET_COUNTERS",
    0x8337E410: "IOCTL_OC_CLOSE_SESSION",
}

ACCESS_NAMES = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_ACCESS",
    2: "FILE_WRITE_ACCESS",
    3: "FILE_READ_ACCESS | FILE_WRITE_ACCESS",
}

METHOD_NAMES = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}


@dataclass(frozen=True)
class IoctlDecode:
    raw_code: int
    device_type: int
    access: int
    function: int
    method: int
    semantic_name: str

    @property
    def access_name(self) -> str:
        return ACCESS_NAMES[self.access]

    @property
    def method_name(self) -> str:
        return METHOD_NAMES[self.method]


def _bounded_int(name: str, value: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= maximum:
        raise ValueError(f"{name} must be in 0..0x{maximum:X}: {value!r}")
    return value


def construct_ioctl(device_type: int, function: int, method: int, access: int) -> int:
    """Construct a 32-bit ``CTL_CODE`` value after validating every field."""

    device_type = _bounded_int("device_type", device_type, 0xFFFF)
    function = _bounded_int("function", function, 0xFFF)
    method = _bounded_int("method", method, 0x3)
    access = _bounded_int("access", access, 0x3)
    return (device_type << 16) | (access << 14) | (function << 2) | method


def decode_ioctl(raw_code: int) -> IoctlDecode:
    """Decode the four fields of a 32-bit Windows IOCTL value."""

    raw_code = _bounded_int("raw_code", raw_code, 0xFFFFFFFF)
    return IoctlDecode(
        raw_code=raw_code,
        device_type=(raw_code >> 16) & 0xFFFF,
        access=(raw_code >> 14) & 0x3,
        function=(raw_code >> 2) & 0xFFF,
        method=raw_code & 0x3,
        semantic_name=KNOWN_IOCTLS.get(raw_code, f"UNKNOWN_IOCTL_{raw_code:08X}"),
    )


def format_decode(decoded: IoctlDecode) -> str:
    return "\n".join(
        (
            f"Raw code:      0x{decoded.raw_code:08X}",
            f"Device type:  0x{decoded.device_type:04X}",
            f"Access:       {decoded.access_name} (0x{decoded.access:X})",
            f"Function:     0x{decoded.function:03X}",
            f"Method:       {decoded.method_name} (0x{decoded.method:X})",
            f"Semantic:     {decoded.semantic_name}",
        )
    )


def _parse_codes(values: Iterable[str]) -> list[int]:
    codes: list[int] = []
    for value in values:
        try:
            codes.append(int(value, 0))
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid IOCTL value: {value}") from exc
    return codes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "codes",
        nargs="*",
        help="IOCTL values in decimal or 0x-prefixed hexadecimal; defaults to the four case values",
    )
    args = parser.parse_args(argv)
    codes = _parse_codes(args.codes) if args.codes else sorted(KNOWN_IOCTLS)
    try:
        for index, code in enumerate(codes):
            if index:
                print()
            print(format_decode(decode_ioctl(code)))
    except (TypeError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
