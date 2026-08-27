"""Shared OCVM2 format and branch semantics."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


INSTRUCTION_WIDTH = 8
MAX_INSTRUCTIONS = 1024


class VMFormatError(ValueError):
    """Raised when bytecode cannot be accepted by the canonical validator."""


class Opcode(IntEnum):
    NOP = 0x00
    LOAD = 0x10
    BRANCH = 0x31
    HALT = 0x7F


@dataclass(frozen=True)
class Instruction:
    index: int
    offset: int
    opcode: Opcode
    raw: bytes
    displacement: int | None = None
    target_index: int | None = None

    @property
    def target_offset(self) -> int | None:
        return None if self.target_index is None else self.target_index * INSTRUCTION_WIDTH


def read_u24(data: bytes, offset: int = 0) -> int:
    """Read exactly three little-endian bytes without a four-byte over-read."""

    if isinstance(offset, bool) or not isinstance(offset, int):
        raise TypeError("offset must be an integer")
    if offset < 0 or offset + 3 > len(data):
        raise VMFormatError(f"three-byte value unavailable at offset {offset}")
    return int.from_bytes(data[offset : offset + 3], "little", signed=False)


def sign_extend_24(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("value must be an integer")
    if not 0 <= value <= 0xFFFFFF:
        raise ValueError("value must fit in 24 bits")
    return value - 0x1000000 if value & 0x800000 else value


def calculate_branch_target(
    current_index: int,
    displacement: int,
    instruction_count: int,
) -> int:
    """Canonical validator and interpreter branch calculation.

    The displacement is expressed in instruction units, relative to the
    instruction following the branch.
    """

    target = current_index + 1 + displacement
    if target < 0 or target >= instruction_count:
        raise VMFormatError(
            f"branch at instruction {current_index} targets {target}; "
            f"valid range is 0..{instruction_count - 1}"
        )
    return target


def historical_byte_target(instruction_offset: int, displacement: int) -> int:
    """Evidence-defined defective interpreter calculation for comparison."""

    return instruction_offset + INSTRUCTION_WIDTH + displacement


def parse_program(program: bytes, *, max_instructions: int = MAX_INSTRUCTIONS) -> tuple[Instruction, ...]:
    """Parse and fully validate a fixed-width OCVM2 program."""

    if not isinstance(program, (bytes, bytearray, memoryview)):
        raise TypeError("program must be bytes-like")
    program = bytes(program)
    if not program:
        raise VMFormatError("program is empty")
    if len(program) % INSTRUCTION_WIDTH:
        raise VMFormatError(
            f"program length {len(program)} is not divisible by {INSTRUCTION_WIDTH}"
        )
    instruction_count = len(program) // INSTRUCTION_WIDTH
    if instruction_count > max_instructions:
        raise VMFormatError(
            f"program has {instruction_count} instructions; maximum is {max_instructions}"
        )

    decoded: list[Instruction] = []
    for index in range(instruction_count):
        offset = index * INSTRUCTION_WIDTH
        raw = program[offset : offset + INSTRUCTION_WIDTH]
        try:
            opcode = Opcode(raw[0])
        except ValueError as exc:
            raise VMFormatError(f"unknown opcode 0x{raw[0]:02X} at instruction {index}") from exc

        displacement: int | None = None
        target: int | None = None
        if opcode == Opcode.BRANCH:
            displacement = sign_extend_24(read_u24(raw, 2))
            target = calculate_branch_target(index, displacement, instruction_count)
        decoded.append(
            Instruction(
                index=index,
                offset=offset,
                opcode=opcode,
                raw=raw,
                displacement=displacement,
                target_index=target,
            )
        )
    return tuple(decoded)


def evidence_program() -> bytes:
    return bytes.fromhex(
        "1001000000000000"
        "3100010000000000"
        "0000000000000000"
        "7f00000000000000"
    )
