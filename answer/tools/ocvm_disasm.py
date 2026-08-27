#!/usr/bin/env python3
"""Disassemble and validate fixed-width OCVM2 bytecode safely."""

from __future__ import annotations

import argparse
from pathlib import Path

try:  # Support both ``python -m`` and direct script execution.
    from .ocvm_common import (
        Instruction,
        VMFormatError,
        evidence_program,
        historical_byte_target,
        parse_program,
        read_u24,
        sign_extend_24,
    )
except ImportError:  # pragma: no cover - direct-script compatibility
    from ocvm_common import (  # type: ignore
        Instruction,
        VMFormatError,
        evidence_program,
        historical_byte_target,
        parse_program,
        read_u24,
        sign_extend_24,
    )


def disassemble_program(program: bytes, max_instructions: int = 1024) -> tuple[Instruction, ...]:
    return parse_program(program, max_instructions=max_instructions)


def format_disassembly(instructions: tuple[Instruction, ...]) -> str:
    lines = [
        "Idx  Offset  Opcode  Mnemonic  Rel24      Target(index/byte)  Historical byte target",
        "---  ------  ------  --------  ---------  ------------------  ----------------------",
    ]
    for insn in instructions:
        displacement = "" if insn.displacement is None else f"{insn.displacement:+d}"
        canonical = (
            ""
            if insn.target_index is None
            else f"{insn.target_index}/0x{insn.target_offset:02X}"
        )
        historical = (
            ""
            if insn.displacement is None
            else f"0x{historical_byte_target(insn.offset, insn.displacement):02X}"
        )
        lines.append(
            f"{insn.index:>3}  0x{insn.offset:04X}  0x{int(insn.opcode):02X}    "
            f"{insn.opcode.name:<8}  {displacement:<9}  {canonical:<18}  {historical}"
        )
    return "\n".join(lines)


def _load_program(args: argparse.Namespace) -> bytes:
    if args.file:
        return Path(args.file).read_bytes()
    if args.program_hex:
        try:
            return bytes.fromhex(args.program_hex)
        except ValueError as exc:
            raise VMFormatError(f"invalid hexadecimal program: {exc}") from exc
    return evidence_program()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--hex", dest="program_hex", help="program bytes as hexadecimal")
    source.add_argument("--file", help="read program bytes from a file")
    parser.add_argument("--max-instructions", type=int, default=1024)
    args = parser.parse_args(argv)
    try:
        instructions = disassemble_program(_load_program(args), args.max_instructions)
    except (OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    print(format_disassembly(instructions))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
