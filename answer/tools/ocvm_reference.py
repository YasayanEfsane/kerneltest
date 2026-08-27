#!/usr/bin/env python3
"""Bounded reference interpreter for validated OCVM2 bytecode."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import Enum, IntEnum

try:  # Support package and direct-script execution.
    from .ocvm_common import Opcode, VMFormatError, evidence_program, parse_program
except ImportError:  # pragma: no cover - direct-script compatibility
    from ocvm_common import Opcode, VMFormatError, evidence_program, parse_program  # type: ignore


DEFAULT_FUEL_LIMIT = 10_000


class VMStatus(Enum):
    RUNNING = "running"
    HALTED = "halted"
    FAULTED = "faulted"


class VMFault(IntEnum):
    NONE = 0
    FUEL_EXHAUSTED = 1
    FELL_OFF_END = 2
    INVALID_STATE = 3


@dataclass
class VMState:
    instruction_pointer: int
    fuel: int
    steps: int = 0
    status: VMStatus = VMStatus.RUNNING
    fault: VMFault = VMFault.NONE

    @property
    def byte_offset(self) -> int:
        return self.instruction_pointer * 8


class OCVMReference:
    """Execute only programs accepted by the canonical shared validator."""

    def __init__(self, program: bytes, fuel_limit: int = DEFAULT_FUEL_LIMIT):
        if isinstance(fuel_limit, bool) or not isinstance(fuel_limit, int):
            raise TypeError("fuel_limit must be an integer")
        if fuel_limit < 0:
            raise ValueError("fuel_limit must be nonnegative")
        self.instructions = parse_program(program)
        self.state = VMState(instruction_pointer=0, fuel=fuel_limit)

    def _fault(self, fault: VMFault) -> bool:
        self.state.status = VMStatus.FAULTED
        self.state.fault = fault
        return False

    def step(self) -> bool:
        """Execute one instruction; return whether another step may run."""

        if self.state.status != VMStatus.RUNNING:
            return False
        if self.state.fuel == 0:
            return self._fault(VMFault.FUEL_EXHAUSTED)
        ip = self.state.instruction_pointer
        if ip < 0 or ip >= len(self.instructions):
            return self._fault(VMFault.FELL_OFF_END)

        instruction = self.instructions[ip]
        self.state.fuel -= 1
        self.state.steps += 1

        if instruction.opcode in (Opcode.NOP, Opcode.LOAD):
            self.state.instruction_pointer += 1
        elif instruction.opcode == Opcode.BRANCH:
            if instruction.target_index is None:
                return self._fault(VMFault.INVALID_STATE)
            self.state.instruction_pointer = instruction.target_index
        elif instruction.opcode == Opcode.HALT:
            self.state.status = VMStatus.HALTED
            return False
        else:  # Unreachable after parse_program; retained as defensive containment.
            return self._fault(VMFault.INVALID_STATE)
        return True

    def run(self) -> VMState:
        while self.step():
            pass
        return self.state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hex", dest="program_hex", help="program bytes as hexadecimal")
    parser.add_argument("--fuel", type=int, default=DEFAULT_FUEL_LIMIT)
    args = parser.parse_args(argv)
    try:
        program = bytes.fromhex(args.program_hex) if args.program_hex else evidence_program()
        state = OCVMReference(program, args.fuel).run()
    except (TypeError, ValueError) as exc:
        parser.error(str(exc))
    print(f"status={state.status.value}")
    print(f"fault={state.fault.name}")
    print(f"steps={state.steps}")
    print(f"instruction_index={state.instruction_pointer}")
    print(f"byte_offset=0x{state.byte_offset:X}")
    print(f"fuel_remaining={state.fuel}")
    return 0 if state.status == VMStatus.HALTED else 1


if __name__ == "__main__":
    raise SystemExit(main())
