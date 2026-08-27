from __future__ import annotations

import unittest

from answer.tools.ocvm_common import (
    INSTRUCTION_WIDTH,
    MAX_INSTRUCTIONS,
    Opcode,
    VMFormatError,
    calculate_branch_target,
    evidence_program,
    historical_byte_target,
    parse_program,
    read_u24,
    sign_extend_24,
)
from answer.tools.ocvm_disasm import disassemble_program
from answer.tools.ocvm_reference import OCVMReference, VMFault, VMStatus


def instruction(opcode: int, displacement: int | None = None) -> bytes:
    raw = bytearray(INSTRUCTION_WIDTH)
    raw[0] = opcode
    if displacement is not None:
        raw[2:5] = (displacement & 0xFFFFFF).to_bytes(3, "little")
    return bytes(raw)


class OcvmTests(unittest.TestCase):
    def test_read_u24_uses_exactly_three_bytes(self) -> None:
        self.assertEqual(read_u24(bytes.fromhex("563412")), 0x123456)
        with self.assertRaises(VMFormatError):
            read_u24(b"\x01\x02")

    def test_sign_extension_boundaries(self) -> None:
        self.assertEqual(sign_extend_24(0), 0)
        self.assertEqual(sign_extend_24(0x7FFFFF), 0x7FFFFF)
        self.assertEqual(sign_extend_24(0x800000), -0x800000)
        self.assertEqual(sign_extend_24(0xFFFFFF), -1)
        with self.assertRaises(ValueError):
            sign_extend_24(0x1000000)

    def test_evidence_program_branch_semantics(self) -> None:
        parsed = parse_program(evidence_program())
        self.assertEqual(len(parsed), 4)
        branch = parsed[1]
        self.assertEqual(branch.opcode, Opcode.BRANCH)
        self.assertEqual(branch.displacement, 1)
        self.assertEqual(branch.target_index, 3)
        self.assertEqual(branch.target_offset, 0x18)
        self.assertEqual(historical_byte_target(branch.offset, branch.displacement or 0), 0x11)

    def test_reference_program_halts_normally(self) -> None:
        state = OCVMReference(evidence_program(), fuel_limit=10).run()
        self.assertEqual(state.status, VMStatus.HALTED)
        self.assertEqual(state.fault, VMFault.NONE)
        self.assertEqual(state.instruction_pointer, 3)
        self.assertEqual(state.byte_offset, 0x18)
        self.assertEqual(state.steps, 3)

    def test_positive_and_negative_branch_targets(self) -> None:
        self.assertEqual(calculate_branch_target(1, 1, 4), 3)
        self.assertEqual(calculate_branch_target(1, -2, 4), 0)

        backward = instruction(Opcode.NOP) + instruction(Opcode.BRANCH, -2)
        parsed = parse_program(backward)
        self.assertEqual(parsed[1].target_index, 0)

    def test_branch_out_of_bounds_rejected_before_execution(self) -> None:
        for program in (instruction(Opcode.BRANCH, 0), instruction(Opcode.BRANCH, -2)):
            with self.subTest(program=program.hex()), self.assertRaises(VMFormatError):
                parse_program(program)

    def test_unknown_opcode_rejected(self) -> None:
        with self.assertRaisesRegex(VMFormatError, "unknown opcode"):
            parse_program(instruction(0xEE))

    def test_empty_truncated_and_unaligned_programs_rejected(self) -> None:
        for program in (b"", b"\x00", bytes(7), bytes(9)):
            with self.subTest(length=len(program)), self.assertRaises(VMFormatError):
                parse_program(program)

    def test_instruction_limit(self) -> None:
        accepted = instruction(Opcode.NOP) * MAX_INSTRUCTIONS
        self.assertEqual(len(parse_program(accepted)), MAX_INSTRUCTIONS)
        with self.assertRaisesRegex(VMFormatError, "maximum"):
            parse_program(accepted + instruction(Opcode.NOP))

    def test_disassembler_parses_bytes_after_halt(self) -> None:
        parsed = disassemble_program(instruction(Opcode.HALT) + instruction(Opcode.NOP))
        self.assertEqual([item.opcode for item in parsed], [Opcode.HALT, Opcode.NOP])

    def test_infinite_loop_is_bounded_by_fuel(self) -> None:
        loop = instruction(Opcode.BRANCH, -1)
        state = OCVMReference(loop, fuel_limit=3).run()
        self.assertEqual(state.status, VMStatus.FAULTED)
        self.assertEqual(state.fault, VMFault.FUEL_EXHAUSTED)
        self.assertEqual(state.steps, 3)

    def test_falling_off_program_is_deterministic_fault(self) -> None:
        state = OCVMReference(instruction(Opcode.NOP), fuel_limit=3).run()
        self.assertEqual(state.status, VMStatus.FAULTED)
        self.assertEqual(state.fault, VMFault.FELL_OFF_END)
        self.assertEqual(state.steps, 1)

    def test_invalid_fuel_rejected(self) -> None:
        with self.assertRaises(ValueError):
            OCVMReference(instruction(Opcode.HALT), fuel_limit=-1)


if __name__ == "__main__":
    unittest.main()
