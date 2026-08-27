#!/usr/bin/env python3
"""
ocvm_disasm.py - OCVM2 bytecode disassembler for ObsidianClock.sys

Parses OCVM2 bytecode instructions and produces human-readable disassembly.
Uses instruction-index semantics for branch targets (matching validator).
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple
import struct


@dataclass
class Instruction:
    """Single OCVM2 instruction."""
    index: int          # Instruction index (0-based)
    offset: int         # Byte offset in program
    opcode: int         # Byte 0
    operand_bytes: bytes  # Bytes 1-7
    displacement: Optional[int] = None  # For branch instructions
    target_index: Optional[int] = None  # Target instruction index
    target_offset: Optional[int] = None  # Target byte offset
    mnemonic: str = "UNKNOWN"
    valid: bool = True
    error: Optional[str] = None


# Opcode definitions
OPCODES = {
    0x00: ("NOP", False),
    0x10: ("LOAD", False),
    0x31: ("BRANCH", True),   # Signed relative branch
    0x7F: ("HALT", False),
}

INSTRUCTION_WIDTH = 8  # All instructions are 8 bytes


def sign_extend_24(value: int) -> int:
    """Sign-extend a 24-bit two's complement integer to 32-bit."""
    if value & 0x800000:  # Negative
        return value | ~0xFFFFFF
    return value & 0xFFFFFF


def read_u24(data: bytes, offset: int) -> int:
    """Read 24-bit little-endian unsigned integer."""
    if len(data) < offset + 3:
        raise ValueError(f"Need {offset + 3} bytes, have {len(data)}")
    return struct.unpack_from("<I", data, offset)[0] & 0xFFFFFF


def disassemble_instruction(data: bytes, offset: int, index: int) -> Instruction:
    """Disassemble a single instruction at given byte offset."""
    if len(data) < offset + INSTRUCTION_WIDTH:
        return Instruction(
            index=index,
            offset=offset,
            opcode=0,
            operand_bytes=b'',
            mnemonic="TRUNCATED",
            valid=False,
            error=f"Instruction truncated: need {INSTRUCTION_WIDTH} bytes at offset {offset}, have {len(data) - offset}"
        )
    
    opcode = data[offset]
    operand_bytes = data[offset + 1:offset + INSTRUCTION_WIDTH]
    
    mnemonic, has_displacement = OPCODES.get(opcode, ("UNKNOWN", False))
    
    instr = Instruction(
        index=index,
        offset=offset,
        opcode=opcode,
        operand_bytes=operand_bytes,
        mnemonic=mnemonic,
    )
    
    if has_displacement:
        # Displacement is bytes 2-4 (offset 2 from instruction start, or offset 1 from operand start)
        disp_raw = read_u24(data, offset + 2)
        instr.displacement = sign_extend_24(disp_raw)
        
        # Calculate target in instruction indices (validator semantics)
        instr.target_index = index + 1 + instr.displacement
        
        # Calculate target in byte offsets (interpreter semantics)
        instr.target_offset = offset + INSTRUCTION_WIDTH + instr.displacement
    
    return instr


def disassemble_program(program: bytes, max_instructions: int = 1024) -> List[Instruction]:
    """Disassemble entire OCVM2 program."""
    instructions = []
    offset = 0
    index = 0
    
    while offset < len(program) and index < max_instructions:
        instr = disassemble_instruction(program, offset, index)
        instructions.append(instr)
        
        # Check for alignment issues
        if offset % INSTRUCTION_WIDTH != 0:
            instr.valid = False
            instr.error = f"Misaligned instruction at byte offset {offset}"
        
        # Stop at HALT or invalid opcode
        if instr.opcode == 0x7F or instr.mnemonic == "UNKNOWN":
            break
        
        offset += INSTRUCTION_WIDTH
        index += 1
    
    return instructions


def validate_branch_targets(instructions: List[Instruction], total_instructions: int) -> List[str]:
    """
    Validate branch targets using instruction-index semantics.
    Returns list of validation errors.
    """
    errors = []
    
    for instr in instructions:
        if instr.opcode == 0x31 and instr.displacement is not None:
            # Validator check: target_index must be in range
            if instr.target_index is not None:
                if instr.target_index < 0:
                    errors.append(f"Instruction {instr.index}: branch target {instr.target_index} is negative")
                elif instr.target_index >= total_instructions:
                    errors.append(f"Instruction {instr.index}: branch target {instr.target_index} exceeds program length {total_instructions}")
                elif instr.target_index % 1 != 0:
                    errors.append(f"Instruction {instr.index}: branch target {instr.target_index} is not instruction-aligned")
    
    return errors


def format_disassembly(instructions: List[Instruction]) -> str:
    """Format disassembly as human-readable string."""
    lines = []
    lines.append("OCVM2 Disassembly")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"{'Idx':>4} {'Offset':>6} {'Opcode':>6} {'Mnemonic':>10} {'Displacement':>14} {'Target Idx':>10} {'Target Off':>10}")
    lines.append("-" * 70)
    
    for instr in instructions:
        disp_str = f"{instr.displacement:+d}" if instr.displacement is not None else ""
        target_idx_str = str(instr.target_index) if instr.target_index is not None else ""
        target_off_str = f"0x{instr.target_offset:X}" if instr.target_offset is not None else ""
        
        line = f"{instr.index:>4} 0x{instr.offset:04X}  0x{instr.opcode:02X}    {instr.mnemonic:<10} {disp_str:>14} {target_idx_str:>10} {target_off_str:>10}"
        
        if not instr.valid:
            line += f"  [INVALID: {instr.error}]"
        
        lines.append(line)
    
    lines.append("")
    return "\n".join(lines)


def main():
    """Disassemble the minimal accepted policy from [E-VM-04]."""
    # Minimal accepted policy bytes
    program = bytes([
        0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Index 0: LOAD
        0x31, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,  # Index 1: BRANCH +1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Index 2: NOP
        0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Index 3: HALT
    ])
    
    print("=" * 70)
    print("OCVM2 Disassembler - Test with [E-VM-04] minimal policy")
    print("=" * 70)
    print()
    print(f"Program size: {len(program)} bytes")
    print(f"Expected instructions: 4")
    print()
    
    instructions = disassemble_program(program)
    print(format_disassembly(instructions))
    
    # Validate
    errors = validate_branch_targets(instructions, len(instructions))
    if errors:
        print("VALIDATION ERRORS:")
        for err in errors:
            print(f"  - {err}")
    else:
        print("VALIDATION: All branch targets valid (instruction-index semantics)")
    
    # Show the unit mismatch
    print()
    print("=" * 70)
    print("VALIDATOR vs INTERPRETER SEMANTICS MISMATCH:")
    print("-" * 70)
    branch_instr = instructions[1]
    print(f"Branch instruction at index {branch_instr.index}, offset 0x{branch_instr.offset:X}")
    print(f"  Displacement: {branch_instr.displacement}")
    print(f"  Validator calculates target_index = {branch_instr.index} + 1 + {branch_instr.displacement} = {branch_instr.target_index}")
    print(f"  Interpreter calculates target_offset = 0x{branch_instr.offset:X} + 8 + {branch_instr.displacement} = 0x{branch_instr.target_offset:X}")
    print()
    print(f"  Instruction {branch_instr.target_index} is at offset 0x{instructions[branch_instr.target_index].offset:X} (correct)")
    print(f"  But interpreter goes to byte offset 0x{branch_instr.target_offset:X} which is MISALIGNED!")
    print(f"  Byte offset 0x11 is in the MIDDLE of instruction 2 (which starts at 0x10)")
    print()
    print("  This causes OCVM_FAULT_INVALID_OPCODE when interpreter fetches from 0x11")


if __name__ == "__main__":
    main()
