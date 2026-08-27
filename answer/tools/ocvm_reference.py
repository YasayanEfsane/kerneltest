#!/usr/bin/env python3
"""
ocvm_reference.py - OCVM2 bounded reference interpreter for ObsidianClock.sys

Implements correct instruction-index semantics for branch targets.
Includes fuel limits, bounds checking, and deterministic fault behavior.
"""

from dataclasses import dataclass
from typing import List, Tuple, Optional
from enum import IntEnum
import struct


class VMFault(IntEnum):
    """OCVM2 fault codes."""
    OK = 0
    INVALID_OPCODE = 1
    MISALIGNED_IP = 2
    BRANCH_OUT_OF_BOUNDS = 3
    FUEL_EXHAUSTED = 4
    HALT = 5


@dataclass
class VMState:
    """Virtual machine state."""
    ip: int           # Instruction pointer (byte offset)
    fp: int           # Frame pointer
    sp: int           # Stack pointer
    fuel: int         # Remaining execution steps
    fault: VMFault = VMFault.OK


INSTRUCTION_WIDTH = 8
DEFAULT_FUEL_LIMIT = 10000
MAX_INSTRUCTIONS = 1024


def sign_extend_24(value: int) -> int:
    """Sign-extend a 24-bit two's complement integer."""
    if value & 0x800000:
        return value | ~0xFFFFFF
    return value & 0xFFFFFF


def read_u24(data: bytes, offset: int) -> int:
    """Read 24-bit little-endian unsigned integer."""
    if len(data) < offset + 3:
        raise ValueError(f"Need {offset + 3} bytes")
    return struct.unpack_from("<I", data, offset)[0] & 0xFFFFFF


class OCVMReference:
    """
    Bounded reference interpreter for OCVM2.
    
    KEY DESIGN DECISIONS:
    1. Branch targets calculated in instruction indices, then converted to byte offsets
    2. All branch targets validated before execution
    3. Fuel limit prevents infinite loops
    4. Deterministic faults on all error conditions
    """
    
    def __init__(self, program: bytes, fuel_limit: int = DEFAULT_FUEL_LIMIT):
        self.program = program
        self.fuel_limit = fuel_limit
        self.state = VMState(ip=0, fp=0, sp=0, fuel=fuel_limit)
        
        # Pre-validate program
        self.instruction_count = len(program) // INSTRUCTION_WIDTH
        self.valid_targets = self._compute_valid_branch_targets()
    
    def _compute_valid_branch_targets(self) -> set:
        """Pre-compute valid branch target instruction indices."""
        valid = set()
        for i in range(self.instruction_count):
            valid.add(i)  # All instruction starts are valid targets
        return valid
    
    def _fetch_instruction(self, ip: int) -> Tuple[int, bytes]:
        """Fetch instruction at byte offset ip."""
        if ip % INSTRUCTION_WIDTH != 0:
            self.state.fault = VMFault.MISALIGNED_IP
            return (0, b'')
        
        if ip >= len(self.program):
            self.state.fault = VMFault.BRANCH_OUT_OF_BOUNDS
            return (0, b'')
        
        opcode = self.program[ip]
        operands = self.program[ip + 1:ip + INSTRUCTION_WIDTH]
        return (opcode, operands)
    
    def _calculate_branch_target(self, ip: int, displacement: int) -> int:
        """
        Calculate branch target using CORRECTED semantics.
        
        CORRECTED: Use instruction-index arithmetic, then convert to byte offset.
        This matches the validator's semantics.
        """
        current_index = ip // INSTRUCTION_WIDTH
        target_index = current_index + 1 + displacement
        
        # Validate target index
        if target_index < 0 or target_index >= self.instruction_count:
            self.state.fault = VMFault.BRANCH_OUT_OF_BOUNDS
            return -1
        
        # Convert to byte offset
        return target_index * INSTRUCTION_WIDTH
    
    def step(self) -> bool:
        """Execute one instruction. Returns False when halted or faulted."""
        if self.state.fuel <= 0:
            self.state.fault = VMFault.FUEL_EXHAUSTED
            return False
        
        self.state.fuel -= 1
        
        opcode, operands = self._fetch_instruction(self.state.ip)
        
        if self.state.fault != VMFault.OK:
            return False
        
        if opcode == 0x00:  # NOP
            self.state.ip += INSTRUCTION_WIDTH
            
        elif opcode == 0x10:  # LOAD
            self.state.ip += INSTRUCTION_WIDTH
            
        elif opcode == 0x31:  # BRANCH
            disp_raw = read_u24(operands, 1)  # Bytes 2-4 of instruction = offset 1-3 of operands
            displacement = sign_extend_24(disp_raw)
            
            # Calculate target using corrected semantics
            new_ip = self._calculate_branch_target(self.state.ip, displacement)
            
            if self.state.fault == VMFault.OK:
                self.state.ip = new_ip
            return self.state.fault == VMFault.OK
            
        elif opcode == 0x7F:  # HALT
            self.state.fault = VMFault.HALT
            return False
            
        else:  # Unknown opcode
            self.state.fault = VMFault.INVALID_OPCODE
            return False
        
        return True
    
    def run(self) -> VMFault:
        """Run program to completion. Returns final fault code."""
        while self.step():
            pass
        return self.state.fault


def main():
    """Test interpreter with minimal policy from [E-VM-04]."""
    program = bytes([
        0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Index 0: LOAD
        0x31, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,  # Index 1: BRANCH +1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Index 2: NOP
        0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Index 3: HALT
    ])
    
    print("=" * 70)
    print("OCVM2 Reference Interpreter - Test with [E-VM-04]")
    print("=" * 70)
    print()
    
    vm = OCVMReference(program)
    
    print("Initial state:")
    print(f"  IP: 0x{vm.state.ip:X}, Fuel: {vm.state.fuel}")
    print()
    
    # Step through execution
    step_count = 0
    while vm.state.fault == VMFault.OK and step_count < 10:
        old_ip = vm.state.ip
        vm.step()
        step_count += 1
        print(f"Step {step_count}: IP 0x{old_ip:X} -> 0x{vm.state.ip:X}, Fault: {vm.state.fault.name}")
    
    print()
    print(f"Final state:")
    print(f"  Fault: {vm.state.fault.name}")
    print(f"  Final IP: 0x{vm.state.ip:X}")
    print(f"  Instructions executed: {step_count}")
    print()
    
    if vm.state.fault == VMFault.HALT:
        print("✓ Program halted normally (CORRECTED semantics)")
    else:
        print(f"✗ Program terminated with fault: {vm.state.fault.name}")


if __name__ == "__main__":
    main()
