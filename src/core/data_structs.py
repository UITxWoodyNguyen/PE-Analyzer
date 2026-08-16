'''
Data Structures for ONLY disassembler module.
'''

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

class Architecture (str, Enum):
    X86_32 = "x86_32"
    X86_64 = "x86_64"
    
@dataclass(frozen = True)
class DisassemblyConfig:
    max_instructions: int = 200
    max_bytes: int = 16 * 1024
    
    def __post_init__ (self) -> None:
        if self.max_instructions <= 0:
            raise ValueError("max_instructions must be greater than 0")
        if self.max_bytes <= 0:
            raise ValueError("max_bytes must be greater than 0")

@dataclass(frozen = True, slots = True)
class CodeRegion:
    data: bytes = field(repr = False)
    virtual_address: int = 0
    file_offset: Optional[int] = None
    section_name: Optional[str] = None
    
    def __post_init__(self) -> None:
        if self.virtual_address < 0:
            raise ValueError("virtual_address must be non-negative")
        if self.file_offset is not None and self.file_offset < 0:
            raise ValueError("file_offset must be non-negative if provided")
        
@dataclass(frozen = True)
class InstructionInfo:
    address: int
    size: int
    bytes_hex: str
    mnemonic: str
    op_str: str
    is_call: bool = False
    is_jump: bool = False
    is_return: bool = False
    
    @property
    def assembly(self) -> str:
        return f"{self.mnemonic} {self.op_str}".strip()
    
@dataclass(frozen = True, slots = True)
class DisassemblyResult:
    architecture: Architecture
    start_address: int
    section_name: Optional[str]
    instructions: list[InstructionInfo]
    hit_instruction_limit: bool = False
    
    @property
    def instruction_count(self) -> int:
        return len(self.instructions)
    
    def to_dict(self) -> dict:
        return {
            "architecture": self.architecture.value,
            "start_address": self.start_address,
            "section_name": self.section_name,
            "instruction_count": self.instruction_count,
            "hit_instruction_limit": self.hit_instruction_limit,
            "instructions": [
                {
                    "address": instr.address,
                    "size": instr.size,
                    "bytes_hex": instr.bytes_hex,
                    "mnemonic": instr.mnemonic,
                    "op_str": instr.op_str,
                    "is_call": instr.is_call,
                    "is_jump": instr.is_jump,
                    "is_return": instr.is_return
                } for instr in self.instructions
            ]
        }
        
@dataclass(frozen = True)
class SectionRange:
    name: str
    virtual_address: int
    virtual_size: int
    raw_pointer: int
    raw_size: int
    
    @property
    def virtual_span(self) -> int:
        return max(self.virtual_size, self.raw_size)
    
    def contains_rva(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.virtual_address + self.virtual_span
    
    def contains_file_offset(self, file_offset: int) -> bool:
        return self.raw_pointer <= file_offset < self.raw_pointer + self.raw_size