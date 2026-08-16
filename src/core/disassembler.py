from __future__ import annotations
from pathlib import Path
import pefile
from capstone import (
    CS_ARCH_X86,
    CS_GRP_CALL,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_32,
    CS_MODE_64,
    Cs,
    CsError,
)

from src.core.data_structs import Architecture, CodeRegion, DisassemblyConfig, DisassemblyResult, InstructionInfo
from src.core.mapper import AddressMapper

class DisassemblyError(Exception):
    pass

def _create_engine (architecture: Architecture) -> Cs:
    mode = CS_MODE_64 if architecture is Architecture.X86_64 else CS_MODE_32
    engine = Cs(CS_ARCH_X86, mode)
    engine.detail = True
    return engine

def disassemble_code (region: CodeRegion, architecture: Architecture, config: DisassemblyConfig | None = None) -> DisassemblyResult:
    # Create a disassembly engine based on the architecture
    config = config or DisassemblyConfig()
    code = region.data[:config.max_bytes]
    if not code:
        raise DisassemblyError("No code bytes were provided for disassembly")
    engine = _create_engine(architecture)
    
    instructions: list[InstructionInfo] = []
    
    try:
        for inst in engine.disasm(code, region.virtual_address, count = config.max_instructions):
            tmpAddress = inst.address
            tmpSize = inst.size 
            tmp_bytes_hex = bytes(inst.bytes).hex()
            tmp_mnemonic = inst.mnemonic
            tmp_op_str = inst.op_str
            
            tmp_is_call = inst.group(CS_GRP_CALL)
            tmp_is_jump = inst.group(CS_GRP_JUMP)
            tmp_is_return = inst.group(CS_GRP_RET)

            instructions.append(
                InstructionInfo(
                    address=tmpAddress,
                    size=tmpSize,
                    bytes_hex=tmp_bytes_hex,
                    mnemonic=tmp_mnemonic,
                    op_str=tmp_op_str,
                    is_call=tmp_is_call,
                    is_jump=tmp_is_jump,
                    is_return=tmp_is_return
                )
            )

    except CsError as exc:
        raise DisassemblyError(f"Disassembly failed: {exc}") from exc
    
    consumed_bytes = sum(inst.size for inst in instructions)
    hit_limit = (
        len(instructions) == config.max_instructions
        and consumed_bytes < len(code)
    )
    
    return DisassemblyResult(
        architecture=architecture,
        start_address=region.virtual_address,
        section_name=region.section_name,
        instructions=instructions,
        hit_instruction_limit=hit_limit
    )
    
def disassemble_pe_entry_point (file_path: str | Path, config: DisassemblyConfig | None = None) -> DisassemblyResult:
    # Disassemble the executable bytes beginning at a PE file's entry point.
    config = config or DisassemblyConfig()
    path = Path(file_path)
    
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    try:
        pe = pefile.PE(str(path), fast_load = True)
    except pefile.PEFormatError as exc:
        raise DisassemblyError(f"Failed to parse PE file: {exc}") from exc
    
    try:
        magic = pe.OPTIONAL_HEADER.Magic
        if magic == 0x20B:
            architecture = Architecture.X86_64
        elif magic == 0x10B:
            architecture = Architecture.X86_32
        else:
            raise DisassemblyError(f"Unsupported PE architecture: {magic}")
        
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase
        
        section = next(
            (
                sec for sec in pe.sections
                if sec.VirtualAddress <= entry_rva < sec.VirtualAddress + max(sec.Misc_VirtualSize, sec.SizeOfRawData)
            ), None,
        )
        
        if section is None:
            raise DisassemblyError("Entry point does not belong to any section")
        mapper = AddressMapper.from_pe(pe)
        file_offset = mapper.rva_to_file_offset(entry_rva)
        section_end = section.PointerToRawData + section.SizeOfRawData
        read_end = min(file_offset + config.max_bytes, section_end)
        
        code = pe.__data__[file_offset:read_end]
        if not code:
            raise DisassemblyError("No code bytes could be read from the entry point")
        
        section_name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        region = CodeRegion(
            data = code,
            virtual_address = image_base + entry_rva,
            file_offset = file_offset,
            section_name = section_name,
        )
        
        return disassemble_code(region, architecture, config)
    except(AttributeError, IndexError, ValueError) as exc:
        raise DisassemblyError(f"Failed to disassemble PE entry point: {exc}") from exc
    finally:
        pe.close()