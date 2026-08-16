from pathlib import Path
import pytest
import sys

from src.core.data_structs import Architecture, CodeRegion, DisassemblyConfig
from src.core.disassembler import DisassemblyError, disassemble_code, disassemble_pe_entry_point

PROJECT_ROOT = Path(__file__).resolve().parent
if (PROJECT_ROOT / "src").is_dir():
    sys.path.insert(0, str(PROJECT_ROOT))
elif (PROJECT_ROOT.parent / "src").is_dir():
    sys.path.insert(0, str(PROJECT_ROOT.parent))

def test_disassemble_raw_x64_bytes():
    raw_code = b"\x55\x48\x89\xe5\xc3"
    region = CodeRegion(
        data=raw_code,
        virtual_address=0x1000,
        file_offset=0,
        section_name=".text",
    )
    
    result = disassemble_code(region, Architecture.X86_64)
    mnemonics = [inst.mnemonic for inst in result.instructions]
    assert len(result.instructions) == 3
    assert mnemonics == ["push", "mov", "ret"]
    
def test_instruction_virtual_address():
    raw_code = b"\x55\x48\x89\xe5\xc3"
    target_va = 0x140001000
    region = CodeRegion(
        data=raw_code,
        virtual_address=target_va,
        file_offset=0,
        section_name=".text",
    )

    result = disassemble_code(region, Architecture.X86_64)

    assert len(result.instructions) > 0
    assert result.instructions[0].address == target_va
    
def test_max_instructions_limit():
    raw_code = b"\x55\x48\x89\xe5\xc3" * 10
    region = CodeRegion(
        data=raw_code,
        virtual_address=0x1000,
        file_offset=0,
        section_name=".text",
    )
    
    config = DisassemblyConfig(max_instructions=5)
    result = disassemble_code(region, Architecture.X86_64, config=config)
    
    assert len(result.instructions) == 5
    assert result.hit_instruction_limit is True
    
def test_empty_input_rejected_by_code_region():
    region = CodeRegion(
        data=b"",
        virtual_address=0x1000,
        file_offset=0,
        section_name=".text",
    )
    
    with pytest.raises(DisassemblyError):
        disassemble_code(region, Architecture.X86_64)
        
def test_disassemble_pe_entry_point_windows_api_exe():
    # This test assumes the presence of a valid Windows PE executable at the specified path.
    # Adjust the path to point to a valid PE file for testing.
    pe_file_path = Path("samples/testfile/pe_analyzer_lab_sample.exe")
    
    if not pe_file_path.exists():
        pytest.skip("Sample PE file not found for testing.")
    
    result = disassemble_pe_entry_point(pe_file_path)
    
    assert len(result.instructions) > 0
    assert result.architecture == Architecture.X86_64 or result.architecture == Architecture.X86