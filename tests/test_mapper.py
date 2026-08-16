import pytest
import sys
from pathlib import Path
from src.core.data_structs import SectionRange
from src.core.mapper import AddressMapper, AddressMappingError

PROJECT_ROOT = Path(__file__).resolve().parent
if (PROJECT_ROOT / "src").is_dir():
    sys.path.insert(0, str(PROJECT_ROOT))
elif (PROJECT_ROOT.parent / "src").is_dir():
    sys.path.insert(0, str(PROJECT_ROOT.parent))

def test_rva_to_file_offset_inside_section():
    mapper = AddressMapper(
        sections=[
            SectionRange(
                name=".text",
                virtual_address=0x1000,
                virtual_size=0x600,
                raw_pointer=0x400,
                raw_size=0x600,
            )
        ],
        size_of_header=0x400,
    )

    assert mapper.rva_to_file_offset(0x1234) == 0x634


def test_file_offset_to_rva_inside_section():
    mapper = AddressMapper(
        sections=[
            SectionRange(
                name=".text",
                virtual_address=0x1000,
                virtual_size=0x600,
                raw_pointer=0x400,
                raw_size=0x600,
            )
        ],
        size_of_header=0x400,
    )

    assert mapper.file_offset_to_rva(0x634) == 0x1234


def test_headers_map_directly():
    mapper = AddressMapper([], size_of_header=0x400)

    assert mapper.rva_to_file_offset(0x120) == 0x120
    assert mapper.file_offset_to_rva(0x120) == 0x120


def test_virtual_only_rva_has_no_file_offset():
    mapper = AddressMapper(
        sections=[
            SectionRange(
                name=".bss",
                virtual_address=0x3000,
                virtual_size=0x1000,
                raw_pointer=0xA00,
                raw_size=0x200,
            )
        ],
        size_of_header=0x400,
    )

    with pytest.raises(AddressMappingError):
        mapper.rva_to_file_offset(0x3400)