from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional
import pefile
from src.core.data_structs import SectionRange

class AddressMappingError(Exception):
    pass
    

class AddressMapper:
    def __init__(self, sections: Iterable[SectionRange], size_of_header: int) -> None:
        if size_of_header < 0:
            raise ValueError("size_of_header must be non-negative")
        self._sections = tuple(sorted(sections, key=lambda s: s.virtual_address))
        self._size_of_header = size_of_header
        
    @classmethod   
    def from_pe(cls, pe: pefile.PE) -> "AddressMapper":
        sections = [
            SectionRange(
                name=section.Name.decode(errors="ignore").rstrip("\x00"),
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_pointer=section.PointerToRawData,
                raw_size=section.SizeOfRawData
            )
            for section in pe.sections
        ]
        return cls(sections, pe.OPTIONAL_HEADER.SizeOfHeaders)
    
    @staticmethod
    def _validate_address(value: int, label: str) -> None:
        if not isinstance(value, int) or value < 0:
            raise ValueError(f"{label} must be a non-negative integer")
        
    def section_for_rva(self, rva: int) -> Optional[SectionRange]:
        self._validate_address(rva, "rva")
        for s in self._sections:
            if s.contains_rva(rva):
                return s
        return None
    
    def section_for_file_offset(self, file_offset: int) -> Optional[SectionRange]:
        self._validate_address(file_offset, "file_offset")
        for s in self._sections:
            if s.contains_file_offset(file_offset):
                return s
        return None
    
    def rva_to_file_offset(self, rva: int) -> int:
        self._validate_address(rva, "rva")
        if rva < self._size_of_header:
            return rva
        section = self.section_for_rva(rva)
        if section is None:
            raise AddressMappingError(f"RVA {rva:#x} does not belong to any section")
        delta = rva - section.virtual_address
        if delta >= section.raw_size:
            raise AddressMappingError(f"RVA {rva:#x} exceeds the raw size of section {section.name}")
        return section.raw_pointer + delta
    
    def file_offset_to_rva(self, file_offset: int) -> int:
        self._validate_address(file_offset, "file_offset")
        if file_offset < self._size_of_header:
            return file_offset
        section = self.section_for_file_offset(file_offset)
        if section is None:
            raise AddressMappingError(f"File offset {file_offset:#x} does not belong to any section")
        delta = file_offset - section.raw_pointer
        if delta >= section.virtual_size:
            raise AddressMappingError(f"File offset {file_offset:#x} exceeds the virtual size of section {section.name}")
        return section.virtual_address + delta
    
    def create_mapper_from_file(self, file_path: Path) -> AddressMapper:
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        try:
            pe = pefile.PE(str(path))
        except pefile.PEFormatError as e:
            raise ValueError(f"Invalid PE file: {file_path}") from e
        
        try:
            return AddressMapper.from_pe(pe)
        finally:
            pe.close()