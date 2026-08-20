from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import pefile
from src.core.data_structs import DisassemblyResult, InstructionInfo
from src.core.pe_parser import ImportedDLL, SUSPICIOUS_API
from src.utils.blacklist import APIThreatInfo, is_blacklisted_api, get_api_threat_info

# Exception
class ApiXrefError(Exception):
    # Base exception for API cross-reference errors
    pass

# Data structures
@dataclass(Frozen = True)
class ApiXrefEntry:
    instruction_address: int
    mnemonic: str
    assembly: str
    api_name: Optional[str] = None
    dll_name: Optional[str] = None
    iat_address: Optional[int] = None
    is_resolved: bool = False
    is_suspicious: bool = False
    threat_info: Optional[APIThreatInfo] = None

    @property
    def instruction_address_hex(self) -> str:
        return f"0x{self.instruction_address:08X}"

    @property
    def display_name(self) -> str:
        if self.api_name and self.dll_name:
            return f"{self.dll_name}!{self.api_name}"
        elif self.api_name:
            return self.api_name

        return self.instruction_address_hex

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instruction_address": self.instruction_address,
            "instruction_address_hex": self.instruction_address_hex,
            "mnemonic": self.mnemonic,
            "assembly": self.assembly,
            "api_name": self.api_name,
            "dll_name": self.dll_name,
            "iat_address": f"0x{self.iat_address:08X}" if self.iat_address else None,
            "is_resolved": self.is_resolved,
            "is_suspicious": self.is_suspicious,
            "severity": self.threat_info.severity.value if self.threat_info else None,
            "category": self.threat_info.category.value if self.threat_info else None,
            "mitre_techniques": self.threat_info.mitre_techniques if self.threat_info else None
        }

@dataclass(Frozen = True)
class ApiXrefResult:
    entries: List[ApiXrefEntry] = field(default_factory = list)
    architecture: Optional[str] = None
    section_name: Optional[str] = None
    image_base: int = 0

    @property
    def total_count(self) -> int:
        return len(self.entries)

    @property
    def resolved_count(self) -> int:
        return sum(1 for entry in self.entries if entry.is_resolved)

    @property
    def suspicious_count(self) -> int:
        return sum(1 for entry in self.entries if entry.is_suspicious)

    @property
    def resolved_entries(self) -> List[ApiXrefEntry]:
        return [entry for entry in self.entries if entry.is_resolved]

    @property
    def suspicious_entries(self) -> List[ApiXrefEntry]:
        return [entry for entry in self.entries if entry.is_suspicious]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_count": self.total_count,
            "resolved_count": self.resolved_count,
            "suspicious_count": self.suspicious_count,
            "architecture": self.architecture,
            "section_name": self.section_name,
            "image_base": f"0x{self.image_base:08X}",
            "entries": [entry.to_dict() for entry in self.entries]
        }