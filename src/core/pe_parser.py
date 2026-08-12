from __future__ import annotations
from logging import info
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Counter, List, Optional, Set, Union
from unittest import result
import pefile
import math

_LOCAL_SITE_PACKAGES = Path(__file__).parent.parent / "site-packages"
if _LOCAL_SITE_PACKAGES.exists():
    sys.path.insert(0, str(_LOCAL_SITE_PACKAGES))

'''
This module is used to check if a file is a valid PE file.

We need to check 2 layers of the file:
- First layer is the DOS header, whose signature is "MZ" (0x5A4D)
- Second layer is the PE Header, whose signature is "PE\0\0" (0x00004550)

Usage:
    python3 pe_parser.py <path_to_file>
'''

MZ_SIGNATURE = 0x5A4D   # "MZ"
PE_SIGNATURE = 0x00004550   # "PE\0\0"
E_LFANEW_OFFSET = 0x3C   # Offset to the PE header pointer in the DOS header
E_LFANEW_SIZE = 4   # Size of the PE header pointer in bytes

ENTROPY_PACKED_THRESHOLD = 7.0   # Threshold for suspicious entropy, indicating potential packed or encrypted data

SECTION_MEM_EXECUTE = 0x20000000   # Section characteristic flag for executable code
SECTION_MEM_READ = 0x40000000   # Section characteristic flag for readable data
SECTION_MEM_WRITE = 0x80000000   # Section characteristic flag for writable data

# List of Windows API functions that are suspicious and may indicate malicious behavior
SUSPICIOUS_API: Set[str] = {
    # Memory Allocation & Protection
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "MapViewOfFile",
    # Process & Thread Injection / Execution
    "CreateProcessA", "CreateProcessW", "CreateRemoteThread", "OpenProcess",
    "QueueUserAPC", "SetThreadContext", "ResumeThread", "NtUnmapViewOfSection",
    # Dynamic Loading
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "LdrLoadDll",
    # Persistence & System Modification
    "RegCreateKeyExA", "RegCreateKeyExW", "RegSetValueExA", "RegSetValueExW",
    "RegOpenKeyExA", "RegOpenKeyExW",
    # Network & Communication
    "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
    "HttpSendRequestA", "HttpSendRequestW", "URLDownloadToFileA", "URLDownloadToFileW",
    "WSAStartup", "socket", "connect", "send", "recv",
    # Anti-Analysis / Evasion
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "GetTickCount", "OutputDebugStringA", "OutputDebugStringW",
    # Keylogging & Hooking
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState"
}

COMMON_PACKER_SECTIONS: Set[str] = {
    "UPX0", "UPX1", "UPX2", ".upx",
    "ASPack", ".aspack",
    "Themida", ".themida",
    "PECompact2", "PEC2",
    "MPRESS1", "MPRESS2",
    ".vmp0", ".vmp1", ".vmp2",  # VMProtect
    ".nsp0", ".nsp1",           # NsPack
    "yC", "yoda",               # yoda's Protector
}

def calculate_shannon_entropy (data: bytes) -> float:
    '''
    This function calculates the Shannon entropy of a given byte sequence.
    Value ranges from 0.0 (no randomness) to 8.0 (maximum randomness).
    Formula: H(X) = -sum(p(x) * log2(p(x))) for all unique bytes x in the data
    '''

    if not data:
        return 0.0

    length = len(data)
    byte_counts = Counter(data)
    entropy = 0.0

    for count in byte_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)  # Round to 4 decimal places for readability

@dataclass
class PECheckResult:
    path: str
    isValid_PE: bool
    reason: str

@dataclass
class PESectionInfo:
    # This dataclass represents the information of a section in a PE file.
    name: str   # Name of the section (e.g., .text, .data)
    virtual_address: int    # Virtual address of the section in memory
    virtual_address_hex: str    # Hexadecimal representation of the virtual address
    virtual_size: int   # Virtual size of the section in memory
    raw_pointer: int    # Pointer to the raw data of the section in the file
    raw_size: int       # Size of the raw data for this section in the PE file
    entropy: float  # Entropy of the section, indicating randomness (higher values may indicate packed or encrypted data)
    is_readable: bool # Indicates if the section is readable
    is_writable: bool   # Indicates if the section is writable
    is_executable: bool     # Indicates if the section is executable
    is_suspicious_entropy: bool     # Indicates if the section has suspicious entropy (e.g., > 7.0)
    is_rwx: bool    # Indicates if the section has read, write, and execute permissions (RWX), which is often suspicious
    packet_warning: Optional[str] = None  # Optional warning message for suspicious sections (e.g., high entropy, RWX permissions, etc.)

    @property
    def permissions_str(self) -> str:
        return f"{'R' if self.is_readable else '-'}{'W' if self.is_writable else '-'}{'X' if self.is_executable else '-'}"

@dataclass
class ImportedFunction:
    # This dataclass represents an Windows API function imported by a PE file.
    name: Optional[str]
    ordinal: Optional[int]
    address: int
    is_ordinal: bool
    is_suspicious: bool

    @property
    def display_name(self) -> str:
        return self.name if self.name else f"Ordinal_{self.ordinal}" if self.ordinal is not None else "Unknown"

    @property
    def hex_address(self) -> str:
        return f"0x{self.address:08X}"

@dataclass
class ImportedDLL:
    # This class represents a DLL imported by a PE file, along with its imported functions.
    dll_name: str
    functions: list[ImportedFunction] = field(default_factory=list)

    @property
    def function_count(self) -> int:
        return len(self.functions)

@dataclass
class PEInfo:
    # This dataclass is used to store the information of a PE file.
    path: str
    machine_raw: int
    machine_name: str
    machine_arch: str
    entry_point_rva: int
    entry_point_rva_hex: str
    image_base: int
    image_base_hex: str
    entry_point_va: int
    entry_point_va_hex: str
    is_64bit: bool
    number_of_sections: int
    compile_time: Optional[int]
    sections: List[PESectionInfo] = field(default_factory=list)
    imports: List[ImportedDLL] = field(default_factory=list)
    has_packed_sections: bool = False
    packer_alerts: List[str] = field(default_factory=list)

# Mapping of machine types to architecture names
MACHINE_ARCH_MAP = {
    0x014C: "x86 (I386)",
    0x8664: "x64 (AMD64)",
    0x01C0: "ARM Little-Endian",
    0xAA64: "ARM64 Little-Endian",
    0x0200: "Intel Itanium (IA-64)",
    0x01C4: "ARM Thumb-2",
}

def PE_checker (file_path: str | Path, full_check: bool = True) -> PECheckResult:
    '''
    Arguments:
        file_path: path of the file need to be checked
        full_check: 
            if True, check both DOS Header and PE Header
            if False, only check DOS Header

    Returns;
        PECheckResult(path, isValid_PE, reason)
    '''

    path = Path(file_path)

    try:
        with open(path, 'rb') as f:
            # DOS Header check
            dos_header = f.read(2)

            if len(dos_header) < 2:
                _path = str(path)
                _valid = False
                _reason = f"FILE IS TOO SMALL TO BE A VALID PE FILE: {len(dos_header)} bytes"

                return PECheckResult(_path, _valid, _reason)

            if dos_header != MZ_SIGNATURE.to_bytes(2, byteorder='little'):
                _path = str(path)
                _valid = False
                _reason = f"INVALID DOS HEADER SIGNATURE: {dos_header.hex()}"

                return PECheckResult(_path, _valid, _reason)

            if not full_check:
                _path = str(path)
                _valid = True
                _reason = "VALID DOS HEADER SIGNATURE"

                return PECheckResult(_path, _valid, _reason)

            # Read PE Header ptr
            f.seek(E_LFANEW_OFFSET)
            lfanew_bytes = f.read(E_LFANEW_SIZE)
            if len(lfanew_bytes) < E_LFANEW_SIZE:
                _path = str(path)
                _valid = False
                _reason = f"FILE IS TOO SMALL TO READ PE HEADER POINTER: {len(lfanew_bytes)} bytes"

                return PECheckResult(_path, _valid, _reason)

            pe_offset = int.from_bytes(lfanew_bytes, byteorder = 'little')

            f.seek(pe_offset)
            pe_signature = f.read(4)
            if pe_signature != PE_SIGNATURE.to_bytes(4, byteorder = 'little'):
                _path = str(path)
                _valid = False
                _reason = f"INVALID PE HEADER SIGNATURE: {pe_signature.hex()}"

                return PECheckResult(_path, _valid, _reason)

            return PECheckResult(str(path), True, "VALID PE FILE")

    except FileNotFoundError:
        _path = str(path)
        _valid = False
        _reason = "FILE NOT FOUND"

        return PECheckResult(_path, _valid, _reason)
    except PermissionError:
        _path = str(path)
        _valid = False
        _reason = "PERMISSION DENIED"

        return PECheckResult(_path, _valid, _reason)
    except OSError as e:
        _path = str(path)
        _valid = False
        _reason = f"OS ERROR: {e}"

        return PECheckResult(_path, _valid, _reason)

def parse_pe_sections (pe: Union[Any, str, Path]) -> List[PESectionInfo]:
    '''
    This function parses the sections of a PE file and returns a list of PESectionInfo objects.
    Arguments:
        pe: a pefile.PE object or a path to the PE file
    Returns:
        A list of PESectionInfo objects containing the sections of the PE file
    '''

    should_close = False
    if isinstance(pe, (str, Path)):
        path = Path(pe)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")
        try:
            pe_instance = pefile.PE(str(path))
            should_close = True
        except pefile.PEFormatError as e:
            raise ValueError(f"Invalid PE file: {e}")
    else:
        pe_instance = pe

    try:
        sections_list: List[PESectionInfo] = []

        for sec in getattr(pe_instance, 'sections', []):
            raw_name = getattr(sec, 'Name', b'')
            if isinstance(raw_name, bytes):
                name = raw_name.split(b'\x00', 1)[0].decode('utf-8', errors='ignore')
            else:
                name = str(raw_name)

            virtual_address = getattr(sec, 'VirtualAddress', 0)
            virtual_size = getattr(sec, 'Misc_VirtualSize', getattr(sec, 'VirtualSize', 0))
            raw_size = getattr(sec, 'SizeOfRawData', 0)
            raw_pointer = getattr(sec, 'PointerToRawData', 0)

            try:
                sec_data = sec.get_data()
                entropy = calculate_shannon_entropy(sec_data)
            except Exception:
                try:
                    entropy = float(sec.get_entropy())
                except Exception:
                    entropy = 0.0

            chars = getattr(sec, 'Characteristics', 0)
            is_readable = bool(chars & SECTION_MEM_READ)
            is_writable = bool(chars & SECTION_MEM_WRITE)
            is_executable = bool(chars & SECTION_MEM_EXECUTE)

            is_suspicious_entropy = entropy > ENTROPY_PACKED_THRESHOLD
            is_rwx = is_writable and is_executable

            warning_reasons = []
            if is_suspicious_entropy:
                warning_reasons.append(f"Suspicious entropy: {entropy:.4f} > {ENTROPY_PACKED_THRESHOLD}")
            if any(name.startswith(pk) for pk in COMMON_PACKER_SECTIONS):
                warning_reasons.append(f"Section name '{name}' matches common packer section names")
            if is_rwx:
                warning_reasons.append("Section has RWX permissions")

            packet_warning = " | ".join(warning_reasons) if warning_reasons else None

            sections_list.append(PESectionInfo(
                name=name,
                virtual_address=virtual_address,
                virtual_address_hex=f"0x{virtual_address:08X}",
                virtual_size=virtual_size,
                raw_pointer=raw_pointer,
                raw_size=raw_size,
                entropy=entropy,
                is_readable=is_readable,
                is_writable=is_writable,
                is_executable=is_executable,
                is_suspicious_entropy=is_suspicious_entropy,
                is_rwx=is_rwx,
                packet_warning=packet_warning
            ))
        return sections_list
    finally:
        if should_close:
            pe_instance.close()

def parse_pe_import (pe: Union[pefile.PE, str, Path]) -> List[ImportedDLL]:
    '''
    This function parses the imported DLLs and functions from a PE file and returns a list of ImportedDLL objects.
    Arguments:
        pe: a pefile.PE object or a path to the PE file
    Returns:
        A list of ImportedDLL objects containing the imported DLLs and their functions
    '''

    should_close = False
    if isinstance(pe, (str, Path)):
        path = Path(pe)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")
        try:
            pe_instance = pefile.PE(str(path))
            should_close = True
        except pefile.PEFormatError as e:
            raise ValueError(f"Invalid PE file: {e}")
    else:
        pe_instance = pe

    try:
        # Make sure Data Directory for imports is present
        if not hasattr(pe_instance, 'DIRECTORY_ENTRY_IMPORT'):
            pe_instance.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])

        imported_dlls: List[ImportedDLL] = []

        if hasattr(pe_instance, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe_instance.DIRECTORY_ENTRY_IMPORT:
                # Extract DLL name
                dll_name = entry.dll.decode('utf-8', errors='ignore') if entry.dll else "Unknown DLL"
                functions: List[ImportedFunction] = []

                # Extract imported functions
                for imp in getattr(entry, 'imports', []):
                    is_ordinal = imp.name is None
                    func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else None
                    ordinal = getattr(imp, 'ordinal', None)
                    address = getattr(imp, 'address', 0)

                    is_suspicious = func_name in SUSPICIOUS_API if func_name else False

                    functions.append(ImportedFunction(name=func_name, ordinal=ordinal, address=address, is_ordinal=is_ordinal, is_suspicious=is_suspicious))

                imported_dlls.append(ImportedDLL(dll_name=dll_name, functions=functions))
        return imported_dlls
    finally:
        if should_close:
            pe_instance.close()

def parse_pe_info (file_path: Union[str, Path], fast_load: bool = True) -> PEInfo:
    '''
    This function parses the PE file and returns a PEInfo object containing relevant information.
    Arguments:
        file_path: path of the PE file to be parsed
        fast_load: if True, use fast load mode (only loads headers)
    Returns:
        PEInfo object containing relevant information about the PE file
    '''

    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    # Init PE object from pefile
    try:
        pe = pefile.PE(str(path), fast_load=fast_load)
    except pefile.PEFormatError as e:
        raise ValueError(f"Invalid PE file: {e}")

    try:
        # Get Machine Type from Header
        machine_raw = pe.FILE_HEADER.Machine
        machine_name = pefile.MACHINE_TYPE.get(machine_raw, f"UNKNOWN_MACHINE_0X{machine_raw:04X}")
        machine_arch = MACHINE_ARCH_MAP.get(machine_raw, machine_name)

        # Get Entry Point and ImageBase from OPTIONAL_HEADER
        entry_point_rva = getattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint')
        image_base = getattr(pe.OPTIONAL_HEADER, 'ImageBase')
        entry_point_va = image_base + entry_point_rva

        # Hexadecimal representations
        magic = getattr(pe.OPTIONAL_HEADER, 'Magic')
        is_64bit = magic == 0x20B  # PE32+ (64-bit)

        hex_fmt = lambda x: f"0x{x:08X}" if not is_64bit else f"0x{x:016X}"
        entry_point_rva_hex = hex_fmt(entry_point_rva)
        image_base_hex = hex_fmt(image_base)
        entry_point_va_hex = hex_fmt(entry_point_va)

        number_of_sections = pe.FILE_HEADER.NumberOfSections
        compile_time = pe.FILE_HEADER.TimeDateStamp if hasattr(pe.FILE_HEADER, 'TimeDateStamp') else None

        sections = parse_pe_sections(pe)
        packer_alerts = [sec.packet_warning for sec in sections if sec.packet_warning]
        has_packed_sections = any(sec.is_suspicious_entropy or sec.is_rwx or any(sec.name.startswith(pk) for pk in COMMON_PACKER_SECTIONS) for sec in sections)

        imports = parse_pe_import(pe)

        return PEInfo(
            path=str(path),
            machine_raw=machine_raw,
            machine_name=machine_name,
            machine_arch=machine_arch,
            entry_point_rva=entry_point_rva,
            entry_point_rva_hex=entry_point_rva_hex,
            image_base=image_base,
            image_base_hex=image_base_hex,
            entry_point_va=entry_point_va,
            entry_point_va_hex=entry_point_va_hex,
            is_64bit=is_64bit,
            number_of_sections=number_of_sections,
            compile_time=compile_time,
            sections=sections,
            imports=imports,
            has_packed_sections=has_packed_sections,
            packer_alerts=packer_alerts
        )
    except Exception as e:
        raise ValueError(f"Error occurred while parsing PE info: {e}")
    finally:
        pe.close()

def print_sections(sections: List[PESectionInfo]) -> None:
    if not sections:
        print("No sections found.")
        print("\n[Sections]\n  No sections found.")
        return
 
    print("Sections:")
    print("\n[Sections]")
    print(f"  {len(sections)} section(s) found")
    print("  " + "-" * 94)
    print(f"  {'Name':<12} {'Virtual Address':<18} {'Virtual Size':>14} {'Entropy':>10} {'Perms':<7} Status")
    print("  " + "-" * 94)
    for sec in sections:
        rwx_flag = " [RWX]" if sec.is_rwx else ""
        suspicious_entropy_flag = " [SUSPICIOUS ENTROPY]" if sec.is_suspicious_entropy else ""
        print(f"  Section: {sec.name}, VA: {sec.virtual_address_hex}, Size: {sec.virtual_size}, Entropy: {sec.entropy:.2f}, Permissions: {sec.permissions_str}{rwx_flag}{suspicious_entropy_flag}")
        alerts = []
        if sec.is_rwx:
            alerts.append("RWX")
        if sec.is_suspicious_entropy:
            alerts.append("High entropy")
        if sec.packet_warning and not alerts:
            alerts.append("Packer indicator")
        status = f"WARNING: {', '.join(alerts)}" if alerts else "OK"
        print(f"  {sec.name:<12} {sec.virtual_address_hex:<18} {sec.virtual_size:>14,} {sec.entropy:>10.2f} {sec.permissions_str:<7} {status}")
        if sec.packet_warning:
            print(f"    Note: {sec.packet_warning}")
    print("  " + "-" * 94)

def print_imports (imports: List[ImportedDLL]) -> None:
    if not imports:
        print("No imported DLLs found.")
        print("\n[Imports]\n  No imported DLLs found.")
        return
 
    total_functions = sum(dll.function_count for dll in imports)
    suspicious_functions = sum(func.is_suspicious for dll in imports for func in dll.functions)
    print("\n[Imports]")
    print(f"  {len(imports)} DLL(s), {total_functions} imported function(s), {suspicious_functions} suspicious")
    for dll in imports:
        print(f"\n  {dll.dll_name}  ({dll.function_count} function(s))")
        print(f"    {'Function':<44} {'Address':<18} Status")
        print("    " + "-" * 78)
        for func in dll.functions:
            status = "SUSPICIOUS" if func.is_suspicious else "OK"
            print(f"    {func.display_name:<44} {func.hex_address:<18} {status}")

def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python pe_parser.py <path_to_file> [additional_file ...]")
        return 1
 
    exit_code = 0
    for file_path in sys.argv[1:]:
        print("\n" + "=" * 100)
        print("PE ANALYSIS REPORT")
        print("=" * 100)
        print(f"File: {Path(file_path).resolve()}")
         # Validation of the PE file
        result = PE_checker(file_path)
        status = "VALID" if result.isValid_PE else "INVALID"
        print(f"{result.path}: {status} - {result.reason}")
        print(f"Validation: {status} — {result.reason}")
 
        if not result.isValid_PE:
            exit_code = 2
            print("Analysis skipped because the file is not a valid PE file.")
            continue
 
         # Analyze with pefile
        try:
            info = parse_pe_info(file_path)
            print(f"Machine Type: {info.machine_name} ({info.machine_arch})")
            print(f"Entry Point RVA: {info.entry_point_rva_hex}")
            print(f"Image Base: {info.image_base_hex}")
            print(f"Entry Point VA: {info.entry_point_va_hex}")
            print(f"Is 64-bit: {info.is_64bit}")
            print(f"Number of Sections: {info.number_of_sections}")
            print("\n[File Information]")
            print(f"  Machine:          {info.machine_name} ({info.machine_arch})")
            print(f"  Architecture:     {'64-bit' if info.is_64bit else '32-bit'}")
            print(f"  Entry point RVA:  {info.entry_point_rva_hex}")
            print(f"  Image base:       {info.image_base_hex}")
            print(f"  Entry point VA:   {info.entry_point_va_hex}")
            print(f"  Section count:    {info.number_of_sections}")
            compile_time = str(info.compile_time) if info.compile_time is not None else "Not available"
            print(f"  Compile time:     {compile_time} (Unix timestamp)")
 
            print_sections(info.sections)
            print_imports(info.imports)
 
            if info.compile_time is not None:
                print(f"Compile Time (Unix Timestamp): {info.compile_time}")
            else:
                print("Compile Time: Not available")
            if info.packer_alerts:
                print("\n[Security Notes]")
                for alert in info.packer_alerts:
                    print(f"  - {alert}")
        except ValueError as e:
            print(f"Error parsing PE info for {file_path}: {e}")
            print(f"\nERROR: Could not parse PE information: {e}")
            exit_code = 2

    return exit_code

if __name__ == "__main__":
    sys.exit(main())