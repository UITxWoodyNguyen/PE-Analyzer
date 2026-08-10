from __future__ import annotations
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Set, Union, Optional
import pefile

# use built-in True/False for boolean defaults

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

@dataclass
class PECheckResult:
    path: str
    isValid_PE: bool
    reason: str

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
            compile_time=compile_time
        )
    except Exception as e:
        raise ValueError(f"Error occurred while parsing PE info: {e}")
    finally:
        pe.close()

def print_imports (imports: List[ImportedDLL]) -> None:
    if not imports:
        print("No imported DLLs found.")
        return

    print("Imported DLLs and Functions:")
    for dll in imports:
        print(f"  DLL: {dll.dll_name} (Functions: {dll.function_count})")
        for func in dll.functions:
            suspicious_flag = " [SUSPICIOUS]" if func.is_suspicious else ""
            print(f"    Function: {func.display_name}, Address: {func.hex_address}{suspicious_flag}")
    
def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python3 pe_parser.py <path_to_file>")
        return 1

    exit_code = 0
    for file_path in sys.argv[1:]:
        # Validation of the PE file
        result = PE_checker(file_path)
        status = "VALID" if result.isValid_PE else "INVALID"
        print(f"{result.path}: {status} - {result.reason}")

        if not result.isValid_PE:
            exit_code = 2

        # Analyze with pefile
        try:
            info = parse_pe_info(file_path)
            print(f"Machine Type: {info.machine_name} ({info.machine_arch})")
            print(f"Entry Point RVA: {info.entry_point_rva_hex}")
            print(f"Image Base: {info.image_base_hex}")
            print(f"Entry Point VA: {info.entry_point_va_hex}")
            print(f"Is 64-bit: {info.is_64bit}")
            print(f"Number of Sections: {info.number_of_sections}")

            imports = parse_pe_import(file_path)
            print_imports(imports)

            if info.compile_time is not None:
                print(f"Compile Time (Unix Timestamp): {info.compile_time}")
            else:
                print("Compile Time: Not available")
        except ValueError as e:
            print(f"Error parsing PE info for {file_path}: {e}")
            exit_code = 2

    return exit_code

if __name__ == "__main__":
    sys.exit(main())