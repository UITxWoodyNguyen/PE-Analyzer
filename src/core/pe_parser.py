from __future__ import annotations
import sys
from pathlib import Path
from dataclasses import dataclass

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

@dataclass
class PECheckResult:
    path: str
    isValid_PE: bool
    reason: str

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

def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python3 pe_parser.py <path_to_file>")
        return 1

    exit_code = 0
    for file_path in sys.argv[1:]:
        result = PE_checker(file_path)
        status = "VALID" if result.isValid_PE else "INVALID"
        print(f"{result.path}: {status} - {result.reason}")

        if not result.isValid_PE:
            exit_code = 2

    return exit_code

if __name__ == "__main__":
    sys.exit(main())