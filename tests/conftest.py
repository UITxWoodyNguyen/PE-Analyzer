from pathlib import Path
import sys
import pytest

PROJECT_ROOT = Path(__file__).parent.parent
SAMPLE_DIR = PROJECT_ROOT / "samples"

# Fetch all sample files in the /samples directory
@pytest.fixture(scope = "session")
def pe_x64_exe():
    # Load /samples/windowsAPI.exe 
    exe_path = SAMPLE_DIR / "windowsAPI.exe"

    if not exe_path.exists():
        exe_path = SAMPLE_DIR / "helloWorld.exe"
    if not exe_path.exists():
        raise FileNotFoundError(f"Sample file not found: {exe_path}")

    return exe_path

@pytest.fixture(scope = "session")
def pe_x86_exe():
    # Load /samples/helloWorld.exe
    exe_path = SAMPLE_DIR / "helloWorld.exe"

    if not exe_path.exists():
        exe_path = SAMPLE_DIR / "windowsAPI.exe"
    if not exe_path.exists():
        raise FileNotFoundError(f"Sample file not found: {exe_path}")

    return exe_path

@pytest.fixture
def temp_path(tmp_path):
    return tmp_path

# Mutate byte of a valid PE file to create a corrupted PE file
@pytest.fixture
def truncated_byte(temp_path):
    # Create a temporary file with only the first byte of a valid PE file (MZ header)
    p = temp_path / "1byte.exe"
    p.write_bytes(b'\x4D')  # Write only the first byte of a valid PE file (MZ header)
    return p

@pytest.fixture
def truncated_1byte(truncated_byte):
    return truncated_byte

@pytest.fixture
def truncated_before_header(pe_x64_exe, temp_path):
    # Create a temporary file with the first 10 bytes of a valid PE file (MZ header)
    p = temp_path / "truncated_pe.exe"
    p.write_bytes(pe_x64_exe.read_bytes()[:0x3C])  # cut off before e_lfanew field
    return p

@pytest.fixture
def corrupted_pe(pe_x64_exe, temp_path):
    # Create a temporary file with a corrupted PE file (MZ error)
    p = temp_path / "corrupted_pe.exe"
    data = bytearray(pe_x64_exe.read_bytes())
    data[0:2] = b"XX"   # Corrupt the MZ header
    p.write_bytes(data)
    return p

@pytest.fixture
def fake_pe_signature(pe_x64_exe, temp_path):
    # Create a temporary file has "MZ" but PE Signature is changed to "XX"
    p = temp_path / "fake_pe_sig.exe"
    data = bytearray(pe_x64_exe.read_bytes())
    pe_offset = int.from_bytes(data[0x3C:0x40], byteorder='little')
    data[pe_offset:pe_offset+2] = b"XX"  # Corrupt the PE signature
    p.write_bytes(data)
    return p

@pytest.fixture
def fake_MZ(fake_pe_signature):
    return fake_pe_signature

@pytest.fixture
def fake_text_exe(temp_path):
    # Create a temporary file with a text file that has "MZ" at the beginning
    p = temp_path / "fake_text.exe"
    p.write_bytes(b"MZ This is not a valid PE file.")
    return p

@pytest.fixture
def empty_exe(temp_path):
    # Create a temporary file that is empty
    p = temp_path / "empty.exe"
    p.write_bytes(b"")
    return p

@pytest.fixture
def non_existent_file(temp_path):
    return temp_path / "does_not_exist.exe"