import unittest
import hashlib
import sys
import pytest
from pathlib import Path

'''
This file is used to test `pe_checker.py` and `hasher.py` modules.
Compile: "python3 test_hasher.py -v"
'''

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from src.core.hasher import calculate_hash, HashError
from src.core.pe_parser import PE_checker

def reference_hash(path: Path) -> tuple[str, str]:
    '''
    Calculate MD5 and SHA256 ground-truth independence hash values for a given file.
    '''

    data = path.read_bytes()
    md5_hash = hashlib.md5(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()
    return md5_hash, sha256_hash

# Test 01: Checking valid PE file 
def isValid_x64_exe(pe_x64_exe):
    result = PE_checker(pe_x64_exe)
    assert result.isValid_PE is True, f"Expected True, got {result.isValid_PE}"

def isValid_x86_exe(pe_x86_exe):
    result = PE_checker(pe_x86_exe)
    assert result.isValid_PE is True, f"Expected True, got {result.isValid_PE}"

def header_quick_check(pe_x64_exe):
    result = PE_checker(pe_x64_exe, full_check = False)
    assert result.isValid_PE is True

# Test 02: Detection and handling of invalid PE file
def test_truncated_1byte_rejected (truncated_1byte):
    result = PE_checker(truncated_1byte)
    assert result.isValid_PE is False

def test_truncated_before_header_rejected (truncated_before_header):
    result = PE_checker(truncated_before_header)
    assert result.isValid_PE is False

def test_corrupted_reject (corrupted_pe):
    result = PE_checker(corrupted_pe)
    assert result.isValid_PE is False

def fake_exe_rejected (fake_exe):
    result = PE_checker(fake_exe)
    assert result.isValid_PE is False

def test_fake_signature_rejected (fake_MZ):
    result = PE_checker(fake_MZ, full_check = True)
    assert result.isValid_PE is False, f"Expected False, got {result.isValid_PE}"

    result = PE_checker(fake_MZ, full_check = False)
    assert result.isValid_PE is True, f"Expected True, got {result.isValid_PE}"

def file_not_found(non_existent_file):
    result = PE_checker(non_existent_file)
    assert result.isValid_PE is False

# Test 03: Hashing module to calculate MD5 and SHA256 hash values
@pytest.mark.parametrize("fixture_name", ["pe_x64_exe", "pe_x86_exe"])
def test_hash_matches_ref (fixture_name, request):
    path = request.getfixturevalue(fixture_name)
    result = calculate_hash(path)
    expected_md5, expected_sha256 = reference_hash(path)

    assert result['md5'] == expected_md5, f"MD5 mismatch: expected {expected_md5}, got {result['md5']}"
    assert result['sha256'] == expected_sha256, f"SHA256 mismatch: expected {expected_sha256}, got {result['sha256']}"
    assert result['file_size'] == path.stat().st_size, f"File size mismatch: expected {path.stat().st_size}, got {result['file_size']}"


@pytest.mark.parametrize("chunk_size", [1, 64, 4096, 65536])
def test_hash_chunk_independence(pe_x64_exe, chunk_size):
    result = calculate_hash(pe_x64_exe, chunk_size=chunk_size)
    expected_md5, expected_sha256 = reference_hash(pe_x64_exe)

    assert result['md5'] == expected_md5, f"MD5 mismatch: expected {expected_md5}, got {result['md5']}"
    assert result['sha256'] == expected_sha256, f"SHA256 mismatch: expected {expected_sha256}, got {result['sha256']}"

def test_hash_nonexistent_file(non_existent_file):
    with pytest.raises(HashError):
        calculate_hash(non_existent_file)

# Test 04: Merge process: Check PE -> Hashing -> Compare with reference hash
def full_process_check(pe_x64_exe):
    pe_result = PE_checker(pe_x64_exe)
    assert pe_result.isValid_PE is True

    hash_result = calculate_hash(pe_x64_exe)
    assert len(hash_result['md5']) == 32
    assert len(hash_result['sha256']) == 64