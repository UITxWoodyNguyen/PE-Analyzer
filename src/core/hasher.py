from __future__ import annotations
import sys
import hashlib
from pathlib import Path
from dataclasses import dataclass

'''
File Usage: Calculate MD5 hash code and SHA256 hash code of a file by read each chunk of the file.
Not try to load the whole file into memory, so it can handle large files.

Usage: python3 hasher.py <path_to_file>
'''

DEFAULT_CHUNK_SIZE = 64 * 1024   # 64KB

@dataclass
class HashResult:
    path: str
    size_bytes: int
    md5_hash: str
    sha256_hash: str

class HashError(Exception):
    pass

def calculate_hash (file_path: str | Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> HashResult:
    '''
    Arguments:
        file_path: path of the file need to be hashed
        chunk_size: size of each chunk to read from the file, default is 64 KB

    Returns: HashResult(path, size_bytes, md5_hash, sha256_hash)
    Raises: HashError if the file cannot be read or hashed
    '''

    path = Path(file_path)

    if chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")

    md5_hasher = hashlib.md5()  # Init MD5 Hasher
    sha256_hasher = hashlib.sha256()    # Init sha256 Hasher
    total_bytes = 0     # Total bytes read from the file

    try:
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                total_bytes += len(chunk)   # Update total bytes read
                md5_hasher.update(chunk)    # Update MD5 hash with the chunk
                sha256_hasher.update(chunk)     # Update SHA256 hash with the chunk
    except FileNotFoundError:
        raise HashError(f"File not found: {path}")
    except PermissionError:
        raise HashError(f"Permission denied: {path}")
    except OSError as e:
        raise HashError(f"OS error occurred while reading the file: {e}")

    _path = str(path)
    _size_bytes = total_bytes
    _md5_hash = md5_hasher.hexdigest()
    _sha256_hash = sha256_hasher.hexdigest()

    return HashResult(_path, _size_bytes, _md5_hash, _sha256_hash)

def printResult(result: HashResult) -> None:
    print(f"File: {result.path}")
    print(f"Size: {result.size_bytes} bytes")
    print(f"MD5: {result.md5_hash}")
    print(f"SHA256: {result.sha256_hash}")
    print()

def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python3 hasher.py <path_to_file>")
        return 1

    exit_code = 0
    for file_path in sys.argv[1:]:
        try:
            result = calculate_hash(file_path)
            printResult(result=result)
        except HashError as e:
            print(f"Error occurred while hashing {file_path}: {e}")
            exit_code = 2

    return exit_code

if __name__ == "__main__":
    sys.exit(main())