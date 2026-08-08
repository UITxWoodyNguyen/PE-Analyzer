"""
tests/test_eicar_pipeline.py - Script demo & check pipeline for EICAR test file.:
1. Create EICAR test file (68 bytes) in src/samples/eicar_test.com
2. Extract strings via src/core/string_extractor.py
3. Check reputation via src/services/vt_checker.py (Mock data)

Running directly:
    python3 tests/test_eicar_pipeline.py

Running with pytest:
    pytest tests/test_eicar_pipeline.py -v
"""

from pathlib import Path
from unittest.mock import MagicMock
import hashlib
import sys

# Add project root to sys.path for imports
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.string_extractor import extract_strings
from src.services.vt_checker import VTResult, check_hash

# Chuỗi EICAR chuẩn quốc tế (68 bytes)
EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


def create_eicar_file(output_path: Path) -> Path:
    """Create EICAR test file at the specified path."""
    output_path.write_text(EICAR_STRING, encoding="ascii")
    return output_path


def run_eicar_pipeline(file_path: Path) -> tuple[str, list, VTResult]:
    """Run the entire EICAR test file analysis pipeline."""
    create_eicar_file(file_path)

    # 1. Calculate Hashes & Validate
    content = file_path.read_bytes()
    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()

    assert sha256 == EICAR_SHA256, f"SHA-256 không khớp! Lấy được: {sha256}"
    assert md5 == EICAR_MD5, f"MD5 không khớp! Lấy được: {md5}"

    # 2. Extract strings
    extracted = extract_strings(file_path, min_len=4, encodings=["ascii"])

    # 3. Virtual Response từ VirusTotal (Mock Session)
    mock_payload = {
        "data": {
            "attributes": {
                "type_description": "DOS COM",
                "last_analysis_stats": {
                    "malicious": 63,
                    "undetected": 8,
                    "harmless": 0,
                    "suspicious": 0,
                    "timeout": 0,
                },
            }
        }
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_payload

    mock_session = MagicMock()
    mock_session.get.return_value = mock_resp

    # Call check_hash with mock session
    vt_result = check_hash(sha256, api_key="mock_key", session=mock_session)

    return sha256, extracted, vt_result


# ---------------------------------------------------------------------------
# Pytest Test Cases
# ---------------------------------------------------------------------------

def test_eicar_integration_pipeline(tmp_path):
    """Test case for pytest to run automatically."""
    eicar_file = tmp_path / "eicar_test.com"
    sha256, extracted, vt_result = run_eicar_pipeline(eicar_file)

    # Check String Extractor
    extracted_values = [s.value for s in extracted]
    assert any("EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" in val for val in extracted_values)

    # Check VT Checker
    assert vt_result.file_hash == EICAR_SHA256
    assert vt_result.malicious == 63
    assert vt_result.is_flagged is True
    assert vt_result.file_type == "DOS COM"


# ---------------------------------------------------------------------------
# CLI Execution (When running the file directly)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_file = PROJECT_ROOT / "samples" / "eicar_test.com"
    test_file.parent.mkdir(exist_ok=True)

    try:
        sha256, extracted_strings, vt_res = run_eicar_pipeline(test_file)

        print("=" * 65)
        print("[1] THÔNG TIN FILE MẪU EICAR:")
        print(f"  - File Path : {test_file.name}")
        print(f"  - File Size : {test_file.stat().st_size} bytes")
        print(f"  - SHA-256   : {sha256}")
        print(f"  - MD5       : {EICAR_MD5}")

        print("\n[2] CHẠY THỬ NGHIỆM STRING EXTRACTOR:")
        for s in extracted_strings:
            print(f"  - {s.hex_offset} | [{s.encoding}] {s.value}")

        print("\n[3] CHẠY THỬ NGHIỆM VIRUSTOTAL CHECKER (MOCK DATA):")
        print(f"  - File Hash       : {vt_res.file_hash}")
        print(f"  - Detection Ratio : {vt_res.malicious}/{vt_res.total_engines}")
        print(f"  - Is Flagged      : {vt_res.is_flagged}")
        print(f"  - File Type       : {vt_res.file_type}")
        print(f"  - Report Link     : {vt_res.permalink}")
        print("=" * 65)

    finally:
        # Automatically clean up the test file after execution
        if test_file.exists():
            test_file.unlink()