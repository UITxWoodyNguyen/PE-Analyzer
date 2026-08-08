'''
This file is used to test the string_extractor.py module.
Usage:
    pytest tests/test_string_extractor.py -v 
'''

from pathlib import Path
import sys
import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from src.core.string_extractor import (
    ExtractedString,
    IOCMatch,
    StringExtractor,
    extracted_strings,
)

# Checkpoint 1: Test the extraction of basic string (ASCII, UTF-16LE, UTF-16BE)
def test_extract_ascii_string():
    # Checking ASCII string extraction and offset
    raw_data = b"\x00\x01\x02Hello, World!\x00\x00Testing123\x00\xff"
    results = extracted_strings(raw_data, min_length = 4, encodings = ["ascii"])

    assert len(results) == 2
    assert results[0].value == "Hello, World!"
    assert results[0].offset == 3
    assert results[0].hex_offset == "0x00000003"
    assert results[0].encoding == "ASCII"
    assert results[0].length == 13

    assert results[1].value == "Testing123"
    assert results[1].offset == 18
    assert results[1].hex_offset == "0x00000012"
    assert results[1].encoding == "ASCII"

def test_extract_utf16le_string():
    # Checking UTF-16LE string extraction and offset
    api_name = "kernel32.dll"
    encoded_payload = b"\x90\x90\x00\x00" + api_name.encode("utf-16le") + b"\x00\x00\xcc\xcc"
    results = extracted_strings(encoded_payload, min_length=4, encodings=["utf-16le"])

    assert len(results) == 1
    assert results[0].value == "kernel32.dll"
    assert results[0].encoding == "UTF-16LE"
    assert results[0].offset == 4
    assert results[0].hex_offset == "0x00000004"

def test_extract_mixed_encodings():
    # Checking mixed encoding extraction
    dos_header = b"This program cannot be run in DOS mode.\r\n\x00\x00"
    c2_url = "https://evil-c2.com/payload.exe"
    data = (
        dos_header
        + b"\x00\x00"
        + c2_url.encode("utf-16le")
        + b"\x00\x00"
    )

    results = extracted_strings(data, min_length=4, encodings=["ascii", "utf-16le"])
    values = [r.value for r in results]

    assert any("This program cannot be run in DOS mode." in v for v in values)
    assert any("https://evil-c2.com/payload.exe" in v for v in values)

def test_min_length_boundary():
    # Testing the minimum length boundary for string extraction
    data = b"abc\x00abcd\x00abcde\x00abcdef\x00"

    res_len4 = extracted_strings(data, min_length=4, encodings=["ascii"])
    assert [r.value for r in res_len4] == ["abcd", "abcde", "abcdef"]

    res_len6 = extracted_strings(data, min_length=6, encodings=["ascii"])
    assert [r.value for r in res_len6] == ["abcdef"]

# Checkpoint 2: Test ipv4 filter with REGEX
def test_filter_ipv4_valid_address():
    # Testing valid IPv4 address extraction
    samples = [
        "C2 connection: 192.168.1.254 on port 443",
        "Public DNS: 8.8.8.8 and 1.1.1.1",
        "Boundary IPs: 0.0.0.0, 255.255.255.255, 10.0.0.1, 172.16.254.1",
    ]

    matches = StringExtractor.filter_ipv4(samples, unique=True)
    extracted_ips = [m.match_value for m in matches]

    assert "192.168.1.254" in extracted_ips
    assert "8.8.8.8" in extracted_ips
    assert "1.1.1.1" in extracted_ips
    assert "0.0.0.0" in extracted_ips
    assert "255.255.255.255" in extracted_ips
    assert "10.0.0.1" in extracted_ips
    assert "172.16.254.1" in extracted_ips

def test_filter_ipv4_rejects_invalid_addresses():
    # Test invalid IPv4 addresses are not matched
    invalid_samples = [
        "Invalid ranges: 999.999.999.999, 256.1.1.1, 192.168.1.300",
        "Version numbers: 1.2.3.4.5, .1.2.3.4, 1234.56.78.90",
    ]

    matches = StringExtractor.filter_ipv4(invalid_samples)
    extracted_ips = [m.match_value for m in matches]

    assert "999.999.999.999" not in extracted_ips
    assert "256.1.1.1" not in extracted_ips
    assert "192.168.1.300" not in extracted_ips
    assert "1234.56.78.90" not in extracted_ips

def test_filter_ipv4_deduplication_and_offset():
    # Test deduplication and offset tracking for IPv4 extraction
    extracted = [
        ExtractedString(value="First IP: 10.0.0.1", offset=100, encoding="ASCII", length=18),
        ExtractedString(value="Duplicate IP: 10.0.0.1", offset=500, encoding="ASCII", length=22),
    ]

    # unique=True: only one record should be kept
    unique_matches = StringExtractor.filter_ipv4(extracted, unique=True)
    assert len(unique_matches) == 1
    assert unique_matches[0].match_value == "10.0.0.1"
    assert unique_matches[0].source_offset == 100 + len("First IP: ")
    assert unique_matches[0].ioc_type == "IPv4"
    assert unique_matches[0].source_encoding == "ASCII"

    # unique=False: both records should be kept
    all_matches = StringExtractor.filter_ipv4(extracted, unique=False)
    assert len(all_matches) == 2

# Checkpoint 3: Prediction Output Validation - Domain + URL filtering
def test_filter_domains_and_urls():
    # Test extraction of domains and URLs from mixed strings
    sample_text = [
        "Beacon URL: https://c2.darknet.top/bot_update.exe?id=123&auth=true",
        "FTP Drop: ftp://backup.attacker-site.com:21/dump.zip",
        "Unprefixed Domain: malicious-gateway.xyz",
        "Subdomain C2: gateway.botnet-network.org",
        "Ransom Portal: ransom-payment.onion",
    ]

    network_iocs = StringExtractor.filter_domains_and_urls(sample_text, unique=True)
    urls = [item.match_value for item in network_iocs["urls"]]
    domains = [item.match_value for item in network_iocs["domains"]]

    # 1.  Check URLs
    assert "https://c2.darknet.top/bot_update.exe?id=123&auth=true" in urls
    assert "ftp://backup.attacker-site.com:21/dump.zip" in urls

    # 2. Check FQDN Domains
    assert "malicious-gateway.xyz" in domains
    assert "gateway.botnet-network.org" in domains
    assert "ransom-payment.onion" in domains

    # 3. Ensure domains found in URLs are not duplicated in the standalone domains list
    assert "c2.darknet.top" not in domains
    assert "backup.attacker-site.com" not in domains

# Checkpoint 4: File Streaming Validation - Test the streaming of file content and extraction of strings
def test_streaming_large_file_cross_chunk_boundary (tmp_path: Path):
    # Check that strings spanning across chunk boundaries are correctly extracted
    test_file = tmp_path / "stream_sample.bin"
    target_string = "SPECIAL_LONG_C2_STRING_192.168.100.200_ENDPOINT"
    
    # Create a binary file with a long prefix, the target string, and a long suffix
    prefix = b"\x00" * 240
    data = prefix + target_string.encode("ascii") + b"\x00" * 300
    test_file.write_bytes(data)

    extractor = StringExtractor(min_len=4)
    # Read with a small chunk size (256 bytes) to test overlap
    streamed_strings = list(extractor.extract_from_file(test_file, chunk_size=256))
    extracted_values = [s.value for s in streamed_strings]

    assert any(target_string in v for v in extracted_values)

    # Check IPv4 extraction from the streamed file content
    ipv4_list = StringExtractor.filter_ipv4(streamed_strings)
    assert any(ip.match_value == "192.168.100.200" for ip in ipv4_list)

# Checkpoint 5: Filter IOC
def test_filter_all_iocs():
    # Check filter_iocs()
    payload = (
        b"Downloading http://attacker.com/miner.exe and saving to malware.dll. "
        b"Connecting to 10.10.10.10. Contact: root@hacker-lab.net. "
        b"Persisting via HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    )

    strings = extracted_strings(payload, min_len=4)
    iocs = StringExtractor.filter_iocs(strings)

    assert any("http://attacker.com/miner.exe" in item.value for item in iocs["url"])
    assert any("10.10.10.10" in item.value for item in iocs["ipv4"])
    assert any("root@hacker-lab.net" in item.value for item in iocs["email"])
    assert any("miner.exe" in item.value or "malware.dll" in item.value for item in iocs["pe_file"])
    assert any("HKLM\\Software\\Microsoft" in item.value for item in iocs["reg_key"])

# Checkpoint 6: Exception Handling - Test that invalid inputs are handled gracefully
def test_invalid_min_len_raises_value_error():
    with pytest.raises(ValueError, match="min_len"):
        StringExtractor(min_len=0)

def test_nonexistent_file_raises_file_not_found():
    # Test that attempting to extract strings from a non-existent file raises FileNotFoundError
    extractor = StringExtractor()
    with pytest.raises(FileNotFoundError):
        list(extractor.extract_from_file("non_existent_binary_file.xyz"))


def test_invalid_target_type_raises_type_error():
    # Test that passing an invalid type to the utility function raises TypeError
    with pytest.raises(TypeError):
        extracted_strings(12345)  # Not a str, Path, or bytes object