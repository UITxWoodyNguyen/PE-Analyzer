'''
This file is used to check for "/src/services/vt_checker.py" file.
Usage: pytest test_vt_checker.py -v
'''

from unittest.mock import MagicMock, patch
from pathlib import Path
import sys
import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

import src
from src.services.vt_checker import (
    check_hash,
    get_API_key,
    VTAuthErrors,
    VTNotFoundErrors,
    VTRateLimitErrors,
    VTRequestErrors,
)

VALID_SHA256 = "dc1869706aefb787daeeddea3865f7208fda26d470474db41ea10f40624beb80"
VALID_MD5 = "208a1aa0d4c07aa664cbae0e7b0b296e"

def _mock_response (status_code: int, json_data: dict | None = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text

    return resp

def _mock_session (response: MagicMock) -> MagicMock:
    session = MagicMock()
    session.get.return_value = response

    return session

# Validate hashing type before calling the VT API
@pytest.mark.parametrize("bad_hash", ["", "abc", "z" * 64, "12345"])
def test_invalid_hash_format (bad_hash: str):
    with pytest.raises(ValueError):
        check_hash(bad_hash, api_key = "fake_key")

@pytest.mark.parametrize("good_hash", [VALID_MD5, VALID_SHA256])
def test_valid_hash_format (good_hash):
    payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70, "suspicious": 0, "undetected": 0, "timeout": 0}}}}
    session = _mock_session(_mock_response(200, json_data = payload))
    result = check_hash(good_hash, api_key = "fake_key", session = session)
    assert result.file_hash == good_hash

# API Key Handling
def test_API_key_raises_when_missing (monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising = False)
    with pytest.raises(VTAuthErrors):
        get_API_key()

def test_API_key_read_from_env (monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "env_key")
    assert get_API_key() == "env_key"

def test_check_hash_uses_env_key_when_not_passed (monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "env_key_value")
    payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 1, "suspicious": 0, "undetected": 0, "timeout": 0}}}}
    session = _mock_session(_mock_response(200, json_data = payload))

    check_hash(VALID_SHA256, session = session)

    called_headers = session.get.call_args[1]["headers"]
    assert called_headers["x-apikey"] == "env_key_value"

# Parse HTTP 200 response
def test_parses_clean_file_correctly():
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0, "suspicious": 0, "harmless": 68,
                    "undetected": 2, "timeout": 0,
                },
                "reputation": 10,
                "type_description": "Win32 EXE",
            }
        }
    }
    session = _mock_session(_mock_response(200, payload))
    result = check_hash(VALID_SHA256, api_key="fake_key", session=session)

    assert result.malicious == 0
    assert result.is_flagged is False
    assert result.total_engines == 70
    assert result.file_type == "Win32 EXE"
    assert VALID_SHA256 in result.permalink


def test_parses_malicious_file_correctly():
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 45, "suspicious": 3, "harmless": 20,
                    "undetected": 2, "timeout": 0,
                },
            }
        }
    }
    session = _mock_session(_mock_response(200, payload))
    result = check_hash(VALID_SHA256, api_key="fake_key", session=session)

    assert result.malicious == 45
    assert result.is_flagged is True


def test_missing_stats_defaults_to_zero():
    payload = {"data": {"attributes": {}}}
    session = _mock_session(_mock_response(200, payload))
    result = check_hash(VALID_SHA256, api_key="fake_key", session=session)

    assert result.malicious == 0
    assert result.total_engines == 0
    assert result.is_flagged is False

# HTTP Error Handling
def test_401_raises_vtautherror():
    session = _mock_session(_mock_response(401, text="Wrong API key"))
    with pytest.raises(VTAuthErrors):
        check_hash(VALID_SHA256, api_key="bad_key", session=session)


def test_403_raises_vtautherror():
    session = _mock_session(_mock_response(403, text="Forbidden"))
    with pytest.raises(VTAuthErrors):
        check_hash(VALID_SHA256, api_key="bad_key", session=session)


def test_404_raises_vtnotfounderror():
    session = _mock_session(_mock_response(404, text="Not found"))
    with pytest.raises(VTNotFoundErrors):
        check_hash(VALID_SHA256, api_key="fake_key", session=session)


def test_429_raises_vtratelimiterror():
    session = _mock_session(_mock_response(429, text="Too many requests"))
    with pytest.raises(VTRateLimitErrors):
        check_hash(VALID_SHA256, api_key="fake_key", session=session)


def test_unexpected_status_raises_vtrequesterror():
    session = _mock_session(_mock_response(500, text="Internal Server Error"))
    with pytest.raises(VTRequestErrors):
        check_hash(VALID_SHA256, api_key="fake_key", session=session)


def test_malformed_json_raises_vtrequesterror():
    session = _mock_session(_mock_response(200, json_data=None))
    with pytest.raises(VTRequestErrors):
        check_hash(VALID_SHA256, api_key="fake_key", session=session)


def test_missing_expected_keys_raises_vtrequesterror():
    session = _mock_session(_mock_response(200, json_data={"unexpected": "shape"}))
    with pytest.raises(VTRequestErrors):
        check_hash(VALID_SHA256, api_key="fake_key", session=session)

# Network Error Handling / Timeouts
def test_timeout_raises_vtrequesterror():
    import requests as requests_module

    session = MagicMock()
    session.get.side_effect = requests_module.exceptions.Timeout()
    with pytest.raises(VTRequestErrors):
        check_hash(VALID_SHA256, api_key="fake_key", session=session)


def test_connection_error_raises_vtrequesterror():
    import requests as requests_module

    session = MagicMock()
    session.get.side_effect = requests_module.exceptions.ConnectionError()
    with pytest.raises(VTRequestErrors):
        check_hash(VALID_SHA256, api_key="fake_key", session=session)

# Format Headers and Endpoint
def test_api_key_sent_via_header_not_url():
    payload = {"data": {"attributes": {"last_analysis_stats": {"harmless": 1}}}}
    session = _mock_session(_mock_response(200, payload))

    check_hash(VALID_SHA256, api_key="super_secret_key", session=session)

    call = session.get.call_args
    url_arg = call.args[0] if call.args else call.kwargs.get("url", "")
    assert "super_secret_key" not in url_arg
    assert call.kwargs["headers"]["x-apikey"] == "super_secret_key"


def test_correct_endpoint_called():
    payload = {"data": {"attributes": {"last_analysis_stats": {"harmless": 1}}}}
    session = _mock_session(_mock_response(200, payload))

    check_hash(VALID_SHA256, api_key="fake_key", session=session)

    call = session.get.call_args
    url_arg = call.args[0] if call.args else call.kwargs.get("url", "")
    assert url_arg == f"https://www.virustotal.com/api/v3/files/{VALID_SHA256}"