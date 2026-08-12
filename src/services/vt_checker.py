'''
This file is used to interact with the VirusTotal API v3.
It provides functions to check the reputation of files, URLs, and IP address using the VT API v3.

Usage: 
'''

from dataclasses import dataclass, field
from typing import Any, Dict, Optional
import requests
import os
import re
from pathlib import Path

# Custom Exceptions

class VTErrors (Exception):
    # Base exception for VT API errors
    pass

class VTAuthErrors (VTErrors):
    # Exception for authentication errors
    pass

class VTNotFoundErrors (VTErrors):
    # Exception for not found errors
    pass

class VTRateLimitErrors (VTErrors):
    # Exception for rate limit errors
    pass

class VTRequestErrors (VTErrors):
    # Exception for request errors
    pass


def _load_dotenv() -> Optional[str]:
    """Read VT_API_KEY from a local .env file if it has not already been set."""

    if os.getenv("VT_API_KEY"):
        return os.getenv("VT_API_KEY")

    candidate_paths = [Path.cwd() / ".env"]

    for dotenv_path in candidate_paths:
        if not dotenv_path.is_file():
            continue

        try:
            for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                if key.strip() != "VT_API_KEY":
                    continue

                cleaned_value = value.strip().strip('"').strip("'")
                if cleaned_value:
                    return cleaned_value
        except OSError:
            return None

    return None

# Dataclass for VT API response
@dataclass
class VTResult:
    file_hash: str  # The file hash (MD5 or SHA256) that was checked
    malicious: int  # The number of engines that flagged the file as malicious
    total_engines: int  # The total number of engines that analyzed the file
    is_flagged: bool  # Indicates if the file is flagged as malicious
    file_type: str  # The type of the file
    permalink: str  # The permalink to the file's report on VirusTotal
    engine_detections: Dict[str, Optional[str]] = field(default_factory = dict)

# Helper function to interact with the VT API
def get_API_key() -> str:
    '''
    This function retrieves the VT API key from a local .env file or the environment variable 'VT_API_KEY'
    Return 'VTAuthErrors' if the key is not found.
    '''

    api_key = os.getenv('VT_API_KEY') or _load_dotenv()
    if not api_key:
        raise VTAuthErrors("VT API key not found. Create a .env file with VT_API_KEY=your_key or set the environment variable.")
    return api_key

def _validate_hash (file_hash: str) -> bool:
    '''
    This function is used to validate the file hash.
    It only accpets MD5 (32 hex) or SHA256 (64 hex) hashes.
    '''

    clean_hash = file_hash.strip().lower()
    is_md5 = bool(re.fullmatch(r'[a-f0-9]{32}', clean_hash))
    is_sha256 = bool(re.fullmatch(r'[a-f0-9]{64}', clean_hash))

    if not (is_md5 or is_sha256):
        raise ValueError("Invalid file hash. Only MD5 (32 hex) or SHA256 (64 hex) hashes are accepted.")

    return clean_hash

def parse_VT_response (data: Dict[str, Any], file_hash: str) -> VTResult:
    '''
    This function is used to parse the VT API response and extract relevant information,
    Arguments:
        - param data: The JSON response from the VT API.
        - param file_hash: The file hash that was checked.

    Process:
        1. Extract the 'attributes' field from the response.
        2. Extract the 'last_analysis_stats' field from the attributes.
        3. Calculate the number of malicious detections and total engines.
        4. Determine if the file is flagged as malicious.
        5. Extract the file type and permalink.
    '''

    if not isinstance(data, dict) or 'data' not in data or 'attributes' not in data['data']:
        raise VTRequestErrors(f"Unexpected JSON structure: {data}")

    attributes = data['data']['attributes']
    stats = attributes.get('last_analysis_stats', {})

    # Stats Parsing: positives/total
    malicious = stats.get("malicious", 0) if isinstance(stats, dict) else 0
    total_engines = sum(stats.values()) if isinstance(stats, dict) else 0
    is_flagged = malicious > 0
    file_type = attributes.get("type_description", "Unknown")
    permalink = f"https://www.virustotal.com/gui/file/{file_hash}"

    analysis_results = attributes.get("last_analysis_results", {})
    target_engines = ["Microsoft", "Kaspersky", "ESET-NOD32", "BitDefender", "Avast", "AVG", "McAfee"]
    engine_detections: Dict[str, Optional[str]] = {}

    for engine in target_engines:
        engine_data = analysis_results.get(engine)
        if engine_data and isinstance(engine_data, dict):
            # Result has a 'result' field, which can be None or a string indicating the detection
            engine_detections[engine] = engine_data.get("result")
        else:
            engine_detections[engine] = None

    return VTResult(
        file_hash = file_hash,
        malicious = malicious,
        total_engines = total_engines,
        is_flagged = is_flagged,
        file_type = file_type,
        permalink = permalink,
        engine_detections = engine_detections
    )
    

# Main Function to check file reputation using VT API v3
def check_hash (file_hash: str, api_key: Optional[str] = None, session: Optional[requests.Session] = None) -> VTResult:
    '''
    Send request to VT API v3 to research the reputation of a file hash.
    Arguments list:
        - param file_hash: MD5 or SHA256 code need to be checked
        - param api_key: Author's API_KEY. If not provided, it will be retrieved from the environment variable 'VT_API_KEY'.
        - param session: Optional requests.Session object for connection pooling. If not provided, a new session will be created.

    Return: VTResult object containing the reputation information of the file hash.
    '''

    clean_hash = _validate_hash(file_hash)
    key = api_key or get_API_key()

    url = f"https://www.virustotal.com/api/v3/files/{clean_hash}"
    headers = {"x-apikey": key, "Accept": "application/json"}

    client = session if session is not None else requests

    # Step 1: Send HTTP Request to VT API
    try:
        response = client.get(url, headers = headers)
    except requests.exceptions.RequestException as e:
        raise VTRequestErrors(f"Error while sending request to VT API: {e}")

    # Step 2: HTTP Status Code Handling
    status_code = response.status_code
    if status_code in (401, 403):
        raise VTAuthErrors(f"Authentication error: {response.text}")
    elif status_code == 404:
        raise VTNotFoundErrors(f"File hash not found: {response.text}")
    elif status_code == 429:
        raise VTRateLimitErrors(f"Rate limit exceeded: {response.text}")
    elif status_code != 200:
        raise VTRequestErrors(f"Unexpected error: {response.text}")

    # Step 3: Parse JSON Response
    try:
        data = response.json()
    except (ValueError, TypeError) as e:
        raise VTRequestErrors(f"Error while parsing JSON response: {e}")

    # Step 4: Parse the VT API response and return a VTResult object
    return parse_VT_response(data, clean_hash)