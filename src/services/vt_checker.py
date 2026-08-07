'''
This file is used to interact with the VirusTotal API v3.
It provides functions to check the reputation of files, URLs, and IP address using the VT API v3.

Usage: 
'''

from dataclasses import dataclass
import requests
import os
import re

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

# Dataclass for VT API response
@dataclass
class VTResult:
    file_hash: str
    malicious: int
    total_engines: int
    is_flagged: bool
    file_type: str
    permalink: str

# Helper function to interact with the VT API
def get_API_key() -> str:
    '''
    This function retrieves the VT API key from the environment variable 'VT_API_KEY'
    Return 'VTAuthErrors' if the key is not found.
    '''

    api_key = os.getenv('VT_API_KEY')
    if not api_key:
        raise VTAuthErrors("VT API key not found in environment variables. Please set 'VT_API_KEY'.")
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

# Main Function to check file reputation using VT API v3
def check_hash (file_hash: str, api_key: str | None = None, session: requests.Session | None = None) -> VTResult:
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
    headers = {"x-apikey": key}

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

    # Step 4: Check Responding JSON Structure
    if not isinstance(data, dict) or 'data' not in data or 'attributes' not in data['data']:
        raise VTRequestErrors(f"Unexpected JSON structure: {data}")

    attributes = data['data']['attributes']
    stats = attributes.get('last_analysis_stats', {})

    # Step 5: Analyze information fields and return VTResult object
    malicious = stats.get("malicious", 0) if isinstance(stats, dict) else 0
    total_engines = sum(stats.values()) if isinstance(stats, dict) else 0
    is_flagged = malicious > 0
    file_type = attributes.get("type_description", "Unknown") 
    permalink = f"https://www.virustotal.com/gui/file/{clean_hash}"

    return VTResult(
        file_hash = clean_hash,
        malicious = malicious,
        total_engines = total_engines,
        is_flagged = is_flagged,
        file_type = file_type,
        permalink = permalink
    )