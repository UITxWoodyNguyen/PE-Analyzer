'''
This module is used to extract ASCII and Unicode strings from binary data. 
It provides functions to identify and extract sequences of printable characters, which can be useful for analyzing binary files, debugging, or reverse engineering.
'''

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Generator, Iterable, List, Optional, Pattern, Set, Union
import re

@dataclass(frozen = True)
class ExtractedString:
    # This dataclass represents an extracted string from binary data.
    value: str  # The extracted string value
    offset: int  # The offset in the binary data where the string was found
    encoding: str  # The encoding of the extracted string (e.g., 'ascii', 'utf-16-le')
    length: int  # The length of the extracted string in bytes

    @property
    def hex_offset(self) -> str:
        # Returns the offset as a hexadecimal string
        return f"0x{self.offset:08X}"

@dataclass(frozen = True)
class IOCMatch:
    # This dataclass represents a match for an IOC pattern
    match_value: str # The matched value
    ioc_type: str # The type of IOC (e.g., 'url', 'ipv4', 'email', etc.)
    source_offset: int # The offset in the binary data where the match was found
    source_encoding: str # The encoding of the source string from which the match was found

    @property
    def hex_offset(self) -> str:
        # Returns the source offset as a hexadecimal string
        return f"0x{self.source_offset:08X}"

class StringExtractor:
    # This class provides method to extract strings from binary data.

    # Figure out IOC (Indicator of Compromise) patterns for strings that are commonly used in malware analysis.
    IOC_PATTERNS: Dict[str, Pattern[str]] = {
        "url": re.compile(r"https?://[a-zA-Z0-9_\-\.\:\@\/\?\=\&\%\#\+]+", re.IGNORECASE),
        "ipv4": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
        "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "pe_file": re.compile(r"\b[\w\-\.]+\.(?:exe|dll|sys|ocx|scr|bat|cmd|vbs|ps1)\b", re.IGNORECASE),
        "reg_key": re.compile(r"\b(?:HKLM|HKCU|HKCR|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[\w\\]+\b", re.IGNORECASE),
    }

    URL_REGEX: Pattern[str] = re.compile(r"\b(?:https?|ftp)://[a-zA-Z0-9_\-\.\:\@\/\?\=\&\%\#\+]+", re.IGNORECASE)
    IPV4_REGEX: Pattern[str] = re.compile(
        r"(?<!\d)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\d)"
    )
    DOMAIN_REGEX: Pattern[str] = re.compile(
        r"\b(?:[A-Za-z0-9-]+\.)+(?:[A-Za-z]{2,}|onion)\b",
        re.IGNORECASE,
    )

    def __init__(self, min_length: int = 4, encodings: Optional[Iterable[str]] = None, *, min_len: Optional[int] = None) -> None:
        '''
        Arguments explanation:
            - min_length: Minimum length of strings to extract. Default is 4.
            - encodings: List of encodings to consider for string extraction. If None, defaults to ['ascii', 'utf-16-le'].
        '''

        if min_len is not None:
            min_length = min_len

        if min_length < 1:
            raise ValueError("min_len must be at least 1.")

        self.min_length = min_length
        self.encodings = {
            e.lower().replace("_", "").replace("-", "")
            for e in (encodings or ['ascii', 'utf-16-le', 'utf-16-be'])
        }

        # Step 1: Regex ASCII 
        self._ascii_pattern = re.compile(rb"[\x20-\x7E\t\r\n]{" + str(self.min_length).encode("ascii") + rb",}")    # Printable ASCII characters (space to tilde, tab, carriage return, newline)

        # Step 2: Regex UTF-16 LE
        self._utf16le_pattern = re.compile(rb"(?:[\x20-\x7E]\x00){" + str(self.min_length).encode("ascii") + rb",}")  # Printable UTF-16 LE characters (space to tilde, followed by null byte)

        #Step 3: Regex UTF-16 BE
        self._utf16be_pattern = re.compile(rb"(?:\x00[\x20-\x7E]){" + str(self.min_length).encode("ascii") + rb",}")  # Printable UTF-16 BE characters (null byte followed by space to tilde)

    def extract_from_bytes (self, data: bytes, base_offset: int = 0) -> List[ExtractedString]:
        '''
        Extracts strings from bytes cache in RAM
        Arguments:
            - data: Bytes data need to be scanned
            - base_offset: The base offset to add to the found string offsets. Default is 0.
        Returns: a list of ExtractedString objects containing the extracted strings and their metadata.
        '''

        results: List[ExtractedString] = []

        # Step 1: Scan for ASCII strings
        if "ascii" in self.encodings:
            for match in self._ascii_pattern.finditer(data):
                raw_bytes = match.group()
                value = raw_bytes.decode("ascii", errors = "replace")
                offset = base_offset + match.start()
                results.append(ExtractedString(value=value, offset=offset, encoding="ASCII", length=len(raw_bytes)))

        # Step 2: Scan for UTF-16 LE strings
        if "utf16le" in self.encodings:
            for match in self._utf16le_pattern.finditer(data):
                raw_bytes = match.group()
                try:
                    value = raw_bytes.decode("utf-16-le", errors = "replace")
                    offset = base_offset + match.start()
                    results.append(ExtractedString(value=value, offset=offset, encoding="UTF-16LE", length=len(raw_bytes)))
                except UnicodeDecodeError:
                    continue  # Skip invalid UTF-16 LE sequences

        # Step 3: Scan for UTF-16 BE strings
        if "utf16be" in self.encodings:
            for match in self._utf16be_pattern.finditer(data):
                raw_bytes = match.group()
                try:
                    value = raw_bytes.decode("utf-16-be", errors = "replace")
                    offset = base_offset + match.start()
                    results.append(ExtractedString(value=value, offset=offset, encoding="UTF-16BE", length=len(raw_bytes)))
                except UnicodeDecodeError:
                    continue  # Skip invalid UTF-16 BE sequences

        results.sort(key=lambda x: x.offset)  # Sort results by offset
        return results

    def extract_from_file(self, file_path: Union[str, Path], chunk_size: int = 1024 * 1024) -> Generator[ExtractedString, None, None]:
        '''
        String extraction from a file by using chunk-by-chunk reading to handle large files efficiently.
        Arguments:
            - file_path: Path to the file to be scanned.
            - chunk_size: Size of each chunk to read from the file. Default is 1 MB.
        Returns: a generator yielding ExtractedString objects containing the extracted strings and their metadata.
        '''

        file_path = Path(file_path)
        if not file_path.is_file():
            raise FileNotFoundError(f"The file {file_path} does not exist.")

        overlap_size = max(self.min_length * 4, 128)  # Ensure enough overlap for multi-byte encodings
        leftover = b""  # Store leftover bytes from the previous chunk
        current_offset = 0  # Track the current offset in the file

        with file_path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    if leftover:
                        for s in self.extract_from_bytes(leftover, base_offset=current_offset):
                            yield s
                    break  # End of file reached

                combined = leftover + chunk  # Combine leftover from previous chunk with the current chunk
                for s in self.extract_from_bytes(combined, base_offset=current_offset):
                    yield s

                current_offset += len(chunk)  # Update the current offset
                leftover = combined[-overlap_size:] if len(combined) > overlap_size else combined  # Keep the last part of the combined chunk for the next iteration

    @classmethod
    def filter_ipv4 (cls, strings: Iterable[Union[ExtractedString, str]], unique: bool = True) -> List[IOCMatch]:
        '''
        Filter extracted strings to find valid IPv4 addresses.
        Arguments:
            - strings: An iterable of ExtractedString objects or raw strings to filter.
            - unique: If True, only unique IPv4 addresses will be returned. Default is True.
        Returns: A list of IOCMatch objects containing the matched IPv4 addresses and their metadata.
        '''

        result: List[IOCMatch] = []
        seen: Set[str] = set()  # To track unique IPv4 addresses

        for item in strings:
            text = item.value if isinstance(item, ExtractedString) else str(item)
            offset = item.offset if isinstance(item, ExtractedString) else 0
            encoding = item.encoding if isinstance(item, ExtractedString) else "UNKNOWN"

            for match in cls.IPV4_REGEX.finditer(text):
                ip_str = match.group()
                if unique and ip_str in seen:
                    continue

                seen.add(ip_str)
                result.append(IOCMatch(match_value=ip_str, ioc_type="IPv4", source_offset=offset + match.start(), source_encoding=encoding))

        return result

    @classmethod
    def filter_domains_and_urls(cls, strings: Iterable[Union[ExtractedString, str]], unique: bool = True) -> Dict[str, List[IOCMatch]]:
        '''
        Filter extracted strings to find valid URLS and domains.
        Arguments:
            - strings: An iterable of ExtractedString objects or raw strings to filter.
            - unique: If True, only unique URLs and domains will be returned. Default is True.

        Returns: A dictionary with keys 'url' and 'domain', each containing a list of IOCMatch objects for the matched URLs and domains.
        '''

        urls: List[IOCMatch] = []
        domains: List[IOCMatch] = []
        seen_urls: Set[str] = set()  # To track unique URLs
        seen_domains: Set[str] = set()  # To track unique domains

        for item in strings:
            text = item.value if isinstance(item, ExtractedString) else str(item)
            offset = item.offset if isinstance(item, ExtractedString) else 0
            encoding = item.encoding if isinstance(item, ExtractedString) else "UNKNOWN"

            # Step 1: Extract URLs
            for match in cls.URL_REGEX.finditer(text):
                url_str = match.group()
                if unique and url_str in seen_urls:
                    continue

                seen_urls.add(url_str)
                urls.append(IOCMatch(match_value=url_str, ioc_type="url", source_offset=offset + match.start(), source_encoding=encoding))

            # Step 2: Extract Domans
            for match in cls.DOMAIN_REGEX.finditer(text):
                dom_str = match.group()
                if any(dom_str in u for u in seen_urls):
                    continue  # Skip if the domain is part of a previously found URL
                if unique and dom_str in seen_domains:
                    continue
                seen_domains.add(dom_str)
                domains.append(IOCMatch(match_value=dom_str, ioc_type="domain", source_offset=offset + match.start(), source_encoding=encoding))

        return {"urls": urls, "domains": domains}

    @classmethod
    def filter_IOCS (cls, extracted_strings: Iterable[ExtractedString]) -> Dict[str, List[ExtractedString]]:
        '''
        Filter extracted strings type base on IOC patterns defined in the class.
        '''

        classifield: Dict[str, List[ExtractedString]] = {key: [] for key in cls.IOC_PATTERNS.keys()}
        for items in extracted_strings:
            for key, pattern in cls.IOC_PATTERNS.items():
                if pattern.search(items.value):
                    classifield[key].append(items)
        return classifield

    @classmethod
    def filter_iocs(cls, extracted_strings: Iterable[ExtractedString]) -> Dict[str, List[ExtractedString]]:
        return cls.filter_IOCS(extracted_strings)

def extracted_strings(target: Union[bytes, str, Path], min_length: int = 4, encodings: Optional[Iterable[str]] = None, *, min_len: Optional[int] = None) -> List[ExtractedString]:
    '''
    A convenience function to extract strings from bytes or a file.
    Arguments:
        - target: The target data to extract strings from. Can be bytes, a file path (str or Path).
        - min_length: Minimum length of strings to extract. Default is 4.
    '''

    if min_len is not None:
        min_length = min_len

    extractor = StringExtractor(min_length=min_length, encodings=encodings)
    if isinstance(target, (str, Path)):
        return list(extractor.extract_from_file(target))
    elif isinstance(target, bytes):
        return list(extractor.extract_from_bytes(target))
    else:
        raise TypeError("Unsupported target type. Please provide bytes, a file path (str or Path), or a file object.")


def extract_strings(target: Union[bytes, str, Path], min_length: int = 4, encodings: Optional[Iterable[str]] = None, *, min_len: Optional[int] = None) -> List[ExtractedString]:
    return extracted_strings(target, min_length=min_length, encodings=encodings, min_len=min_len)