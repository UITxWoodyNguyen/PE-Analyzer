"""Tests for the PE parser report output and supporting data structures.

Move this file to the PE-Analyzer project root (or its tests directory) and run:
    python -m unittest test_pe_parser.py
"""

from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

# The test is intended to run from the repository root, where ``src`` is
# importable. It also supports running from a conventional tests/ directory.
PROJECT_ROOT = Path(__file__).resolve().parent
if (PROJECT_ROOT / "src").is_dir():
    sys.path.insert(0, str(PROJECT_ROOT))
elif (PROJECT_ROOT.parent / "src").is_dir():
    sys.path.insert(0, str(PROJECT_ROOT.parent))

from src.core import pe_parser

def make_section(**overrides: object) -> pe_parser.PESectionInfo:
    """Create a representative section, allowing each field to be overridden."""
    values: dict[str, object] = {
        "name": ".text",
        "virtual_address": 0x1000,
        "virtual_address_hex": "0x00001000",
        "virtual_size": 4096,
        "raw_pointer": 0x400,
        "entropy": 6.12,
        "is_readable": True,
        "is_writable": False,
        "is_executable": True,
        "is_suspicious_entropy": False,
        "is_rwx": False,
        "packet_warning": None,
    }
    values.update(overrides)
    return pe_parser.PESectionInfo(**values)  # type: ignore[arg-type]


def make_info() -> pe_parser.PEInfo:
    """Return stable parsed information for testing main() without a PE file."""
    suspicious_section = make_section(
        name="UPX1",
        entropy=7.56,
        is_writable=True,
        is_suspicious_entropy=True,
        is_rwx=True,
        packet_warning="Suspicious entropy: 7.5600 > 7.0 | Section has RWX permissions",
    )
    imported_function = pe_parser.ImportedFunction(
        name="VirtualAlloc",
        ordinal=None,
        address=0x401000,
        is_ordinal=False,
        is_suspicious=True,
    )
    return pe_parser.PEInfo(
        path="sample.exe",
        machine_raw=0x8664,
        machine_name="IMAGE_FILE_MACHINE_AMD64",
        machine_arch="x64 (AMD64)",
        entry_point_rva=0x1234,
        entry_point_rva_hex="0x0000000000001234",
        image_base=0x140000000,
        image_base_hex="0x0000000140000000",
        entry_point_va=0x140001234,
        entry_point_va_hex="0x0000000140001234",
        is_64bit=True,
        number_of_sections=1,
        compile_time=1_700_000_000,
        sections=[suspicious_section],
        imports=[pe_parser.ImportedDLL("KERNEL32.dll", [imported_function])],
        has_packed_sections=True,
        packer_alerts=[suspicious_section.packet_warning],
    )


class PrintSectionsTests(unittest.TestCase):
    def test_print_sections_displays_table_and_warnings(self) -> None:
        section = make_section(
            name=".packed",
            entropy=7.25,
            is_writable=True,
            is_suspicious_entropy=True,
            is_rwx=True,
            packet_warning="Section has RWX permissions",
        )

        with io.StringIO() as buffer, redirect_stdout(buffer):
            pe_parser.print_sections([section])
            output = buffer.getvalue()

        self.assertIn("[Sections]", output)
        self.assertIn("Virtual Address", output)
        self.assertIn(".packed", output)
        self.assertIn("WARNING: RWX, High entropy", output)
        self.assertIn("Note: Section has RWX permissions", output)

    def test_print_sections_handles_an_empty_list(self) -> None:
        with io.StringIO() as buffer, redirect_stdout(buffer):
            pe_parser.print_sections([])
            output = buffer.getvalue()

        self.assertIn("No sections found.", output)


class PrintImportsTests(unittest.TestCase):
    def test_print_imports_displays_summary_and_suspicious_api(self) -> None:
        imported_dll = pe_parser.ImportedDLL(
            "KERNEL32.dll",
            [
                pe_parser.ImportedFunction("VirtualAlloc", None, 0x401000, False, True),
                pe_parser.ImportedFunction(None, 12, 0x401004, True, False),
            ],
        )

        with io.StringIO() as buffer, redirect_stdout(buffer):
            pe_parser.print_imports([imported_dll])
            output = buffer.getvalue()

        self.assertIn("[Imports]", output)
        self.assertIn("1 DLL(s), 2 imported function(s), 1 suspicious", output)
        self.assertIn("KERNEL32.dll", output)
        self.assertIn("VirtualAlloc", output)
        self.assertIn("Ordinal_12", output)
        self.assertIn("SUSPICIOUS", output)

    def test_print_imports_handles_an_empty_list(self) -> None:
        with io.StringIO() as buffer, redirect_stdout(buffer):
            pe_parser.print_imports([])
            output = buffer.getvalue()

        self.assertIn("No imported DLLs found.", output)


class MainTests(unittest.TestCase):
    def test_main_prints_complete_report_for_valid_file(self) -> None:
        validation = pe_parser.PECheckResult("sample.exe", True, "VALID PE FILE")
        with (
            patch.object(pe_parser, "PE_checker", return_value=validation),
            patch.object(pe_parser, "parse_pe_info", return_value=make_info()),
            patch.object(sys, "argv", ["pe_parser.py", "sample.exe"]),
            io.StringIO() as buffer,
            redirect_stdout(buffer),
        ):
            exit_code = pe_parser.main()
            output = buffer.getvalue()

        self.assertEqual(exit_code, 0)
        self.assertIn("PE ANALYSIS REPORT", output)
        self.assertIn("Validation: VALID", output)
        self.assertIn("[File Information]", output)
        self.assertIn("Architecture:     64-bit", output)
        self.assertIn("[Security Notes]", output)

    def test_main_skips_analysis_for_invalid_file(self) -> None:
        validation = pe_parser.PECheckResult("bad.exe", False, "INVALID DOS HEADER SIGNATURE")
        with (
            patch.object(pe_parser, "PE_checker", return_value=validation),
            patch.object(pe_parser, "parse_pe_info") as parse_pe_info,
            patch.object(sys, "argv", ["pe_parser.py", "bad.exe"]),
            io.StringIO() as buffer,
            redirect_stdout(buffer),
        ):
            exit_code = pe_parser.main()
            output = buffer.getvalue()

        self.assertEqual(exit_code, 2)
        parse_pe_info.assert_not_called()
        self.assertIn("Validation: INVALID", output)
        self.assertIn("Analysis skipped because the file is not a valid PE file.", output)


if __name__ == "__main__":
    unittest.main()
