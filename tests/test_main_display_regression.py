import io
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rich.console import Console

from src.main import MalwareAnalysisPipeline
from src.services.vt_checker import VTNotFoundErrors
from src.utils.display import render_rich_report


def test_report_uses_permissions_key_for_sections(pe_x64_exe):
    pipeline = MalwareAnalysisPipeline(pe_x64_exe)
    report = pipeline.run_analysis()

    assert report["pe_analysis"] is not None
    sections = report["pe_analysis"]["sections"]
    assert sections
    assert "permissions" in sections[0]
    assert "permission" not in sections[0]


def test_render_rich_report_handles_valid_report(pe_x64_exe):
    pipeline = MalwareAnalysisPipeline(pe_x64_exe)
    report = pipeline.run_analysis()
    out = io.StringIO()
    console = Console(file=out, force_terminal=False, color_system=None)

    render_rich_report(report, console)

    output = out.getvalue()
    assert "STATIC MALWARE" in output or "Overall Assessment Summary" in output


def test_unknown_vt_hash_is_reported_as_not_found(monkeypatch, pe_x64_exe):
    pipeline = MalwareAnalysisPipeline(pe_x64_exe, query_vt=True, vt_api_key="test-key")

    with patch("src.main.check_hash", side_effect=VTNotFoundErrors("File hash not found: {}")):
        report = pipeline.run_analysis()

    assert report["virustotal"]["status"] == "not_found"
    assert "not found" in report["virustotal"]["message"].lower()
    assert not any("VirusTotal API error" in w for w in report["overall_summary"]["warnings"])
