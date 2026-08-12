import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rich.console import Console

from src.main import MalwareAnalysisPipeline
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
