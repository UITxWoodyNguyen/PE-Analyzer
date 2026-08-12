"""
Package: src.utils
"""

from src.utils.blacklist import (
    APISeverity,
    APIThreatInfo,
    API_DATABASE,
    DANGEROUS_APIS_SET,
    is_blacklisted_api,
    get_api_threat_info,
    inspect_apis,
    summarize_api_risks,
    load_blacklist_database,
    reload_database,
)

try:
    from src.utils.display import (
        console,
        render_banner,
        display_file_summary,
        display_pe_header,
        display_sections_table,
        display_blacklist_apis,
        display_import_tree,
        display_ioc_strings,
        display_virustotal_panel,
        display_overall_verdict,
        render_rich_report,
    )
except ModuleNotFoundError:
    console = None
    render_banner = None
    display_file_summary = None
    display_pe_header = None
    display_sections_table = None
    display_blacklist_apis = None
    display_import_tree = None
    display_ioc_strings = None
    display_virustotal_panel = None
    display_overall_verdict = None
    render_rich_report = None

__all__ = [
    # Blacklist
    "APISeverity",
    "APIThreatInfo",
    "API_DATABASE",
    "DANGEROUS_APIS_SET",
    "is_blacklisted_api",
    "get_api_threat_info",
    "inspect_apis",
    "summarize_api_risks",
    "load_blacklist_database",
    "reload_database",
    # Display & UI
    "console",
    "render_banner",
    "display_file_summary",
    "display_pe_header",
    "display_sections_table",
    "display_blacklist_apis",
    "display_import_tree",
    "display_ioc_strings",
    "display_virustotal_panel",
    "display_overall_verdict",
    "render_rich_report",
]
