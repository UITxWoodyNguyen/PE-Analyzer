'''
This file is part of the PE-Analyzer project. 
It serves as the main entry point for the application, orchestrating the analysis of Portable Executable (PE) files. The script utilizes various modules from the 'core' package to perform tasks such as parsing PE headers, extracting strings, calculating hashes, and checking for potential indicators of compromise (IOCs).

Arguments support:
- `-f / --file`: Specify the path to the PE file to be analyzed.
- `-o / --output`: Specify the output file path for saving the analysis results.
- `--vt`: Enable VirusTotal integration for additional threat intelligence.
- `--min-len`: Set the minimum length for string extraction.
- `--fast`: Enable fast mode for quicker analysis, potentially skipping some detailed checks.

'''

from __future__ import annotations
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import argparse
import json
import os
import sys
from unittest import result

# Add project root to sys.path for module imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
    
from src.core.disassembler import DisassemblyError
from src.core.hasher import calculate_hash, HashError, HashResult
from src.core.pe_parser import (
    PE_checker,
    parse_pe_info,
    PEInfo,
    PECheckResult,
    ENTROPY_PACKED_THRESHOLD,
)
from src.core.string_extractor import extract_strings, StringExtractor
from src.services.vt_checker import check_hash, VTErrors, VTNotFoundErrors, VTResult
from src.utils.blacklist import summarize_api_risks
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from src.utils.display import render_rich_report, console

'''
# Disassembler module import
from src.core.disassembler import disassemble_pe_entry_point
from src.core.data_structs import DisassemblyConfig
'''

class MalwareAnalysisPipeline:
    '''
    Analyzing process for PE files, including parsing, string extraction, hashing, and IOC checks.
    - Step 1: Calculate hashes (MD5, SHA1, SHA256) of the PE file.
    - Step 2: Parse PE Structure and extract relevant information.
    - Step 3: Compare with API blacklist to identify potential risks.
    - Step 4: Extract strings from the PE file based on specified minimum length.
    - Step 5: Research on VirusTotal for additional threat intelligence if enabled.
    '''
    
    def __init__ (self, file_path: Path | str, min_string_len: int = 4, query_vt: bool = False, vt_api_key: Optional[str] = None) -> None:
        self.target_path = Path(file_path).resolve()
        self.min_string_len = min_string_len
        self.query_vt = query_vt
        self.vt_api_key = vt_api_key
        
        if not self.target_path.is_file():
            raise FileNotFoundError(f"File not found: {self.target_path}")
        
    def run_analysis (self, progress: Optional[Progress] = None) -> Dict[str, Any]:
        report: Dict[str, Any] = {
            "target_file": str(self.target_path),
            "file_name": self.target_path.name,
            "is_pe_file": False,
            "hashing": {},
            "pe_analysis": None,
            "api_blacklist_analysis": None,
            "ioc_strings": {},
            "virustotal": None,
            "overall_summary": {
                "verdict": "BENIGN",
                "risk_score": 0,
                "warnings": [],
            }
        }

        task_id = None
        if progress is not None:
            task_id = progress.add_task("[cyan]Analyzing PE file...[/cyan]", total=100)

        def advance(value: int, description: Optional[str] = None) -> None:
            if progress is not None and task_id is not None:
                if description is not None:
                    progress.update(task_id, description=description)
                progress.update(task_id, advance=value)

        warnings: List[str] = []
        
        # Step 1: Calculate hashes
        try:
            hash_res: HashResult = calculate_hash(self.target_path)
            report["hashing"] = {
                "size_bytes": hash_res.size_bytes,
                "md5": hash_res.md5_hash,
                "sha256": hash_res.sha256_hash,
            }
            advance(20, "[cyan]Hashing file...[/cyan]")
        except HashError as e:
            warnings.append(f"Hashing error: {str(e)}")
            advance(20, "[yellow]Hashing skipped[/yellow]")
            
        # Step 2: Parse PE Structure
        pe_check: PECheckResult = PE_checker(self.target_path)
        report["is_pe_file"] = pe_check.isValid_PE
        
        if pe_check.isValid_PE:
            try:
                pe_info: PEInfo = parse_pe_info(self.target_path)
                
                sections_data = [
                    {
                        "name": (
                            section.name.decode(errors='ignore').rstrip('\x00')
                            if isinstance(section.name, bytes)
                            else str(section.name)
                        ),
                        "virtual_address": hex(section.virtual_address),
                        "virtual_size": section.virtual_size,
                        "raw_size": getattr(section, "raw_size", 0),
                        "entropy": section.entropy,
                        "permissions": section.permissions_str,
                        "is_rwx": section.is_rwx,
                        "is_high_entropy": section.is_suspicious_entropy,
                        "warning": section.packet_warning
                    }
                    for section in pe_info.sections
                ]
                
                imports_data = [
                    {
                        "dll_name": dll.dll_name,
                        "function_count": dll.function_count,
                        "functions": [
                            {
                                "name": fn.name,
                                "address": fn.hex_address,
                                "is_ordinal": fn.is_ordinal,
                                "is_suspicious": fn.is_suspicious
                            }
                            for fn in dll.functions
                        ]
                    }
                    for dll in pe_info.imports
                ]

                report["pe_analysis"] = {
                    "machine_type": pe_info.machine_arch,
                    "machine_name": pe_info.machine_name,
                    "architecture": "64-bit (PE32+)" if pe_info.is_64bit else "32-bit (PE32)",
                    "entry_point_rva": pe_info.entry_point_rva_hex,
                    "entry_point_va": pe_info.entry_point_va_hex,
                    "image_base": pe_info.image_base_hex,
                    "total_sections": pe_info.number_of_sections,
                    "has_packed_sections": pe_info.has_packed_sections,
                    "packer_alerts": pe_info.packer_alerts,
                    "sections": sections_data,
                    "imported_dlls": imports_data
                }
                
                if pe_info.has_packed_sections:
                    warnings.append("The PE file contains sections that may be packed or compressed, which is often used by malware to evade detection.")

                advance(25, "[cyan]Parsing PE structure...[/cyan]")

                # Step 3: Compare with API blacklist
                all_imported_apis = [
                    fn.name for dll in pe_info.imports for fn in dll.functions if fn.name
                ]
                api_risk = summarize_api_risks(all_imported_apis)

                report["api_blacklist_analysis"] = {
                    "total_blacklisted_apis": api_risk["total_blacklisted_apis"],
                    "risk_score": api_risk["risk_score"],
                    "risk_level": api_risk["risk_level"],
                    "severity_counts": api_risk["severity_counts"],
                    "categories": api_risk["categories"],
                    "detected_apis": [
                        {
                            "name": t.name,
                            "category": t.category,
                            "severity": t.severity.value,
                            "description": t.description,
                            "mitre_technique": t.mitre_technique
                        }
                        for t in api_risk["threat_details"]
                    ]
                }
                
                if api_risk["total_blacklisted_apis"] > 0:
                    warnings.append(f"Detected {api_risk['total_blacklisted_apis']} blacklisted API(s) which may indicate malicious behavior.")

                advance(15, "[cyan]Scanning blacklisted APIs...[/cyan]")

            except Exception as e:
                warnings.append(f"PE parsing error: {str(e)}")
        else:
            warnings.append("The provided file is not a valid PE file. Further PE analysis will be skipped.")
            
        # Step 4: Extract strings
        try:
            extracted_strs = extract_strings(self.target_path, min_length=self.min_string_len)
            
            ipv4_matches = StringExtractor.filter_ipv4(extracted_strs)
            net_iocs = StringExtractor.filter_domains_and_urls(extracted_strs)
            classified_iocs = StringExtractor.filter_iocs(extracted_strs)

            report["ioc_strings"] = {
                "total_strings_found": len(extracted_strs),
                "ipv4_addresses": [m.match_value for m in ipv4_matches],
                "urls": [m.match_value for m in net_iocs["urls"]],
                "domains": [m.match_value for m in net_iocs["domains"]],
                "registry_keys": [item.value for item in classified_iocs.get("reg_key", [])],
                "pe_filenames": [item.value for item in classified_iocs.get("pe_file", [])],
            }
            
            if report["ioc_strings"]["urls"] or report["ioc_strings"]["ipv4_addresses"] or report["ioc_strings"]["domains"]:
                warnings.append("Potential network IOCs (URLs/domains) were detected in the extracted strings.")

            advance(20, "[cyan]Extracting indicators...[/cyan]")

        except Exception as e:
            warnings.append(f"String extraction error: {str(e)}")
            advance(20, "[yellow]String extraction skipped[/yellow]")
            
        # Step 5: VirusTotal check
        if self.query_vt:
            sha256 = report["hashing"].get("sha256")
            if sha256:
                try:
                    advance(10, "[cyan]Querying VirusTotal...[/cyan]")
                    vt_res: VTResult = check_hash(sha256, api_key=self.vt_api_key)
                    report["virustotal"] = {
                        "status": "ok",
                        "malicious_detections": vt_res.malicious,
                        "total_engines": vt_res.total_engines,
                        "detection_ratio": f"{vt_res.malicious}/{vt_res.total_engines}",
                        "is_flagged": vt_res.is_flagged,
                        "file_type": vt_res.file_type,
                        "permalink": vt_res.permalink,
                        "engine_detections": vt_res.engine_detections
                    }
                    
                    if vt_res.is_flagged:
                        warnings.append(f"VirusTotal flagged the file as malicious with {vt_res.malicious} detections out of {vt_res.total_engines} engines.")
                except VTNotFoundErrors as e:
                    report["virustotal"] = {
                        "status": "not_found",
                        "message": str(e),
                        "hash": sha256,
                    }
                except VTErrors as e:
                    report["virustotal"] = {
                        "status": "error",
                        "error": str(e)
                    }
                    warnings.append(f"VirusTotal API error: {str(e)}")
                finally:
                    advance(10, "[cyan]Finalizing report...[/cyan]")
        else:
            advance(10, "[cyan]Finalizing report...[/cyan]")

        # Finalize report
        final_risk_score = 0
        if report.get("api_blacklist_analysis"):
            final_risk_score += report["api_blacklist_analysis"]["risk_score"] * 0.6
        if report.get("pe_analysis") and report["pe_analysis"].get("has_packed_sections"):
            final_risk_score += 30
        if report.get("virustotal") and report["virustotal"].get("status") == "ok" and report["virustotal"].get("is_flagged"):
            final_risk_score += 40

        final_risk_score = min(100, int(final_risk_score))

        verdict = (
            "MALICIOUS" if final_risk_score >= 60
            else "SUSPICIOUS" if final_risk_score >= 30
            else "BENIGN"
        )

        report["overall_summary"]["risk_score"] = final_risk_score
        report["overall_summary"]["verdict"] = verdict
        report["overall_summary"]["warnings"] = warnings

        if progress is not None and task_id is not None:
            progress.update(task_id, completed=100, description="[green]Analysis complete[/green]")
        
        '''    
        # Disassembly of Entry Point (Optional, if implemented)
        try:
            report["pe_analysis"]["entry_point_disassembly"] = result.to_dict()  # Placeholder for disassembly results if implemented
        except DisassemblyError as e:
            warnings.append(f"Disassembly error: {str(e)}")
            report["overall_summary"]["warnings"] = warnings
        '''

        return report
    
def format_text_report(report: Dict[str, Any]) -> str:
    """Format the analysis report into clean, human-readable English text output."""
    lines = []
    lines.append("=" * 80)
    lines.append("              STATIC MALWARE & PE BINARY ANALYSIS REPORT                ")
    lines.append("=" * 80)
    lines.append(f"Target File  : {report['target_file']}")
    lines.append(f"File Name    : {report['file_name']}")
    lines.append(f"Format       : {'Valid Windows PE Binary' if report['is_pe_file'] else 'Non-PE / Unsupported Binary'}")

    # 1. Hashing
    h = report.get("hashing", {})
    lines.append("\n[1] HASHING & FILE METRICS:")
    lines.append(f"  - File Size   : {h.get('size_bytes', 0):,} bytes")
    lines.append(f"  - MD5         : {h.get('md5', 'N/A')}")
    lines.append(f"  - SHA-256     : {h.get('sha256', 'N/A')}")

    # 2. PE Structure
    pe = report.get("pe_analysis")
    if pe:
        lines.append("\n[2] PE HEADERS & SECTIONS STRUCTURE:")
        lines.append(f"  - Machine Type     : {pe['machine_type']} ({pe['machine_name']})")
        lines.append(f"  - Architecture     : {pe['architecture']}")
        lines.append(f"  - ImageBase        : {pe['image_base']}")
        lines.append(f"  - EntryPoint (VA)  : {pe['entry_point_va']} (RVA: {pe['entry_point_rva']})")
        lines.append(f"  - Total Sections   : {pe['total_sections']}")

        lines.append("\n  Section Table:")
        lines.append(f"    {'Name':<10} | {'Virtual Addr':<14} | {'Raw Size':<10} | {'Entropy':<8} | {'Perms':<6} | {'Alerts'}")
        lines.append("    " + "-" * 70)
        for s in pe["sections"]:
            warn = " [!] High Entropy" if s["is_high_entropy"] else ""
            if s["is_rwx"]:
                warn += " [!] W+X (RWX)"
            lines.append(f"    {s['name']:<10} | {s['virtual_address']:<14} | {s['raw_size']:<10} | {s['entropy']:<8.2f} | {s['permissions']:<6} |{warn}")

        if pe["has_packed_sections"]:
            lines.append("\n  ⚠️  PACKER WARNINGS (HIGH ENTROPY / PACKED SECTIONS):")
            for alert in pe["packer_alerts"]:
                lines.append(f"    * {alert}")

    # 3. API Blacklist Analysis
    api_rep = report.get("api_blacklist_analysis")
    if api_rep and api_rep["total_blacklisted_apis"] > 0:
        lines.append(f"\n[3] IMPORT TABLE & BLACKLISTED APIS ANALYSIS ({api_rep['total_blacklisted_apis']} suspicious APIs):")
        lines.append(f"  - API Risk Level   : {api_rep['risk_level']} (Score: {api_rep['risk_score']}/100)")
        for t in api_rep["detected_apis"]:
            lines.append(f"    * [{t['severity']:<8}] {t['name']:<25} | Category: {t['category']:<20} | {t.get('mitre_technique', '')}")

    # 4. IOC Strings
    iocs = report.get("ioc_strings", {})
    lines.append("\n[4] EXTRACTED IOC STRINGS & NETWORK INDICATORS:")
    lines.append(f"  - C2 URLs        : {len(iocs.get('urls', []))} URLs found")
    for u in iocs.get("urls", [])[:5]:
        lines.append(f"      * {u}")
    lines.append(f"  - IPv4 Addresses : {len(iocs.get('ipv4_addresses', []))} IPs found")
    for ip in iocs.get("ipv4_addresses", [])[:5]:
        lines.append(f"      * {ip}")
    lines.append(f"  - Domains (FQDN) : {len(iocs.get('domains', []))} Domains found")
    for dom in iocs.get("domains", [])[:5]:
        lines.append(f"      * {dom}")

    # 5. VirusTotal
    vt = report.get("virustotal")
    if vt:
        lines.append("\n[5] VIRUSTOTAL THREAT INTELLIGENCE:")
        status = vt.get("status")
        if status == "not_found":
            lines.append(f"  - Status: Not found ({vt.get('message', 'Hash not found in VT database')})")
        elif status == "error" or "error" in vt:
            lines.append(f"  - Status: Error ({vt.get('error', vt.get('message', 'Unknown VirusTotal error'))})")
        elif status == "ok":
            lines.append(f"  - Detection Ratio  : {vt.get('detection_ratio', '0/0')} engines flagged malicious")
            lines.append(f"  - Full Report Link : {vt.get('permalink', 'N/A')}")
            if vt.get("engine_detections"):
                lines.append("  - Antivirus Detections:")
                for av, name in vt["engine_detections"].items():
                    if name:
                        lines.append(f"      * {av:<15}: {name}")
        else:
            lines.append(f"  - Status: {status or 'Unknown'}")

    # 6. Final Verdict
    sum_rep = report["overall_summary"]
    lines.append("\n" + "=" * 80)
    lines.append(f"  OVERALL VERDICT : {sum_rep['verdict']} (Risk Score: {sum_rep['risk_score']}/100)")
    if sum_rep["warnings"]:
        lines.append("  Observed Risk Indicators:")
        for w in sum_rep["warnings"]:
            lines.append(f"    - {w}")
    lines.append("=" * 80)

    return "\n".join(lines)

def export_report(report_data: Dict[str, Any], output_path_str: str) -> None:
    """Export the analysis report to either .json or .txt based on file extension."""
    output_path = Path(output_path_str).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.suffix.lower() == ".json":
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        print(f"\n[✓] Analysis report successfully exported to JSON: {output_path}")
    else:
        text_content = format_text_report(report_data)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(text_content + "\n")
        print(f"\n[✓] Analysis report successfully exported to Text: {output_path}")


def default_output_path(file_path: Path) -> Path:
    """Return the default location for generated reports under the repository output directory."""
    output_dir = Path("output").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / f"{file_path.stem}_report.json"


# --- CLI PARSER & MAIN ENTRYPOINT ---

def build_cli_parser() -> argparse.ArgumentParser:
    """Construct the English CLI parser using argparse."""
    parser = argparse.ArgumentParser(
        prog="python -m src.main",
        description="Static Malware & PE Binary Analysis Framework.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:
  python src/main.py -f samples/bin/malware_simulator_x64.exe
  python src/main.py -f samples/bin/malware_simulator_x64.exe -o report.json
  python src/main.py -f samples/bin/malware_simulator_x64.exe -o report.txt --vt
        """
    )

    # Required file argument
    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Path to the binary file to analyze (.exe, .dll, .bin, .sys, etc.)"
    )

    # Output report destination
    parser.add_argument(
        "-o", "--output",
        help="Output report destination path (.json or .txt)"
    )

    # Optional analysis flags
    parser.add_argument(
        "--vt",
        action="store_true",
        help="Enable VirusTotal API v3 hash reputation lookup"
    )

    parser.add_argument(
        "--min-len",
        type=int,
        default=4,
        help="Minimum printable string length for string extraction (default: 4)"
    )

    parser.add_argument(
        "--api-key",
        help="VirusTotal API Key (defaults to 'VT_API_KEY' environment variable)"
    )

    return parser


def main() -> int:
    """Main CLI execution flow."""
    parser = build_cli_parser()
    args = parser.parse_args()

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"[-] Error: Target file '{args.file}' does not exist.", file=sys.stderr)
        return 1

    try:
        pipeline = MalwareAnalysisPipeline(
            file_path=file_path,
            min_string_len=args.min_min_len if hasattr(args, 'min_min_len') else args.min_len,
            query_vt=args.vt,
            vt_api_key=args.api_key
        )
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            report_data = pipeline.run_analysis(progress=progress)
        render_rich_report(report_data)

        # Print formatted text report to Console
        print(format_text_report(report_data))

        output_target = args.output if args.output else str(default_output_path(file_path))
        export_report(report_data, output_target)

        return 0

    except Exception as err:
        print(f"[-] Error during analysis: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())