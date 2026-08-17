"""
Module: src/utils/display.py
Purpose: Integrate the Rich library to format and color the Terminal interface:
- Visual tables (rich.table.Table)
- Summary panels (rich.panel.Panel)
- Hierarchical import tree (rich.tree.Tree)
- Color-coded alerts based on risk level (Red: Critical, Yellow: High, Blue: Benign)
"""

from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

# Create a global Console instance for rich output
console = Console()


def render_banner(c: Optional[Console] = None) -> None:
    out = c or console

    banner = r"""
 ██████╗ ███████╗     █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗
 ██╔══██╗██╔════╝    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
 ██████╔╝█████╗█████╗███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
 ██╔═══╝ ██╔══╝╚════╝██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
 ██║     ███████╗    ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
 ╚═╝     ╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
    """

    out.print(
        Panel(
            f"[bold cyan]{banner}[/bold cyan]\n"
            "[bold white]Static Malware & PE Binary Analysis Framework[/bold white]\n"
            "[dim]Offline PE triage • Import analysis • IOC extraction[/dim]",
            border_style="bright_blue",
            padding=(1, 2),
        )
    )


def display_file_summary(report: Dict[str, Any], c: Optional[Console] = None) -> None:
    """Display the overall file information and cryptographic hash values."""
    out = c or console
    hashing = report.get("hashing", {})
    is_pe = report.get("is_pe_file", False)

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Property", style="bold cyan", justify="right")
    table.add_column("Value", style="white")

    table.add_row("Target File:", f"[bold white]{report.get('target_file', 'N/A')}[/bold white]")
    table.add_row("File Name:", f"[white]{report.get('file_name', 'N/A')}[/white]")
    table.add_row("File Size:", f"{hashing.get('size_bytes', 0):,} bytes")
    table.add_row("MD5 Hash:", f"[yellow]{hashing.get('md5', 'N/A')}[/yellow]")
    table.add_row("SHA-256 Hash:", f"[bold green]{hashing.get('sha256', 'N/A')}[/bold green]")
    table.add_row(
        "PE Format:",
        "[bold green]✓ Valid Windows PE Binary[/bold green]" if is_pe
        else "[bold red]✗ Non-PE / Raw Binary[/bold red]"
    )

    out.print(Panel(table, title="[bold blue]1. File Metrics & Cryptographic Hashes[/bold blue]", border_style="blue"))


def display_pe_header(pe_data: Optional[Dict[str, Any]], c: Optional[Console] = None) -> None:
    """Display the PE Header & Optional Header information."""
    out = c or console
    if not pe_data:
        return

    table = Table(title="PE Header Architecture & EntryPoint", border_style="cyan", header_style="bold magenta")
    table.add_column("Machine Architecture", style="cyan")
    table.add_column("Binary Format", style="green")
    table.add_column("Image Base", style="yellow")
    table.add_column("EntryPoint (RVA)", style="magenta")
    table.add_column("EntryPoint (Virtual Address)", style="bold magenta")
    table.add_column("Total Sections", justify="center", style="white")

    table.add_row(
        pe_data.get("machine_type", "N/A"),
        pe_data.get("architecture", "N/A"),
        pe_data.get("image_base", "N/A"),
        pe_data.get("entry_point_rva", "N/A"),
        pe_data.get("entry_point_va", "N/A"),
        str(pe_data.get("total_sections", 0))
    )

    out.print(table)


def display_sections_table(sections: List[Dict[str, Any]], c: Optional[Console] = None) -> None:
    """
    Display the PE Sections analysis table with colored alerts:
    - Red: Entropy > 7.0 (Packed / Encrypted) or Permissions RWX (W+X)
    - Yellow: Entropy 6.0 - 7.0
    - Blue: Normal Entropy <= 6.0
    """
    out = c or console
    if not sections:
        return

    table = Table(
        title="PE Sections Analysis (Entropy & Memory Permissions)",
        border_style="blue",
        header_style="bold white on blue",
        expand=True
    )
    table.add_column("Section Name", style="bold cyan", width=14)
    table.add_column("Virtual Address", justify="center", style="white")
    table.add_column("Virtual Size", justify="right", style="white")
    table.add_column("Raw Size", justify="right", style="white")
    table.add_column("Shannon Entropy", justify="center")
    table.add_column("Permissions", justify="center")
    table.add_column("Heuristic Status / Alerts", style="white")

    has_packed_warning = False

    for s in sections:
        entropy_val = s.get("entropy", 0.0)

        # Tô màu Entropy
        if entropy_val > 7.0:
            entropy_styled = f"[bold white on red] {entropy_val:.2f} [/bold white on red]"
            has_packed_warning = True
        elif entropy_val >= 6.0:
            entropy_styled = f"[bold yellow]{entropy_val:.2f}[/bold yellow]"
        else:
            entropy_styled = f"[green]{entropy_val:.2f}[/green]"

        # Tô màu Quyền hạn (Permissions)
        perms = s.get("permissions") or s.get("permission") or "---"
        is_rwx = s.get("is_rwx", False)
        if is_rwx:
            perms_styled = "[bold white on red] RWX [/bold white on red]"
        elif "X" in perms:
            perms_styled = "[bold magenta]R-X[/bold magenta]"
        elif "W" in perms:
            perms_styled = "[yellow]RW-[/yellow]"
        else:
            perms_styled = "[dim]R--[/dim]"

        # Phân tích Cảnh báo
        alerts = []
        if s.get("is_high_entropy"):
            alerts.append("[bold red]⚠️ High Entropy (>7.0)[/bold red]")
        if is_rwx:
            alerts.append("[bold red]⚠️ W+X (Self-Modifying Code)[/bold red]")
        alert_str = " | ".join(alerts) if alerts else "[green]Normal[/green]"

        table.add_row(
            s.get("name", "N/A"),
            s.get("virtual_address", "N/A"),
            f"{s.get('virtual_size', 0):,} B",
            f"{s.get('raw_size', 0):,} B",
            entropy_styled,
            perms_styled,
            alert_str
        )

    out.print(table)

    if has_packed_warning:
        out.print(
            Panel(
                "[bold red]⚠️  PACKER / ENCRYPTION ALERT DETECTED:[/bold red]\n"
                "[yellow]One or more sections have Shannon Entropy > 7.0, strongly indicating "
                "the binary is packed (e.g. UPX, Themida, VMProtect) or contains encrypted payloads/shellcode.[/yellow]",
                border_style="bold red",
                padding=(0, 2)
            )
        )


def display_blacklist_apis(api_data: Optional[Dict[str, Any]], c: Optional[Console] = None) -> None:
    """
    Display the API Blacklist table with colored alerts based on Severity:
    - CRITICAL: Red background (Process Injection / Shellcode Execution)
    - HIGH: Red (Memory Manipulation / Persistence)
    - MEDIUM: Yellow (Anti-Debug / Execution)
    - LOW: Blue (Network)
    """
    out = c or console
    if not api_data or api_data.get("total_blacklisted_apis", 0) == 0:
        return

    risk_level = api_data.get("risk_level", "LOW")
    risk_score = api_data.get("risk_score", 0)

    # Tô màu Risk Level
    if risk_level == "CRITICAL":
        risk_styled = f"[bold white on red] CRITICAL ({risk_score}/100) [/bold white on red]"
    elif risk_level == "HIGH":
        risk_styled = f"[bold red]HIGH ({risk_score}/100)[/bold red]"
    elif risk_level == "MEDIUM":
        risk_styled = f"[bold yellow]MEDIUM ({risk_score}/100)[/bold yellow]"
    else:
        risk_styled = f"[green]LOW ({risk_score}/100)[/green]"

    table = Table(
        title=f"API Blacklist & Suspicious Windows APIs ({api_data['total_blacklisted_apis']} detected) - Risk: {risk_styled}",
        border_style="red",
        header_style="bold white on red",
        expand=True
    )
    table.add_column("Severity", justify="center", width=12)
    table.add_column("API Function Name", style="bold white", width=24)
    table.add_column("Category", style="cyan", width=22)
    table.add_column("MITRE ATT&CK Mapping", style="yellow", width=32)
    table.add_column("Behavior Description", style="dim white")

    for t in api_data.get("detected_apis", []):
        sev = t.get("severity", "LOW")
        if sev == "CRITICAL":
            sev_badge = "[bold white on red] CRITICAL [/bold white on red]"
        elif sev == "HIGH":
            sev_badge = "[bold red]HIGH[/bold red]"
        elif sev == "MEDIUM":
            sev_badge = "[bold yellow]MEDIUM[/bold yellow]"
        else:
            sev_badge = "[green]LOW[/green]"

        table.add_row(
            sev_badge,
            t.get("name", "N/A"),
            t.get("category", "General"),
            t.get("mitre_technique") or "N/A",
            t.get("description", "")
        )

    out.print(table)


def display_import_tree(imports: List[Dict[str, Any]], c: Optional[Console] = None) -> None:
    """Display the Import Table as a hierarchical tree structure."""
    out = c or console
    if not imports:
        return

    tree = Tree("[bold blue]📦 Imported Dynamic Link Libraries (DLLs) & APIs[/bold blue]")

    for dll in imports:
        dll_name = dll.get("dll_name", "UNKNOWN_DLL")
        func_count = dll.get("function_count", 0)
        dll_node = tree.add(f"[bold cyan]📁 {dll_name}[/bold cyan] [dim]({func_count} functions)[/dim]")

        for fn in dll.get("functions", []):
            name = fn.get("name") or f"Ordinal_{fn.get('ordinal')}"
            addr = fn.get("address", "0x0")
            is_susp = fn.get("is_suspicious", False)

            if is_susp:
                dll_node.add(f"[bold red]⚡ {name}[/bold red] [dim]({addr})[/dim] [bold red][! SUSPICIOUS][/bold red]")
            else:
                dll_node.add(f"[white]• {name}[/white] [dim]({addr})[/dim]")

    out.print(Panel(tree, border_style="cyan", padding=(0, 2)))


def display_ioc_strings(ioc_data: Optional[Dict[str, Any]], c: Optional[Console] = None) -> None:
    """Display the extracted IOC strings and threat indicators in a colored table."""
    out = c or console
    if not ioc_data:
        return

    urls = ioc_data.get("urls", [])
    ips = ioc_data.get("ipv4_addresses", [])
    domains = ioc_data.get("domains", [])
    reg_keys = ioc_data.get("registry_keys", [])

    if not (urls or ips or domains or reg_keys):
        return

    table = Table(title="Extracted IOC Strings & Threat Indicators", border_style="yellow", header_style="bold yellow", expand=True)
    table.add_column("IOC Type", style="bold yellow", width=18)
    table.add_column("Extracted Threat Indicators", style="white")

    if urls:
        table.add_row("[bold red]C2 URLs[/bold red]", "\n".join([f"[red]• {u}[/red]" for u in urls[:6]]))
    if ips:
        table.add_row("[bold magenta]IPv4 Addresses[/bold magenta]", "\n".join([f"[magenta]• {ip}[/magenta]" for ip in ips[:6]]))
    if domains:
        table.add_row("[cyan]Domains (FQDN)[/cyan]", "\n".join([f"[cyan]• {d}[/cyan]" for d in domains[:6]]))
    if reg_keys:
        table.add_row("[yellow]Registry Keys[/yellow]", "\n".join([f"[yellow]• {r}[/yellow]" for r in reg_keys[:4]]))

    out.print(table)


def display_virustotal_panel(vt_data: Optional[Dict[str, Any]], c: Optional[Console] = None) -> None:
    """Display the VirusTotal API v3 threat intelligence results."""
    out = c or console
    if not vt_data:
        return

    if vt_data.get("status") == "not_found":
        message = vt_data.get("message", "Hash not found in VirusTotal database.")
        out.print(Panel(f"[yellow]VirusTotal: hash not found[/yellow]\n[dim]{message}[/dim]", border_style="yellow"))
        return

    if vt_data.get("status") == "error" or "error" in vt_data:
        msg = vt_data.get("error", "Unknown VirusTotal error")
        out.print(Panel(f"[red]VirusTotal Query Error:[/red] {msg}", border_style="red"))
        return

    malicious = vt_data.get("malicious_detections", 0)
    total = vt_data.get("total_engines", 0)
    permalink = vt_data.get("permalink", "N/A")

    if malicious > 0:
        badge = f"[bold white on red] MALICIOUS ({malicious}/{total} engines detected) [/bold white on red]"
    else:
        badge = f"[bold white on green] CLEAN (0/{total} detections) [/bold white on green]"

    table = Table(show_header=False, box=None)
    table.add_column("Key", style="bold cyan")
    table.add_column("Value")

    table.add_row("Detection Ratio:", badge)
    table.add_row("File Type:", vt_data.get("file_type", "Unknown"))
    table.add_row("Full GUI Report:", f"[blue underline]{permalink}[/blue underline]")

    engines = vt_data.get("engine_detections", {})
    if engines:
        det_lines = [f"[bold]{av}:[/bold] [red]{label}[/red]" for av, label in engines.items() if label]
        if det_lines:
            table.add_row("AV Detections:", "\n".join(det_lines))

    out.print(Panel(table, title="[bold magenta]5. VirusTotal Threat Intelligence[/bold magenta]", border_style="magenta"))


def display_overall_verdict(summary: Dict[str, Any], c: Optional[Console] = None) -> None:
    """Display the overall verdict and risk assessment summary."""
    out = c or console
    verdict = summary.get("verdict", "BENIGN")
    risk_score = summary.get("risk_score", 0)
    warnings = summary.get("warnings", [])

    if verdict == "MALICIOUS":
        color = "bold red"
        border = "red"
        badge = f"[bold white on red]  FINAL VERDICT: MALICIOUS (Risk Score: {risk_score}/100)  [/bold white on red]"
    elif verdict == "SUSPICIOUS":
        color = "bold yellow"
        border = "yellow"
        badge = f"[bold black on yellow]  FINAL VERDICT: SUSPICIOUS (Risk Score: {risk_score}/100)  [/bold black on yellow]"
    else:
        color = "bold green"
        border = "green"
        badge = f"[bold white on green]  FINAL VERDICT: BENIGN / CLEAN (Risk Score: {risk_score}/100)  [/bold white on green]"

    content = f"\n{badge}\n"
    if warnings:
        content += "\n[bold underline]Observed Threat Indicators & Warnings:[/bold underline]\n"
        for w in warnings:
            content += f"  [yellow]•[/yellow] [white]{w}[/white]\n"

    out.print(Panel(content, title=f"[{color}]Overall Assessment Summary[/{color}]", border_style=border, padding=(1, 2)))


def render_rich_report(report: Dict[str, Any], c: Optional[Console] = None) -> None:
    """This function orchestrates the rendering of the complete Rich report, including all sections."""
    out = c or console
    display_file_summary(report, out)

    pe_data = report.get("pe_analysis")
    if pe_data:
        display_pe_header(pe_data, out)
        display_sections_table(pe_data.get("sections", []), out)
        display_import_tree(pe_data.get("imported_dlls", []), out)

    display_blacklist_apis(report.get("api_blacklist_analysis"), out)
    display_ioc_strings(report.get("ioc_strings"), out)
    display_virustotal_panel(report.get("virustotal"), out)
    display_overall_verdict(report.get("overall_summary", {}), out)
