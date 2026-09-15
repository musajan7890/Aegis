import argparse
import json
import os
import sys
from datetime import datetime
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from core.scope import load_scope
from recon.dns import resolve_domain
from recon.subdomains import discover_subdomains
from technology.http_probe import fetch_http_info
from technology.fingerprint import detect_technologies
from discovery.port_scanner import scan_ports
from security.headers import check_security_headers
from findings.engine import analyze_security_headers
from reports.reporter import generate_report


# ============================================================
# AEGIS CONSOLE
# ============================================================

console = Console()


# ============================================================
# UI HELPERS
# ============================================================

def title(text):
    console.print(
        Panel(
            f"[bold cyan]{text}[/bold cyan]",
            border_style="cyan",
            box=box.DOUBLE,
        )
    )


def success(text):
    console.print(f"[bold green][+] {text}[/bold green]")


def info(text):
    console.print(f"[bold cyan][*] {text}[/bold cyan]")


def warning(text):
    console.print(f"[bold yellow][!] {text}[/bold yellow]")


def error(text):
    console.print(f"[bold red][-] {text}[/bold red]")


def pause():
    Prompt.ask("\n[dim]Press ENTER to return to AEGIS[/dim]", default="")


# ============================================================
# BANNER
# ============================================================

def show_banner():
    console.clear()

    banner = r"""
      █████╗ ███████╗ ██████╗ ██╗███████╗
     ██╔══██╗██╔════╝██╔══██╗██║██╔════╝
     ███████║█████╗  ██████╔╝██║███████╗
     ██╔══██║██╔══╝  ██╔══██╗██║╚════██║
     ██║  ██║███████╗██║  ██║██║███████║
     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝
    """

    console.print(
        Panel(
            f"[bold cyan]{banner}[/bold cyan]"
            "\n"
            "[bold white]             AUTHORIZED SECURITY ASSESSMENT[/bold white]"
            "\n"
            "[dim]                 AI Security Assistant[/dim]",
            border_style="cyan",
            box=box.DOUBLE,
            padding=(1, 2),
        )
    )

    console.print(
        "[dim]────────────────────────────────────────────────────────────[/dim]"
    )

    console.print(
        "[bold green]SYSTEM[/bold green]   : [white]AEGIS ONLINE[/white]"
    )
    console.print(
        "[bold green]MODE[/bold green]     : [white]AUTHORIZED ASSESSMENT[/white]"
    )
    console.print(
        "[bold green]VERSION[/bold green]  : [white]0.1[/white]"
    )

    console.print(
        "[dim]────────────────────────────────────────────────────────────[/dim]\n"
    )


# ============================================================
# DOMAIN NORMALIZATION
# ============================================================

def normalize_domain(value):
    value = value.strip()

    if not value:
        return ""

    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)

    domain = parsed.netloc

    if not domain:
        domain = parsed.path

    domain = domain.split("/")[0]
    domain = domain.split(":")[0]

    return domain.lower().strip()


# ============================================================
# HISTORY
# ============================================================

def save_scan_history(targets, findings):
    os.makedirs("reports", exist_ok=True)

    history_file = "reports/history.json"

    history = []

    if os.path.exists(history_file):
        try:
            with open(history_file, "r", encoding="utf-8") as f:
                history = json.load(f)

            if not isinstance(history, list):
                history = []

        except Exception:
            history = []

    scan_id = datetime.now().strftime("%Y%m%d-%H%M%S")

    entry = {
        "scan_id": scan_id,
        "timestamp": datetime.now().isoformat(),
        "targets": targets,
        "total_findings": len(findings),
        "findings": findings,
    }

    history.append(entry)

    with open(history_file, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=4)

    return scan_id


# ============================================================
# SUBDOMAIN WORDLIST
# ============================================================

def load_subdomain_wordlist():
    wordlist = "recon/subdomains.txt"

    if os.path.exists(wordlist):
        try:
            with open(wordlist, "r", encoding="utf-8") as f:
                return [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
        except Exception:
            pass

    return [
        "www",
        "mail",
        "api",
        "dev",
        "test",
        "staging",
        "admin",
    ]


# ============================================================
# RECON
# ============================================================

def run_recon(domain):
    domain = normalize_domain(domain)

    if not domain:
        error("Invalid domain.")
        return

    title("RECONNAISSANCE")

    info(f"Target: {domain}")

    console.print()

    # DNS
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Resolving DNS..."),
            transient=True,
        ) as progress:
            progress.add_task("dns", total=None)
            dns_result = resolve_domain(domain)

        success("DNS resolution completed.")

        console.print()

        if isinstance(dns_result, dict):
            table = Table(
                title="DNS Intelligence",
                box=box.ROUNDED,
                border_style="cyan",
            )

            table.add_column("Field", style="bold cyan")
            table.add_column("Value")

            for key, value in dns_result.items():
                table.add_row(str(key), str(value))

            console.print(table)

        else:
            console.print(dns_result)

    except Exception as exc:
        error(f"DNS error: {exc}")

    # Subdomains
    console.print()

    try:
        info("Discovering subdomains...")

        wordlist = load_subdomain_wordlist()

        subdomains = discover_subdomains(
            domain,
            wordlist,
        )

        success("Subdomain discovery completed.")

        if subdomains:
            table = Table(
                title="Discovered Subdomains",
                box=box.ROUNDED,
                border_style="green",
            )

            table.add_column("#", style="bold cyan")
            table.add_column("Subdomain")

            for index, subdomain in enumerate(subdomains, 1):
                table.add_row(
                    str(index),
                    str(subdomain),
                )

            console.print(table)

        else:
            warning("No subdomains discovered.")

    except Exception as exc:
        error(f"Subdomain discovery error: {exc}")


# ============================================================
# TECHNOLOGY DETECTION
# ============================================================

def run_technology(domain):
    domain = normalize_domain(domain)

    if not domain:
        error("Invalid domain.")
        return

    title("TECHNOLOGY DETECTION")

    info(f"Target: {domain}")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Analyzing HTTP response..."),
            transient=True,
        ) as progress:
            progress.add_task("http", total=None)
            http_result = fetch_http_info(domain)

        success("HTTP probe completed.")

        console.print()

        if isinstance(http_result, dict):
            table = Table(
                title="HTTP Information",
                box=box.ROUNDED,
                border_style="cyan",
            )

            table.add_column("Property", style="bold cyan")
            table.add_column("Value")

            for key, value in http_result.items():
                if key not in ["body"]:
                    table.add_row(
                        str(key),
                        str(value),
                    )

            console.print(table)

        console.print()

        try:
            headers = http_result.get("headers", {})
            body = http_result.get("body", "")

            technologies = detect_technologies(
                headers,
                body,
            )

            if technologies:
                table = Table(
                    title="Detected Technologies",
                    box=box.ROUNDED,
                    border_style="green",
                )

                table.add_column("#", style="bold cyan")
                table.add_column("Technology")

                for index, technology in enumerate(
                    technologies,
                    1,
                ):
                    table.add_row(
                        str(index),
                        str(technology),
                    )

                console.print(table)

            else:
                warning("No technologies detected.")

        except Exception as exc:
            error(f"Technology detection error: {exc}")

    except Exception as exc:
        error(f"HTTP probe error: {exc}")


# ============================================================
# PORT DISCOVERY
# ============================================================

def run_ports(host):
    host = host.strip()

    if not host:
        error("Invalid host.")
        return

    title("PORT DISCOVERY")

    info(f"Target: {host}")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Scanning common ports..."),
            transient=True,
        ) as progress:
            progress.add_task("ports", total=None)

            ports = scan_ports(host)

        success("Port scan completed.")

        console.print()

        if ports:
            table = Table(
                title="Port Results",
                box=box.ROUNDED,
                border_style="cyan",
            )

            table.add_column("Port", style="bold cyan")
            table.add_column("Service / Result")

            if isinstance(ports, dict):
                for port, result in ports.items():
                    table.add_row(
                        str(port),
                        str(result),
                    )

            else:
                for port in ports:
                    table.add_row(
                        str(port),
                        "Detected",
                    )

            console.print(table)

        else:
            warning("No open/common ports detected.")

    except Exception as exc:
        error(f"Port scan error: {exc}")


# ============================================================
# FULL SECURITY SCAN
# ============================================================

def run_scan(targets):
    title("AEGIS SECURITY ASSESSMENT")

    if not targets:
        error("No targets supplied.")
        return

    findings = []

    for target in targets:

        target = normalize_domain(target)

        if not target:
            continue

        console.print(
            Panel(
                f"[bold white]TARGET[/bold white]\n"
                f"[cyan]{target}[/cyan]",
                border_style="cyan",
            )
        )

        # ----------------------------------------------------
        # DNS
        # ----------------------------------------------------

        try:
            info("Resolving target...")

            dns_result = resolve_domain(target)

            success("DNS resolved.")

        except Exception as exc:
            error(f"DNS failed: {exc}")
            dns_result = {}

        # ----------------------------------------------------
        # IP
        # ----------------------------------------------------

        ip = None

        if isinstance(dns_result, dict):

            for key in [
                "ip",
                "ipv4",
                "address",
                "ip_address",
            ]:

                if key in dns_result:
                    ip = dns_result[key]
                    break

        # ----------------------------------------------------
        # SUBDOMAINS
        # ----------------------------------------------------

        try:
            info("Discovering subdomains...")

            wordlist = load_subdomain_wordlist()

            subdomains = discover_subdomains(
                target,
                wordlist,
            )

            success(
                f"Subdomain discovery complete: "
                f"{len(subdomains) if subdomains else 0}"
            )

        except Exception as exc:
            error(f"Subdomain discovery failed: {exc}")
            subdomains = []

        # ----------------------------------------------------
        # HTTP
        # ----------------------------------------------------

        try:
            info("Probing HTTP...")

            http_result = fetch_http_info(target)

            success("HTTP probe completed.")

        except Exception as exc:
            error(f"HTTP probe failed: {exc}")
            http_result = {}

        # ----------------------------------------------------
        # TECHNOLOGIES
        # ----------------------------------------------------

        technologies = []

        try:

            headers = http_result.get(
                "headers",
                {},
            )

            body = http_result.get(
                "body",
                "",
            )

            technologies = detect_technologies(
                headers,
                body,
            )

            success("Technology fingerprinting completed.")

        except Exception as exc:
            error(
                f"Technology detection failed: {exc}"
            )

        # ----------------------------------------------------
        # SECURITY HEADERS
        # ----------------------------------------------------

        header_results = {}

        try:

            headers = http_result.get(
                "headers",
                {},
            )

            header_results = check_security_headers(
                headers
            )

            success("Security header analysis completed.")

        except Exception as exc:
            error(
                f"Security header check failed: {exc}"
            )

        # ----------------------------------------------------
        # FINDINGS
        # ----------------------------------------------------

        try:

            target_findings = analyze_security_headers(
                header_results
            )

            if target_findings:
                findings.extend(
                    target_findings
                )

                warning(
                    f"{len(target_findings)} "
                    f"finding(s) detected."
                )

            else:
                success(
                    "No security-header findings detected."
                )

        except Exception as exc:
            error(
                f"Finding engine failed: {exc}"
            )

        # ----------------------------------------------------
        # PORT SCAN
        # ----------------------------------------------------

        ports = {}

        if ip:

            try:

                info(
                    f"Scanning common ports on {ip}..."
                )

                ports = scan_ports(ip)

                success(
                    "Port discovery completed."
                )

            except Exception as exc:
                error(
                    f"Port discovery failed: {exc}"
                )

        else:
            warning(
                "No IP address available for port scan."
            )

        # ----------------------------------------------------
        # TARGET SUMMARY
        # ----------------------------------------------------

        console.print()

        table = Table(
            title=f"Assessment Summary: {target}",
            box=box.ROUNDED,
            border_style="cyan",
        )

        table.add_column(
            "Category",
            style="bold cyan",
        )

        table.add_column("Result")

        table.add_row(
            "Target",
            target,
        )

        table.add_row(
            "IP",
            str(ip or "Not found"),
        )

        table.add_row(
            "Subdomains",
            str(
                len(subdomains)
                if subdomains
                else 0
            ),
        )

        table.add_row(
            "Technologies",
            str(
                len(technologies)
                if technologies
                else 0
            ),
        )

        table.add_row(
            "Findings",
            str(len(findings)),
        )

        console.print(table)

        console.print()

    # ========================================================
    # REPORT
    # ========================================================

    try:

        os.makedirs(
            "reports",
            exist_ok=True,
        )

        report_path = "reports/aegis_report.txt"

        generate_report(
            targets,
            findings,
            report_path,
        )

        success(
            f"Report generated: {report_path}"
        )

    except Exception as exc:

        error(
            f"Report generation failed: {exc}"
        )

    # ========================================================
    # HISTORY
    # ========================================================

    try:

        scan_id = save_scan_history(
            targets,
            findings,
        )

        success(
            f"Scan saved to history. ID: {scan_id}"
        )

    except Exception as exc:

        error(
            f"History save failed: {exc}"
        )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    console.print()

    if findings:

        console.print(
            Panel(
                f"[bold yellow]ASSESSMENT COMPLETE[/bold yellow]\n\n"
                f"Findings detected: "
                f"[bold]{len(findings)}[/bold]",
                border_style="yellow",
            )
        )

    else:

        console.print(
            Panel(
                "[bold green]ASSESSMENT COMPLETE[/bold green]\n\n"
                "No findings detected by the current checks.",
                border_style="green",
            )
        )


# ============================================================
# HISTORY VIEWER
# ============================================================

def show_history():

    title("SCAN HISTORY")

    history_file = "reports/history.json"

    if not os.path.exists(history_file):

        warning("No scan history found.")

        return

    try:

        with open(
            history_file,
            "r",
            encoding="utf-8",
        ) as f:

            history = json.load(f)

    except Exception as exc:

        error(
            f"Could not read history: {exc}"
        )

        return

    if not history:

        warning("History is empty.")

        return

    table = Table(
        title="AEGIS Scan History",
        box=box.ROUNDED,
        border_style="cyan",
    )

    table.add_column(
        "Scan ID",
        style="bold cyan",
    )

    table.add_column("Timestamp")

    table.add_column("Targets")

    table.add_column("Findings")

    for entry in reversed(history):

        targets = entry.get(
            "targets",
            [],
        )

        table.add_row(
            str(
                entry.get(
                    "scan_id",
                    "unknown",
                )
            ),
            str(
                entry.get(
                    "timestamp",
                    "",
                )
            ),
            ", ".join(
                map(
                    str,
                    targets,
                )
            ),
            str(
                entry.get(
                    "total_findings",
                    0,
                )
            ),
        )

    console.print(table)


# ============================================================
# REPORT VIEWER
# ============================================================

def show_reports():

    title("REPORTS")

    reports_dir = "reports"

    if not os.path.exists(reports_dir):

        warning("Reports directory does not exist.")

        return

    files = []

    for filename in os.listdir(reports_dir):

        path = os.path.join(
            reports_dir,
            filename,
        )

        if os.path.isfile(path):

            files.append(filename)

    if not files:

        warning("No reports found.")

        return

    table = Table(
        title="Available Reports",
        box=box.ROUNDED,
        border_style="cyan",
    )

    table.add_column(
        "#",
        style="bold cyan",
    )

    table.add_column("File")

    for index, filename in enumerate(
        sorted(files),
        1,
    ):

        table.add_row(
            str(index),
            filename,
        )

    console.print(table)

    console.print()

    choice = Prompt.ask(
        "Enter report number to view",
        default="0",
    )

    if choice == "0":
        return

    try:

        index = int(choice) - 1

        filename = sorted(files)[index]

        path = os.path.join(
            reports_dir,
            filename,
        )

        console.print()

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as f:

            content = f.read()

        console.print(
            Panel(
                content,
                title=filename,
                border_style="green",
            )
        )

    except Exception as exc:

        error(
            f"Could not open report: {exc}"
        )


# ============================================================
# INTERACTIVE AEGIS MENU
# ============================================================

def interactive_mode():

    while True:

        show_banner()

        menu = Table(
            box=box.ROUNDED,
            border_style="cyan",
            show_header=False,
            padding=(0, 2),
        )

        menu.add_column(
            "Option",
            style="bold cyan",
            width=8,
        )

        menu.add_column(
            "Module",
            style="white",
        )

        menu.add_row(
            "[1]",
            "Reconnaissance",
        )

        menu.add_row(
            "[2]",
            "Technology Detection",
        )

        menu.add_row(
            "[3]",
            "Port Discovery",
        )

        menu.add_row(
            "[4]",
            "Full Security Assessment",
        )

        menu.add_row(
            "[5]",
            "Scan History",
        )

        menu.add_row(
            "[6]",
            "Reports",
        )

        menu.add_row(
            "[0]",
            "Exit",
        )

        console.print(menu)

        console.print()

        choice = Prompt.ask(
            "[bold cyan]AEGIS[/bold cyan]",
            choices=[
                "0",
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
            ],
            default="0",
        )

        # ----------------------------------------------------
        # EXIT
        # ----------------------------------------------------

        if choice == "0":

            console.print()

            console.print(
                Panel(
                    "[bold cyan]AEGIS SHUTDOWN[/bold cyan]\n\n"
                    "[dim]Session terminated safely.[/dim]",
                    border_style="cyan",
                )
            )

            break

        # ----------------------------------------------------
        # RECON
        # ----------------------------------------------------

        elif choice == "1":

            console.clear()

            domain = Prompt.ask(
                "[bold cyan]Target domain[/bold cyan]"
            )

            run_recon(domain)

            pause()

        # ----------------------------------------------------
        # TECHNOLOGY
        # ----------------------------------------------------

        elif choice == "2":

            console.clear()

            domain = Prompt.ask(
                "[bold cyan]Target domain[/bold cyan]"
            )

            run_technology(domain)

            pause()

        # ----------------------------------------------------
        # PORTS
        # ----------------------------------------------------

        elif choice == "3":

            console.clear()

            host = Prompt.ask(
                "[bold cyan]Target host/IP[/bold cyan]"
            )

            run_ports(host)

            pause()

        # ----------------------------------------------------
        # FULL SCAN
        # ----------------------------------------------------

        elif choice == "4":

            console.clear()

            domain = Prompt.ask(
                "[bold cyan]Authorized target domain[/bold cyan]"
            )

            run_scan([domain])

            pause()

        # ----------------------------------------------------
        # HISTORY
        # ----------------------------------------------------

        elif choice == "5":

            console.clear()

            show_history()

            pause()

        # ----------------------------------------------------
        # REPORTS
        # ----------------------------------------------------

        elif choice == "6":

            console.clear()

            show_reports()

            pause()


# ============================================================
# CLI MODE
# ============================================================

def main():

    # --------------------------------------------------------
    # IMPORTANT:
    # No arguments = launch cinematic interactive interface.
    # --------------------------------------------------------

    if len(sys.argv) == 1:

        interactive_mode()

        return

    parser = argparse.ArgumentParser(
        prog="aegis",
        description=(
            "AI-powered authorized "
            "security assessment assistant"
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    # --------------------------------------------------------
    # RECON
    # --------------------------------------------------------

    recon_parser = subparsers.add_parser(
        "recon",
        help="Run reconnaissance",
    )

    recon_parser.add_argument(
        "domain",
        help="Target domain",
    )

    # --------------------------------------------------------
    # TECHNOLOGY
    # --------------------------------------------------------

    tech_parser = subparsers.add_parser(
        "tech",
        help="Detect web technologies",
    )

    tech_parser.add_argument(
        "domain",
        help="Target domain",
    )

    # --------------------------------------------------------
    # PORTS
    # --------------------------------------------------------

    ports_parser = subparsers.add_parser(
        "ports",
        help="Discover common open ports",
    )

    ports_parser.add_argument(
        "host",
        help="Target host or IP",
    )

    # --------------------------------------------------------
    # SCAN
    # --------------------------------------------------------

    scan_parser = subparsers.add_parser(
        "scan",
        help="Run security assessment",
    )

    scan_parser.add_argument(
        "--scope",
        required=True,
        help="Path to scope file",
    )

    # --------------------------------------------------------
    # PARSE
    # --------------------------------------------------------

    args = parser.parse_args()

    # --------------------------------------------------------
    # COMMAND HANDLERS
    # --------------------------------------------------------

    if args.command == "recon":

        run_recon(args.domain)

    elif args.command == "tech":

        run_technology(args.domain)

    elif args.command == "ports":

        run_ports(args.host)

    elif args.command == "scan":

        targets = load_scope(
            args.scope
        )

        if not targets:

            error(
                "Scope file contains no valid targets."
            )

            return

        run_scan(targets)

    else:

        interactive_mode()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()

