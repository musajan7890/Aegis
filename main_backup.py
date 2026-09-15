import argparse
import json
import os
from datetime import datetime

from core.scope import load_scope
from recon.dns import resolve_domain
from recon.subdomains import discover_subdomains
from technology.http_probe import fetch_http_info
from technology.fingerprint import detect_technologies
from discovery.port_scanner import scan_ports
from security.headers import check_security_headers
from findings.engine import analyze_security_headers
from reports.reporter import generate_report


def save_scan_history(
    targets: list[str],
    findings: list[dict]
) -> None:

    history_file = "reports/history.json"

    os.makedirs("reports", exist_ok=True)

    history = []

    if os.path.exists(history_file):

        try:

            with open(
                history_file,
                "r",
                encoding="utf-8"
            ) as file:

                history = json.load(file)

                if not isinstance(history, list):
                    history = []

        except (json.JSONDecodeError, OSError):

            history = []

    scan_record = {
        "scan_id": len(history) + 1,
        "timestamp": datetime.now().isoformat(
            timespec="seconds"
        ),
        "targets": targets,
        "total_findings": len(findings),
        "findings": findings
    }

    history.append(scan_record)

    with open(
        history_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            history,
            file,
            indent=4
        )


def main():

    parser = argparse.ArgumentParser(
        prog="aegis",
        description="AI-powered authorized security assessment assistant"
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    # ============================================================
    # RECON
    # ============================================================

    recon_parser = subparsers.add_parser(
        "recon",
        help="Run reconnaissance"
    )

    recon_parser.add_argument(
        "domain",
        help="Authorized domain to analyze"
    )

    # ============================================================
    # TECHNOLOGY
    # ============================================================

    tech_parser = subparsers.add_parser(
        "tech",
        help="Detect web technologies"
    )

    tech_parser.add_argument(
        "domain",
        help="Authorized domain to analyze"
    )

    # ============================================================
    # PORT DISCOVERY
    # ============================================================

    ports_parser = subparsers.add_parser(
        "ports",
        help="Discover common open ports"
    )

    ports_parser.add_argument(
        "host",
        help="Authorized host to analyze"
    )

    # ============================================================
    # FULL SCAN
    # ============================================================

    scan_parser = subparsers.add_parser(
        "scan",
        help="Run security assessment"
    )

    scan_parser.add_argument(
        "--scope",
        required=True,
        help="Path to authorized scope file"
    )

    args = parser.parse_args()

    # ============================================================
    # RECON
    # ============================================================

    if args.command == "recon":

        domain = args.domain.strip()

        if not domain:

            print("[!] Domain cannot be empty.")
            return

        print()
        print("=" * 50)
        print("             AEGIS RECON")
        print("=" * 50)

        print()
        print(f"[*] Target: {domain}")
        print("[*] Resolving domain...")

        dns_result = resolve_domain(domain)

        print()
        print("[+] DNS Resolution")
        print(f"    Domain : {dns_result['domain']}")
        print(f"    IP     : {dns_result['ip']}")
        print(f"    Status : {dns_result['status']}")

        if dns_result["status"] != "resolved":

            print("[!] DNS resolution failed.")
            return

        print()
        print("[*] Discovering subdomains...")

        try:

            with open(
                "recon/subdomains.txt",
                "r",
                encoding="utf-8"
            ) as file:

                wordlist = [
                    line.strip()
                    for line in file
                    if line.strip()
                ]

        except FileNotFoundError:

            print(
                "[!] recon/subdomains.txt not found."
            )

            return

        subdomains = discover_subdomains(
            domain,
            wordlist
        )

        print()
        print(
            f"[+] Subdomains discovered: "
            f"{len(subdomains)}"
        )

        if subdomains:

            for subdomain in subdomains:

                print(
                    f"    -> {subdomain}"
                )

        else:

            print(
                "    No subdomains discovered."
            )

        print()
        print("[+] Recon completed.")

    # ============================================================
    # TECHNOLOGY DETECTION
    # ============================================================

    elif args.command == "tech":

        domain = args.domain.strip()

        print()
        print("=" * 50)
        print("          AEGIS TECHNOLOGY DETECTOR")
        print("=" * 50)

        print()
        print(f"[*] Target: {domain}")
        print("[*] Fetching HTTP information...")

        result = fetch_http_info(domain)

        if result["error"]:

            print()
            print("[!] HTTP request failed.")
            print(
                f"    Error: {result['error']}"
            )

            return

        print()
        print("[+] HTTP Information")

        print(
            f"    URL         : "
            f"{result['url']}"
        )

        print(
            f"    Status Code : "
            f"{result['status_code']}"
        )

        print()
        print(
            "[*] Analyzing technology fingerprints..."
        )

        technologies = detect_technologies(
            result["headers"],
            result["body"]
        )

        print()
        print("[+] Technologies Detected")

        if technologies:

            for technology in technologies:

                print(
                    f"    -> {technology}"
                )

        else:

            print(
                "    No known technologies detected."
            )

        print()
        print(
            "[+] Technology detection completed."
        )

    # ============================================================
    # PORT DISCOVERY
    # ============================================================

    elif args.command == "ports":

        host = args.host.strip()

        print()
        print("=" * 50)
        print("            AEGIS PORT DISCOVERY")
        print("=" * 50)

        print()
        print(f"[*] Target: {host}")
        print("[*] Scanning common ports...")

        ports = scan_ports(host)

        print()
        print("[+] Open Ports")

        if ports:

            for result in ports:

                print(
                    f"    -> "
                    f"{result['port']:<5} "
                    f"{result['service']}"
                )

        else:

            print(
                "    No open common ports detected."
            )

        print()
        print(
            "[+] Port discovery completed."
        )

    # ============================================================
    # FULL SECURITY ASSESSMENT
    # ============================================================

    elif args.command == "scan":

        try:

            targets = load_scope(
                args.scope
            )

            if not targets:

                print(
                    "[!] Scope file is empty."
                )

                return

            print()
            print("=" * 50)
            print("        AEGIS SECURITY ASSISTANT")
            print("=" * 50)

            print()

            print(
                "[+] Scope loaded"
            )

            print(
                f"[+] Targets: {len(targets)}"
            )

            print()

            for target in targets:

                print(
                    f"    -> {target}"
                )

            # ====================================================
            # FINDINGS STORAGE
            # ====================================================

            all_findings = []

            # ====================================================
            # PROCESS EACH TARGET
            # ====================================================

            for target in targets:

                print()
                print("-" * 50)

                print(
                    f"[*] Processing target: {target}"
                )

                print("-" * 50)

                # =================================================
                # DNS
                # =================================================

                print()
                print(
                    "[*] Resolving domain..."
                )

                dns_result = resolve_domain(
                    target
                )

                print(
                    f"[+] DNS Status: "
                    f"{dns_result['status']}"
                )

                if dns_result["status"] != "resolved":

                    print(
                        "[!] DNS resolution failed."
                    )

                    continue

                ip = dns_result["ip"]

                print(
                    f"    IP: {ip}"
                )

                # =================================================
                # SUBDOMAINS
                # =================================================

                print()
                print(
                    "[*] Discovering subdomains..."
                )

                try:

                    with open(
                        "recon/subdomains.txt",
                        "r",
                        encoding="utf-8"
                    ) as file:

                        wordlist = [
                            line.strip()
                            for line in file
                            if line.strip()
                        ]

                except FileNotFoundError:

                    print(
                        "[!] recon/subdomains.txt "
                        "not found."
                    )

                    wordlist = []

                if wordlist:

                    subdomains = discover_subdomains(
                        target,
                        wordlist
                    )

                    print()
                    print(
                        "[+] Subdomains discovered"
                    )

                    if subdomains:

                        for subdomain in subdomains:

                            print(
                                f"    -> "
                                f"{subdomain}"
                            )

                    else:

                        print(
                            "    No subdomains discovered."
                        )

                # =================================================
                # HTTP PROBE
                # =================================================

                print()
                print(
                    "[*] Fetching HTTP information..."
                )

                http_result = fetch_http_info(
                    target
                )

                if http_result["error"]:

                    print(
                        "[!] HTTP request failed."
                    )

                    print(
                        f"    Error: "
                        f"{http_result['error']}"
                    )

                else:

                    print()
                    print(
                        "[+] HTTP Information"
                    )

                    print(
                        f"    URL         : "
                        f"{http_result['url']}"
                    )

                    print(
                        f"    Status Code : "
                        f"{http_result['status_code']}"
                    )

                    # =============================================
                    # TECHNOLOGY
                    # =============================================

                    print()
                    print(
                        "[*] Detecting technologies..."
                    )

                    technologies = detect_technologies(
                        http_result["headers"],
                        http_result["body"]
                    )

                    print()
                    print(
                        "[+] Technologies Detected"
                    )

                    if technologies:

                        for technology in technologies:

                            print(
                                f"    -> "
                                f"{technology}"
                            )

                    else:

                        print(
                            "    No known technologies "
                            "detected."
                        )

                    # =============================================
                    # SECURITY HEADERS
                    # =============================================

                    print()
                    print(
                        "[*] Checking security headers..."
                    )

                    header_results = check_security_headers(
                        http_result["headers"]
                    )

                    print()
                    print(
                        "[+] Security Headers"
                    )

                    for result in header_results:

                        if result["status"] == "present":

                            print(
                                f"    [+] "
                                f"{result['header']}: "
                                f"PRESENT"
                            )

                        else:

                            print(
                                f"    [!] "
                                f"{result['header']}: "
                                f"MISSING"
                            )

                    # =============================================
                    # FINDINGS ENGINE
                    # =============================================

                    print()
                    print(
                        "[*] Analyzing security observations..."
                    )

                    findings = analyze_security_headers(
                        header_results
                    )

                    all_findings.extend(
                        findings
                    )

                    print()
                    print(
                        "[+] Findings Generated"
                    )

                    if findings:

                        for finding in findings:

                            print()
                            print(
                                f"    Title    : "
                                f"{finding['title']}"
                            )

                            print(
                                f"    Severity : "
                                f"{finding['severity']}"
                            )

                            print(
                                f"    Evidence : "
                                f"{finding['evidence']}"
                            )

                    else:

                        print(
                            "    No security-header "
                            "findings generated."
                        )

                # =================================================
                # PORT DISCOVERY
                # =================================================

                print()
                print(
                    "[*] Scanning common ports..."
                )

                ports = scan_ports(ip)

                print()
                print(
                    "[+] Open Ports"
                )

                if ports:

                    for result in ports:

                        print(
                            f"    -> "
                            f"{result['port']:<5} "
                            f"{result['service']}"
                        )

                else:

                    print(
                        "    No open common ports detected."
                    )

            # ====================================================
            # FINDINGS SUMMARY
            # ====================================================

            print()
            print("=" * 50)
            print(
                "             FINDINGS SUMMARY"
            )
            print("=" * 50)

            print()

            if all_findings:

                print(
                    f"[+] Total Findings: "
                    f"{len(all_findings)}"
                )

                print()

                for number, finding in enumerate(
                    all_findings,
                    start=1
                ):

                    print(
                        f"{number}. "
                        f"[{finding['severity']}] "
                        f"{finding['title']}"
                    )

            else:

                print(
                    "[+] No findings generated."
                )

            # ====================================================
            # GENERATE REPORT
            # ====================================================

            print()
            print(
                "[*] Generating security report..."
            )

            os.makedirs(
                "reports",
                exist_ok=True
            )

            report_file = (
                "reports/aegis_report.txt"
            )

            generate_report(
                target=", ".join(targets),
                findings=all_findings,
                output_file=report_file
            )

            print(
                "[+] Report generated:"
            )

            print(
                f"    {report_file}"
            )

            # ====================================================
            # SAVE HISTORY
            # ====================================================

            print()
            print(
                "[*] Saving scan history..."
            )

            save_scan_history(
                targets=targets,
                findings=all_findings
            )

            print(
                "[+] Scan history saved:"
            )

            print(
                "    reports/history.json"
            )

            # ====================================================
            # COMPLETE
            # ====================================================

            print()
            print("=" * 50)
            print(
                "[+] AEGIS assessment completed."
            )
            print("=" * 50)

        except FileNotFoundError as error:

            print(
                f"[!] Error: {error}"
            )

    # ============================================================
    # NO COMMAND
    # ============================================================

    else:

        parser.print_help()


if __name__ == "__main__":
    main()