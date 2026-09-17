#!/usr/bin/env python3
"""
CLI entry point wiring together host discovery, port scanning, config
checks, and report generation.

Usage:
    sudo python scripts/run_audit.py --subnet 192.168.1.0/24
    python scripts/run_audit.py --host 192.168.1.1
    python scripts/run_audit.py --local-only

Local config checks (SSH, firewall) always run regardless of mode,
since they're about this machine, not the network. A short summary —
finding counts by severity plus the report path — is printed to
stdout; the full report is written to disk as Markdown.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.risk_rules import Severity, classify_port, severity_rank
from checks.ssh_check import check_ssh_config
from checks.firewall_check import check_firewall
from scan.host_discovery import NmapNotFound, discover_hosts
from scan.port_scanner import scan_host
from report.report_generator import build_report, normalize_finding, write_report


def _classify_host(host: str, port_range: str = "1-1024") -> list[dict]:
    results = scan_host(host, port_range)
    return [
        {**result, "rule": classify_port(result["port"], result["banner"])}
        for result in results
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Home network security audit tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--subnet", type=str, help="CIDR subnet to scan, e.g. 192.168.1.0/24")
    group.add_argument("--host", type=str, help="Single host/IP to scan")
    group.add_argument("--local-only", action="store_true", help="Skip network scan, run local config checks only")
    args = parser.parse_args()

    host_findings: dict[str, list] = {}

    if args.subnet or args.host:
        hosts = [args.host] if args.host else None
        try:
            if hosts is None:
                hosts = discover_hosts(args.subnet)
        except NmapNotFound as exc:
            print(f"Network scan skipped: {exc}", file=sys.stderr)
            hosts = []
        for host in hosts:
            try:
                host_findings[host] = _classify_host(host)
            except NmapNotFound as exc:
                print(f"Port scan skipped: {exc}", file=sys.stderr)
                break

    config_findings = check_ssh_config() + check_firewall()

    content = build_report(host_findings, config_findings)
    path = write_report(content)
    print_summary(host_findings, config_findings, path)


def print_summary(host_findings: dict[str, list], config_findings: list, path: Path) -> None:
    all_findings: list[dict] = []
    for findings in host_findings.values():
        for finding in findings:
            all_findings.append(normalize_finding("port-scan", finding))
    for finding in config_findings:
        all_findings.append(normalize_finding(finding.get("source", "config"), finding))

    counts = {
        severity: sum(1 for f in all_findings if f["severity"] is severity)
        for severity in Severity
    }
    severities = sorted(Severity, key=severity_rank, reverse=True)
    summary = ", ".join(f"{severity.value}: {counts[severity]}" for severity in severities)
    hosts_scanned = ", ".join(host_findings) or "none"
    print(f"Report: {path}")
    print(f"Hosts scanned: {hosts_scanned}")
    print(f"Findings -> {summary}")


if __name__ == "__main__":
    main()