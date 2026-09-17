#!/usr/bin/env python3
"""
CLI entry point wiring together host discovery, port scanning, config
checks, and report generation.

Usage:
    sudo python scripts/run_audit.py --subnet 192.168.1.0/24
    python scripts/run_audit.py --host 192.168.1.1
    python scripts/run_audit.py --local-only

TODO(implementation):
    - argparse: mutually exclusive --subnet / --host / --local-only
    - if --subnet: hosts = host_discovery.discover_hosts(subnet)
      if --host: hosts = [host]
      if --local-only: skip network scanning entirely
    - for each host: findings = port_scanner.scan_host(host); classify
      each open port with risk_rules.classify_port(port, banner)
    - always run local config checks (ssh_check.check_ssh_config(),
      firewall_check.check_firewall()) regardless of mode, since
      they're about this machine, not the network
    - content = report_generator.build_report(host_findings, config_findings)
    - path = report_generator.write_report(content)
    - print a short summary to stdout (finding counts by severity) and
      the report path — don't dump the whole report to the terminal
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scan.host_discovery import discover_hosts
from scan.port_scanner import scan_host
from checks.risk_rules import classify_port
from checks.ssh_check import check_ssh_config
from checks.firewall_check import check_firewall
from report.report_generator import build_report, write_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Home network security audit tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--subnet", type=str, help="CIDR subnet to scan, e.g. 192.168.1.0/24")
    group.add_argument("--host", type=str, help="Single host/IP to scan")
    group.add_argument("--local-only", action="store_true", help="Skip network scan, run local config checks only")
    args = parser.parse_args()

    raise NotImplementedError(
        "run_audit main: wire together discover_hosts/scan_host/classify_port for "
        "--subnet or --host, always run check_ssh_config + check_firewall, then "
        "build_report + write_report. See module docstring for the intended flow."
    )


if __name__ == "__main__":
    main()
