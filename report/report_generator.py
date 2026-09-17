"""
Stage: Render collected findings (open ports classified by risk +
config check results) into a readable Markdown report.

Findings from checks/risk_rules.py (PortRule dataclasses) and
checks/ssh_check.py / checks/firewall_check.py (plain dicts) are
normalized into a common shape here so they can be sorted and
rendered together by severity.

TODO(implementation):
    - normalize_finding(source: str, finding) -> dict: convert either
      a PortRule or a check-module dict into a common shape:
      {"source": str, "title": str, "severity": Severity, "reason": str,
       "remediation": str}
    - build_report(host_findings: dict[str, list], config_findings: list) -> str:
        1. Flatten + normalize all findings
        2. Sort by risk_rules.severity_rank(), most severe first
        3. Render as Markdown: a summary count by severity at the top,
           then a table or section per host, then a "Local Config"
           section for SSH/firewall findings
    - write_report(content: str, output_dir: str) -> Path: write to
      data/reports/audit_<timestamp>.md, return the path so the CLI
      can print it.
"""

from datetime import datetime, timezone
from pathlib import Path

from checks.risk_rules import Severity, severity_rank


def normalize_finding(source: str, finding) -> dict:
    raise NotImplementedError("normalize_finding: handle both PortRule and check-dict shapes")


def build_report(host_findings: dict[str, list], config_findings: list) -> str:
    raise NotImplementedError("build_report: flatten, sort by severity, render Markdown")


def write_report(content: str, output_dir: str = "data/reports") -> Path:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = Path(output_dir) / f"audit_{timestamp}.md"
    path.write_text(content)
    return path
