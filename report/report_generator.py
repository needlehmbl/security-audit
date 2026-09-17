"""
Stage: Render collected findings (open ports classified by risk +
config check results) into a readable Markdown report.

Findings from checks/risk_rules.py (PortRule dataclasses) and
checks/ssh_check.py / checks/firewall_check.py (plain dicts) are
normalized into a common shape here so they can be sorted and
rendered together by severity.
"""

from datetime import datetime, timezone
from pathlib import Path

from checks.risk_rules import PortRule, Severity, severity_rank


def _port_rule_to_dict(source: str, rule: PortRule) -> dict:
    return {
        "source": source,
        "title": f"{rule.service_name} (port {rule.port})",
        "severity": rule.severity,
        "reason": rule.reason,
        "remediation": rule.remediation,
    }


def normalize_finding(source: str, finding) -> dict:
    """
    Convert either a PortRule, a scan dict wrapping a PortRule ({"rule": ...}),
    or a check-module dict into the common shape:
    {"source": str, "title": str, "severity": Severity, "reason": str,
     "remediation": str}.

    Config-module dicts already carry these keys and pass through with a
    guaranteed Severity enum; a PortRule gets a title derived from its
    service name and port.
    """
    if isinstance(finding, PortRule):
        return _port_rule_to_dict(source, finding)

    if isinstance(finding, dict) and isinstance(finding.get("rule"), PortRule):
        return _port_rule_to_dict(source, finding["rule"])

    severity = finding.get("severity")
    if not isinstance(severity, Severity):
        severity = Severity(severity)
    return {
        "source": source,
        "title": finding.get("title", "Finding"),
        "severity": severity,
        "reason": finding.get("reason", ""),
        "remediation": finding.get("remediation", ""),
    }


def _sort_by_severity(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: severity_rank(f["severity"]), reverse=True)


def build_report(host_findings: dict[str, list], config_findings: list) -> str:
    """
    Render all findings as Markdown: a severity-count summary table up
    top, a section per scanned host (ports sorted most-severe first),
    then a Local Config section for SSH/firewall findings.
    """
    lines = ["# Security Audit Report", ""]
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("")

    normalized_hosts: dict[str, list[dict]] = {}
    for host, findings in host_findings.items():
        normalized_hosts[host] = _sort_by_severity(
            [normalize_finding("port-scan", f) for f in findings]
        )

    config = _sort_by_severity([normalize_finding(f.get("source", "config"), f) for f in config_findings])

    all_findings = [f for findings in normalized_hosts.values() for f in findings] + config

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        count = sum(1 for f in all_findings if f["severity"] is severity)
        lines.append(f"| {severity.value} | {count} |")
    lines.append("")

    if normalized_hosts:
        lines.append("## Hosts")
        lines.append("")
        for host, findings in normalized_hosts.items():
            lines.append(f"### {host}")
            lines.append("")
            if not findings:
                lines.append("No open ports detected.")
                lines.append("")
                continue
            for finding in findings:
                lines.append(_render_finding(finding))
    else:
        lines.append("## Hosts")
        lines.append("")
        lines.append("No hosts scanned (local-only mode).")
        lines.append("")

    lines.append("## Local Config")
    lines.append("")
    if not config:
        lines.append("No configuration findings.")
        lines.append("")
    else:
        for finding in config:
            lines.append(_render_finding(finding))

    return "\n".join(lines).rstrip() + "\n"


def _render_finding(finding: dict) -> str:
    severity = finding["severity"].value.upper()
    lines = [
        f"- **[{severity}] {finding['title']}**",
        f"  - {finding['reason']}",
        f"  - *Remediation: {finding['remediation']}*",
        "",
    ]
    return "\n".join(lines)


def write_report(content: str, output_dir: str = "data/reports") -> Path:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = Path(output_dir) / f"audit_{timestamp}.md"
    path.write_text(content)
    return path