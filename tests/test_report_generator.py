"""
Tests for report/report_generator.py — pure logic (normalize + render),
no live system/network dependency.

Run with:
    python -m pytest tests/
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.risk_rules import PortRule, Severity
from report.report_generator import build_report, normalize_finding


def test_normalize_port_rule():
    rule = PortRule(23, "Telnet", Severity.CRITICAL, "plaintext", "use ssh")
    result = normalize_finding("port-scan", rule)
    assert result["source"] == "port-scan"
    assert result["title"] == "Telnet (port 23)"
    assert result["severity"] is Severity.CRITICAL
    assert result["reason"] == "plaintext"
    assert result["remediation"] == "use ssh"


def test_normalize_scan_dict_wrapping_port_rule():
    rule = PortRule(23, "Telnet", Severity.CRITICAL, "plaintext", "use ssh")
    scanned = {"host": "192.168.1.1", "port": 23, "service": "telnet", "banner": "x", "rule": rule}
    result = normalize_finding("port-scan", scanned)
    assert result["title"] == "Telnet (port 23)"
    assert result["severity"] is Severity.CRITICAL


def test_normalize_config_dict_with_string_severity():
    finding = {"source": "ssh", "title": "x", "severity": "high", "reason": "r", "remediation": "m"}
    result = normalize_finding(finding["source"], finding)
    assert result["severity"] is Severity.HIGH


def test_build_report_summary_counts():
    rule = PortRule(23, "Telnet", Severity.CRITICAL, "plaintext", "use ssh")
    config = {"source": "firewall", "title": "inactive", "severity": Severity.HIGH,
              "reason": "no firewall", "remediation": "enable"}
    content = build_report({"192.168.1.5": [rule]}, [config])
    assert "## Summary" in content
    assert "| critical | 1 |" in content
    assert "| high | 1 |" in content


def test_build_report_includes_host_and_config_sections():
    rule = PortRule(22, "SSH", Severity.INFO, "fine", "none")
    content = build_report({"192.168.1.5": [rule]}, [])
    assert "### 192.168.1.5" in content
    assert "[INFO] SSH (port 22)" in content


def test_build_report_local_only_mode():
    content = build_report({}, [])
    assert "No hosts scanned (local-only mode)." in content
    assert "No configuration findings." in content


def test_build_report_sorts_most_severe_first():
    low = PortRule(53, "DNS", Severity.LOW, "dns", "none")
    crit = PortRule(23, "Telnet", Severity.CRITICAL, "plaintext", "use ssh")
    content = build_report({"h": [low, crit]}, [])
    assert content.index("CRITICAL") < content.index("[LOW]")


def test_write_report_writes_markdown_file(tmp_path):
    from report.report_generator import write_report
    out = tmp_path / "reports"
    path = write_report("# hi\n", str(out))
    assert path.exists()
    assert path.read_text() == "# hi\n"