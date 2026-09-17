"""
Tests for checks/risk_rules.py — pure logic, no live system/network
dependency, so it's the easiest module to verify correctness on
before wiring up nmap-dependent scanning.

Run with:
    python -m pytest tests/
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.risk_rules import classify_port, severity_rank, Severity


def test_known_critical_port_classified_correctly():
    rule = classify_port(23)
    assert rule.service_name == "Telnet"
    assert rule.severity == Severity.CRITICAL


def test_known_high_risk_port_classified_correctly():
    rule = classify_port(21)
    assert rule.service_name == "FTP"
    assert rule.severity == Severity.HIGH


def test_known_low_risk_port_classified_as_info():
    rule = classify_port(22)
    assert rule.service_name == "SSH"
    assert rule.severity == Severity.INFO


def test_unknown_port_flagged_for_review_not_ignored():
    rule = classify_port(54321)
    assert rule.severity == Severity.MEDIUM
    assert "unknown" in rule.reason.lower() or "no recognized service" in rule.reason.lower()


def test_unknown_port_includes_banner_in_reason_when_given():
    rule = classify_port(54321, banner="mystery-service 1.0")
    assert "mystery-service" in rule.reason


def test_severity_rank_orders_correctly():
    assert severity_rank(Severity.INFO) < severity_rank(Severity.LOW)
    assert severity_rank(Severity.LOW) < severity_rank(Severity.MEDIUM)
    assert severity_rank(Severity.MEDIUM) < severity_rank(Severity.HIGH)
    assert severity_rank(Severity.HIGH) < severity_rank(Severity.CRITICAL)
