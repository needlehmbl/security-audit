"""
Tests for checks/firewall_check.py's parse_ufw_status — pure string
parsing, tested against realistic sample output so it works
correctly before ever shelling out to a real `ufw` binary.

Run with:
    python -m pytest tests/
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.firewall_check import check_firewall, get_ufw_status, parse_ufw_status
from checks.risk_rules import Severity

ACTIVE_SAMPLE = """
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
"""

INACTIVE_SAMPLE = """
Status: inactive
"""


def test_parses_active_status():
    result = parse_ufw_status(ACTIVE_SAMPLE)
    assert result["active"] is True


def test_parses_inactive_status():
    result = parse_ufw_status(INACTIVE_SAMPLE)
    assert result["active"] is False


def test_parses_default_policies():
    result = parse_ufw_status(ACTIVE_SAMPLE)
    assert result["default_incoming"] == "deny"
    assert result["default_outgoing"] == "allow"


def test_parses_rules_list():
    result = parse_ufw_status(ACTIVE_SAMPLE)
    assert len(result["rules"]) == 3
    assert any("22/tcp" in rule for rule in result["rules"])
    assert any("443/tcp" in rule for rule in result["rules"])


def test_inactive_firewall_has_no_rules():
    result = parse_ufw_status(INACTIVE_SAMPLE)
    assert result["rules"] == []


def test_check_firewall_active(monkeypatch):
    monkeypatch.setattr("checks.firewall_check.shutil.which", lambda name: "/usr/bin/ufw" if name == "ufw" else None)
    import checks.firewall_check as fc
    monkeypatch.setattr(fc, "get_ufw_status", lambda: ACTIVE_SAMPLE)
    result = check_firewall()
    assert len(result) == 1
    assert result[0]["title"] == "ufw firewall is active"
    assert result[0]["severity"] is Severity.INFO


def test_check_firewall_inactive(monkeypatch):
    import checks.firewall_check as fc
    monkeypatch.setattr(fc.shutil, "which", lambda name: "/usr/bin/ufw" if name == "ufw" else None)
    monkeypatch.setattr(fc, "get_ufw_status", lambda: INACTIVE_SAMPLE)
    result = check_firewall()
    assert result[0]["title"] == "ufw firewall is inactive"
    assert result[0]["severity"] is Severity.HIGH


def test_check_firewall_ufw_missing_iptables_present(monkeypatch):
    import checks.firewall_check as fc
    monkeypatch.setattr(fc.shutil, "which", lambda name: "/usr/sbin/iptables" if name == "iptables" else None)
    result = check_firewall()
    assert result[0]["title"] == "ufw not installed (iptables present)"
    assert result[0]["severity"] is Severity.INFO


def test_check_firewall_no_tools(monkeypatch):
    import checks.firewall_check as fc
    monkeypatch.setattr(fc.shutil, "which", lambda name: None)
    result = check_firewall()
    assert result[0]["title"] == "No firewall tool detected"
    assert result[0]["severity"] is Severity.HIGH


def test_check_firewall_unable_to_read(monkeypatch):
    import checks.firewall_check as fc
    monkeypatch.setattr(fc.shutil, "which", lambda name: "/usr/bin/ufw" if name == "ufw" else None)

    def boom():
        raise RuntimeError("a password is required")

    monkeypatch.setattr(fc, "get_ufw_status", boom)
    result = check_firewall()
    assert result[0]["title"] == "Could not determine firewall status"
    assert result[0]["severity"] is Severity.INFO
