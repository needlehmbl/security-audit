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

from checks.firewall_check import parse_ufw_status

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
