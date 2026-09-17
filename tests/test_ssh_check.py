"""
Tests for checks/ssh_check.py — pure string parsing, tested against
realistic sshd_config snippets with no live system dependency.

Run with:
    python -m pytest tests/
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.ssh_check import check_ssh_config, parse_sshd_config
from checks.risk_rules import Severity


def test_parses_directives_case_insensitively():
    result = parse_sshd_config("PermitRootLogin yes\nPORT 2222\n")
    assert result["permitrootlogin"] == "yes"
    assert result["port"] == "2222"


def test_skips_comments_and_blank_lines():
    result = parse_sshd_config(
        "# This is a comment\n\nPermitRootLogin prohibit-password\n"
        "    PasswordAuthentication no\n"
    )
    assert result["permitrootlogin"] == "prohibit-password"
    assert result["passwordauthentication"] == "no"


def test_keeps_first_value_token():
    result = parse_sshd_config("MaxAuthTries 6 something-else\n")
    assert result["maxauthtries"] == "6"


def test_later_directive_overrides_earlier():
    result = parse_sshd_config("PasswordAuthentication yes\nPasswordAuthentication no\n")
    assert result["passwordauthentication"] == "no"


def test_no_findings_when_hardened(tmp_path):
    config = tmp_path / "sshd_config"
    config.write_text("PermitRootLogin no\nPasswordAuthentication no\n")
    result = check_ssh_config(str(config))
    assert result == []


def test_finds_risky_directives(tmp_path):
    config = tmp_path / "sshd_config"
    config.write_text("PermitRootLogin yes\nPasswordAuthentication yes\n")
    result = check_ssh_config(str(config))
    assert len(result) == 2
    by_title = {finding["title"] for finding in result}
    assert "sshd_config: PermitRootLogin yes" in by_title
    assert "sshd_config: PasswordAuthentication yes" in by_title
    assert all(finding["severity"] in (Severity.HIGH, Severity.MEDIUM) for finding in result)


def test_unreadable_config_reported_not_crashing(tmp_path):
    missing = tmp_path / "does-not-exist"
    result = check_ssh_config(str(missing))
    assert len(result) == 1
    assert result[0]["severity"] is Severity.INFO
    assert "could not read" in result[0]["reason"].lower()