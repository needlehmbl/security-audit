"""
Check sshd_config for common weak/insecure settings.

Parsing logic (parse_sshd_config) is pure string handling with no
live-system dependency — tested against sample configs the same way
firewall_check.py's ufw parser is. Reading the real file and shelling
out are handled gracefully: if sshd_config is unreadable (it's often
root-readable only) that's noted as a finding in the report rather
than a crash.

Reading the file requires read access to /etc/ssh/sshd_config, which
some systems restrict to root — check_ssh_config() returns a finding
telling the operator to re-run with elevated privileges in that case.
"""

from pathlib import Path

from checks.risk_rules import Severity


def read_sshd_config(path: str = "/etc/ssh/sshd_config") -> str:
    """Return the raw contents of sshd_config, or raise OSError if unreadable."""
    return Path(path).read_text()


def parse_sshd_config(raw_text: str) -> dict[str, str]:
    """
    Extract sshd_config directives as a dict of {directive: value}.

    Comments (#) and blank lines are skipped, directive names are
    case-insensitive, and only the first value token is kept (a later
    directive overrides an earlier one, matching OpenSSH's last-wins
    behavior).

        parse_sshd_config("PermitRootLogin yes\nPasswordAuthentication no")
        -> {"PermitRootLogin": "yes", "PasswordAuthentication": "no"}
    """
    parsed: dict[str, str] = {}
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) < 2:
            continue
        directive, value = parts[0], parts[1].split(None, 1)[0]
        parsed[directive.lower()] = value.lower()
    return parsed


# TODO: flesh out with more directives (X11Forwarding, MaxAuthTries,
# AllowUsers/AllowGroups presence, Protocol version, etc.)
CHECKS = [
    ("PermitRootLogin", "yes", Severity.HIGH,
     "Root login over SSH allows a single compromised credential full system access.",
     "Set 'PermitRootLogin no' or 'prohibit-password'."),
    ("PasswordAuthentication", "yes", Severity.MEDIUM,
     "Password auth is more brute-forceable than key-based auth.",
     "Set 'PasswordAuthentication no' and use SSH keys only."),
]


def check_ssh_config(path: str | None = None) -> list[dict]:
    """
    Read + parse sshd_config and evaluate it against CHECKS.

    Returns a list of finding dicts with the common shape
    {"source", "title", "severity", "reason", "remediation"} so
    report_generator.py can render them uniformly. An unreadable
    config file yields an INFO finding explaining how to complete the
    check, never a crash.
    """
    config_path = path or "/etc/ssh/sshd_config"
    try:
        raw = read_sshd_config(config_path)
    except OSError as exc:
        return [{
            "source": "ssh",
            "title": "Could not read sshd_config",
            "severity": Severity.INFO,
            "reason": f"Could not read {config_path} ({exc}). SSH config is often root-readable only.",
            "remediation": "Re-run the audit with elevated privileges (sudo) to run the SSH hardening check.",
        }]

    parsed = parse_sshd_config(raw)
    findings: list[dict] = []
    for directive, risky_value, severity, reason, remediation in CHECKS:
        if parsed.get(directive.lower()) != risky_value.lower():
            continue
        findings.append({
            "source": "ssh",
            "title": f"sshd_config: {directive} {parsed[directive.lower()]}",
            "severity": severity,
            "reason": reason,
            "remediation": remediation,
        })
    return findings