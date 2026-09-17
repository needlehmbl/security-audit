"""
Check sshd_config for common weak/insecure settings.

Parsing logic (parse_sshd_config) is pure string handling and could
be fully implemented without a live system, similar to
firewall_check.py's ufw parser — left as a TODO here mainly to keep
this scaffold's first pass focused, but it's a good next module to
implement and test the same way risk_rules.py and firewall_check.py's
parser were: write a few sample sshd_config strings as test fixtures,
no live system required.

TODO(implementation):
    - read_sshd_config(path="/etc/ssh/sshd_config") -> str: read the
      file; handle permission errors gracefully (sshd_config is often
      root-readable only — note this in the report if unreadable
      rather than crashing).
    - parse_sshd_config(raw_text: str) -> dict: extract key directives
      as a dict, e.g. {"PermitRootLogin": "yes", "PasswordAuthentication": "yes", ...}.
      Handle comments (#) and case-insensitive directive names.
    - CHECKS: a list of (directive, risky_value, severity, reason,
      remediation) tuples to evaluate against the parsed config, e.g.
        ("PermitRootLogin", "yes", Severity.HIGH,
         "Root login over SSH allows a single compromised credential
          to grant full system access.",
         "Set 'PermitRootLogin no' or 'prohibit-password'.")
        ("PasswordAuthentication", "yes", Severity.MEDIUM,
         "Password auth is more brute-forceable than key-based auth.",
         "Set 'PasswordAuthentication no' and use SSH keys only.")
    - check_ssh_config(path=None) -> list[dict]: read + parse + evaluate
      against CHECKS, return a list of finding dicts matching the same
      shape risk_rules.PortRule findings use, so report_generator.py
      can render both kinds of findings uniformly.
"""

from checks.risk_rules import Severity


def read_sshd_config(path: str = "/etc/ssh/sshd_config") -> str:
    raise NotImplementedError("read_sshd_config: read the file, handle permission errors")


def parse_sshd_config(raw_text: str) -> dict:
    raise NotImplementedError("parse_sshd_config: parse directive: value pairs, skip comments")


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
    raise NotImplementedError("check_ssh_config: read_sshd_config -> parse_sshd_config -> evaluate CHECKS")
