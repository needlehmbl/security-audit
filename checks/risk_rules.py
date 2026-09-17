"""
Single source of truth for how open ports/services get classified by
risk level. Both the port scanner's report output and the report
generator import from here, so adding a new rule is a one-line change
that propagates everywhere — same pattern as schema_config.py in the
doc-pipeline project.

This module has no external dependencies, so it's fully implemented
and tested here.
"""

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PortRule:
    port: int
    service_name: str
    severity: Severity
    reason: str
    remediation: str


# Ordered roughly by how commonly these show up misconfigured on a
# home network / small server. Extend freely — this table is the
# whole point of the tool's "judgment layer."
PORT_RULES: dict[int, PortRule] = {
    21: PortRule(
        21, "FTP", Severity.HIGH,
        "FTP transmits credentials and data in plaintext.",
        "Disable FTP; use SFTP/SCP over SSH instead.",
    ),
    23: PortRule(
        23, "Telnet", Severity.CRITICAL,
        "Telnet transmits everything, including passwords, in plaintext.",
        "Disable Telnet entirely; use SSH.",
    ),
    25: PortRule(
        25, "SMTP", Severity.MEDIUM,
        "An exposed mail relay can be abused for spam/relay attacks if misconfigured.",
        "Ensure the mail server requires auth and isn't an open relay.",
    ),
    445: PortRule(
        445, "SMB", Severity.HIGH,
        "SMB has a history of critical remote-exploit vulnerabilities (e.g. EternalBlue).",
        "Restrict SMB to trusted hosts only; keep patched; disable if unused.",
    ),
    3389: PortRule(
        3389, "RDP", Severity.HIGH,
        "RDP exposed to the internet is a top target for brute-force and exploit attempts.",
        "Never expose RDP directly to the internet; use a VPN in front of it.",
    ),
}

# Ports considered generally fine to have open, so they don't clutter
# reports with noise — still listed at INFO level for completeness.
LOW_RISK_PORTS: dict[int, str] = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
}


def classify_port(port: int, banner: str | None = None) -> PortRule:
    """
    Return a PortRule for the given port. Known risky ports use the
    curated table above. Known low-risk ports get an INFO-level rule.
    Anything unrecognized is flagged at MEDIUM for manual review
    rather than silently ignored — an audit tool should never let an
    unknown open port pass without comment.
    """
    if port in PORT_RULES:
        return PORT_RULES[port]

    if port in LOW_RISK_PORTS:
        service = LOW_RISK_PORTS[port]
        return PortRule(
            port, service, Severity.INFO,
            f"{service} is commonly open and not inherently risky.",
            "No action needed; keep the service patched and access-controlled.",
        )

    banner_note = f" (banner: {banner})" if banner else ""
    return PortRule(
        port, "Unknown", Severity.MEDIUM,
        f"Open port with no recognized service in the rule table{banner_note}.",
        "Manually confirm what's listening on this port and whether it should be exposed.",
    )


def severity_rank(severity: Severity) -> int:
    """Higher number = more severe. Used for sorting report findings."""
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return order.index(severity)
