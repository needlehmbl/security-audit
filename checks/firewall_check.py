"""
Check the local host's firewall status.

The `ufw status verbose` text parser (parse_ufw_status) is pure string
handling with no external dependencies, so it's fully implemented and
tested. Shelling out to `ufw`/`iptables` requires elevated privileges;
check_firewall() handles missing tools and permission problems by
returning a finding in the report instead of crashing.

On systems running under systemd, consider `firewalld` as a further
fallback — for now ufw (with an iptables-present signal) is the
default because it's the most common "set and forget" host firewall.
"""

import shutil
import subprocess

from checks.risk_rules import Severity


def get_ufw_status() -> str:
    """Run `sudo ufw status verbose` and return stdout.

    Raises RuntimeError (with stderr from ufw/sudo) if the command
    exits non-zero — e.g. sudo requires a password — or TimeoutExpired
    / OSError for other subprocess failures.
    """
    result = subprocess.run(
        ["sudo", "ufw", "status", "verbose"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"ufw status exited {result.returncode}")
    return result.stdout


def parse_ufw_status(raw_output: str) -> dict:
    """
    Parse the text output of `ufw status verbose` into a structured
    result: {"active": bool, "default_incoming": str, "default_outgoing": str,
    "rules": list[str]}.

    Example input:
        Status: active
        Logging: on (low)
        Default: deny (incoming), allow (outgoing), disabled (routed)
        New profiles: skip

        To                         Action      From
        --                         ------      ----
        22/tcp                     ALLOW IN    Anywhere
        80/tcp                     ALLOW IN    Anywhere
    """
    lines = [line.strip() for line in raw_output.splitlines() if line.strip()]

    active = any(
        line.lower().startswith("status:") and line.lower().split(":", 1)[1].strip() == "active"
        for line in lines
    )

    default_incoming = "unknown"
    default_outgoing = "unknown"
    for line in lines:
        if line.lower().startswith("default:"):
            # "Default: deny (incoming), allow (outgoing), disabled (routed)"
            parts = line.split(":", 1)[1].split(",")
            for part in parts:
                part = part.strip()
                if "(incoming)" in part:
                    default_incoming = part.split("(")[0].strip()
                elif "(outgoing)" in part:
                    default_outgoing = part.split("(")[0].strip()

    rules = []
    in_rules_section = False
    for line in lines:
        if line.startswith("--") and "----" in line:
            in_rules_section = True
            continue
        if in_rules_section:
            rules.append(line)

    return {
        "active": active,
        "default_incoming": default_incoming,
        "default_outgoing": default_outgoing,
        "rules": rules,
    }


def check_firewall() -> list[dict]:
    """
    Determine firewall status as a list of finding dicts in the common
    report shape {"source", "title", "severity", "reason", "remediation"}.

    Handles three environments gracefully: ufw installed and readable,
    ufw missing (falls back to an iptables-presence signal), and
    elevated permissions unavailable (reports "could not determine").
    """
    if shutil.which("ufw") is None:
        if shutil.which("iptables") is not None:
            return [{
                "source": "firewall",
                "title": "ufw not installed (iptables present)",
                "severity": Severity.INFO,
                "reason": "No ufw wrapper found, but iptables is available — the host may "
                          "be firewalled at the iptables/nftables level.",
                "remediation": "Confirm iptables/nftables rules are loaded, or install ufw for "
                               "a higher-level policy review.",
            }]
        return [{
            "source": "firewall",
            "title": "No firewall tool detected",
            "severity": Severity.HIGH,
            "reason": "Neither ufw nor iptables was found on the system — likely no host firewall.",
            "remediation": "Install and enable a firewall (e.g. ufw) and deny inbound by default.",
        }]

    try:
        parsed = parse_ufw_status(get_ufw_status())
    except (RuntimeError, subprocess.SubprocessError, OSError) as exc:
        return [{
            "source": "firewall",
            "title": "Could not determine firewall status",
            "severity": Severity.INFO,
            "reason": f"Reading ufw status failed: {exc}",
            "remediation": "Re-run the audit with elevated privileges (sudo) to check the firewall.",
        }]

    if parsed["active"]:
        return [{
            "source": "firewall",
            "title": "ufw firewall is active",
            "severity": Severity.INFO,
            "reason": f"ufw is active with default incoming policy "
                      f"'{parsed['default_incoming']}' and {len(parsed['rules'])} "
                      f"allow rule(s).",
            "remediation": "Review the allowed inbound ports against what actually needs "
                           "to be exposed to the network.",
        }]
    return [{
        "source": "firewall",
        "title": "ufw firewall is inactive",
        "severity": Severity.HIGH,
        "reason": "ufw reports 'inactive', so no host firewall is filtering inbound traffic.",
        "remediation": "Enable it with 'sudo ufw enable' and set default incoming to deny.",
    }]