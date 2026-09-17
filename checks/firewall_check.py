"""
Check the local host's firewall status.

The `ufw status verbose` text parser has no external dependencies
(it's pure string parsing) so it's fully implemented and tested here.
Actually invoking `ufw`/`iptables` requires shelling out with elevated
privileges, so that part is left as a TODO — the parser can be
developed and tested completely independently of running on a real
system with ufw installed.

TODO(implementation):
    - get_ufw_status() -> str: run `sudo ufw status verbose`
      via subprocess, return stdout. Handle the case where ufw isn't
      installed (FileNotFoundError) or the command needs sudo the
      caller doesn't have (non-zero exit) — return a clear "could not
      determine firewall status" result rather than crashing.
    - check_firewall() -> dict: the public entry point —
        1. raw = get_ufw_status()
        2. return parse_ufw_status(raw)
      If ufw isn't available, consider falling back to checking
      `iptables -L` presence as a secondary signal.
"""

import subprocess


def get_ufw_status() -> str:
    raise NotImplementedError("get_ufw_status: run `sudo ufw status verbose` via subprocess")


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


def check_firewall() -> dict:
    raise NotImplementedError("check_firewall: get_ufw_status() then parse_ufw_status()")
