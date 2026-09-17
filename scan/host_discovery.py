"""
Stage 1: Discover live hosts on a local subnet.

Uses `nmap`'s ping scan (`-sn`) via the `python-nmap` wrapper rather
than rolling raw ICMP/ARP by hand — nmap already handles the
platform-specific details (ARP on local subnets, ICMP otherwise)
reliably and it's the industry-standard tool to know for this kind
of work anyway.

Requires nmap installed on the system; python-nmap just wraps the CLI
binary. If nmap is missing, a clear NmapNotFound error is raised so
the CLI can report it gracefully instead of crashing with a traceback.
"""

import shutil


class NmapNotFound(RuntimeError):
    """Raised when the `nmap` binary isn't installed on this system."""


def discover_hosts(subnet: str) -> list[str]:
    """
    Returns a list of IP addresses found to be up on the given subnet,
    e.g. discover_hosts("192.168.1.0/24") -> ["192.168.1.1", "192.168.1.5", ...]

    Running host discovery may need sudo depending on the scan technique
    nmap chooses for the subnet.
    """
    if shutil.which("nmap") is None:
        raise NmapNotFound(
            "nmap is not installed. Install it (e.g. 'sudo pacman -S nmap') "
            "to run network scans."
        )

    import nmap

    scanner = nmap.PortScanner()
    scanner.scan(hosts=subnet, arguments="-sn -T4")
    return [h for h in scanner.all_hosts() if scanner[h].state() == "up"]