"""
Stage 2: Scan a single host for open TCP ports and grab service
banners where nmap can identify them.

Uses nmap's `-sV` version detection via the `python-nmap` wrapper.
Version detection is slower than a plain connect scan but gives much
more useful banners for the report — worth the tradeoff for a
home-network-sized audit.

If the `nmap` binary is missing, a clear NmapNotFound error is raised
(reused from host_discovery.py) so the CLI can report it gracefully.
"""

import shutil

from scan.host_discovery import NmapNotFound


def scan_host(host: str, port_range: str = "1-1024") -> list[dict]:
    """
    Returns a list of dicts: {"host", "port", "service", "banner"}
    for each open port found on `host`.
    """
    if shutil.which("nmap") is None:
        raise NmapNotFound(
            "nmap is not installed. Install it (e.g. 'sudo pacman -S nmap') "
            "to run network scans."
        )

    import nmap

    scanner = nmap.PortScanner()
    scanner.scan(host, port_range, arguments="-sV -T4")

    if host not in scanner.all_hosts():
        return []

    results: list[dict] = []
    for proto in scanner[host].all_protocols():
        for port in scanner[host][proto].keys():
            info = scanner[host][proto][port]
            if info["state"] == "open":
                product = info.get("product", "")
                version = info.get("version", "")
                banner = " ".join(part for part in (product, version) if part)
                results.append({
                    "host": host,
                    "port": port,
                    "service": info.get("name", "unknown"),
                    "banner": banner,
                })
    return results