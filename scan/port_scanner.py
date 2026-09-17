"""
Stage 2: Scan a single host for open TCP ports and grab service
banners where nmap can identify them.

TODO(implementation):
    - scan_host(host: str, port_range: str = "1-1024") -> list[dict]:
        import nmap
        scanner = nmap.PortScanner()
        scanner.scan(host, port_range, arguments="-sV")  # -sV = version detection
        results = []
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                info = scanner[host][proto][port]
                if info["state"] == "open":
                    results.append({
                        "host": host,
                        "port": port,
                        "service": info.get("name", "unknown"),
                        "banner": info.get("product", "") + " " + info.get("version", ""),
                    })
        return results
      Note: -sV version detection is slower than a plain connect scan
      but gives much more useful banners for the report — worth the
      tradeoff for a home-network-sized audit.
    - Consider a plain-socket fallback (connect() to each port in a
      range) for environments without nmap installed, documented as
      a lower-fidelity mode.
"""


def scan_host(host: str, port_range: str = "1-1024") -> list[dict]:
    """
    Returns a list of dicts: {"host", "port", "service", "banner"}
    for each open port found on `host`.
    """
    raise NotImplementedError("scan_host: wire up python-nmap version-detection scan")
