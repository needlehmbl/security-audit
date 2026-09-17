"""
Stage 1: Discover live hosts on a local subnet.

Uses `nmap`'s ping scan (`-sn`) via the `python-nmap` wrapper rather
than rolling raw ICMP/ARP by hand — nmap already handles the
platform-specific details (ARP on local subnets, ICMP otherwise)
reliably and it's the industry-standard tool to know for this kind
of work anyway.

TODO(implementation):
    - discover_hosts(subnet: str) -> list[str]:
        import nmap
        scanner = nmap.PortScanner()
        scanner.scan(hosts=subnet, arguments="-sn")
        return [h for h in scanner.all_hosts() if scanner[h].state() == "up"]
      Requires nmap installed on the system; python-nmap just wraps
      the CLI binary. Running host discovery may need sudo depending
      on the scan technique nmap chooses — document this in the
      README's usage section if it comes up during implementation.
"""


def discover_hosts(subnet: str) -> list[str]:
    """
    Returns a list of IP addresses found to be up on the given subnet,
    e.g. discover_hosts("192.168.1.0/24") -> ["192.168.1.1", "192.168.1.5", ...]
    """
    raise NotImplementedError("discover_hosts: wire up python-nmap ping scan (-sn)")
