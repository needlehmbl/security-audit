# Home Network Security Audit Tool

Local network and host security scanner: discovers active hosts on your
LAN, scans for open ports and identifies risky services, checks common
misconfigurations (SSH hardening, firewall status), and generates a
readable report with severity-ranked findings.

Built as a practical tool for auditing your own network/workstation —
grounded in real sysadmin work rather than a generic tutorial dataset.

## Why this exists

Security tooling is a differentiator in most portfolios, which skew
heavily toward web/AI projects. This demonstrates network fundamentals
(ports, services, protocols), config auditing, and — just as
importantly — how to turn raw scan output into a report a non-expert
could act on, which is the actual job of a security tool.

**Only run this against hosts/networks you own or have explicit
permission to scan.** Scanning networks you don't control, even
passively, can violate terms of service or local law.

## Architecture

```
host discovery (scan/host_discovery.py)
        │
        ▼
port scan per host (scan/port_scanner.py)
        │
        ▼
risk classification (checks/risk_rules.py)   ─── shared rule table
        │
        ▼
config checks (checks/ssh_check.py, checks/firewall_check.py)  [local host only]
        │
        ▼
report/report_generator.py  →  data/reports/audit_<timestamp>.md
```

| Stage        | Module                      | Responsibility                              |
|--------------|-----------------------------|-----------------------------------------------|
| Discover     | `scan/host_discovery.py`    | Find live hosts on the local subnet           |
| Port scan    | `scan/port_scanner.py`      | Scan each host for open TCP ports + banners   |
| Risk rules   | `checks/risk_rules.py`      | Classify ports/services by risk level         |
| SSH check    | `checks/ssh_check.py`       | Parse sshd_config for weak settings           |
| Firewall     | `checks/firewall_check.py`  | Parse ufw/iptables status                     |
| Report       | `report/report_generator.py`| Render findings into a Markdown report        |
| Orchestrate  | `scripts/run_audit.py`      | CLI entry point wiring all stages together    |

## Setup

Requires Python 3.10+ and `nmap` installed on the system (used for host
discovery and service/version detection — much more reliable than rolling
raw sockets by hand).

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Arch Linux
sudo pacman -S nmap
```

Some checks (SSH config, firewall status) need to read system files or
run commands that may require elevated permissions — see each module's
docstring for specifics.

## Usage

```bash
# Full audit: discover hosts on your subnet, scan each, check local config
sudo python scripts/run_audit.py --subnet 192.168.1.0/24

# Scan a single host only
python scripts/run_audit.py --host 192.168.1.1

# Local-machine config checks only (no network scan)
python scripts/run_audit.py --local-only
```

Reports are written to `data/reports/audit_<timestamp>.md` — Markdown so
they're readable in a terminal, on GitHub, or converted to HTML/PDF later.

## Testing

Pure-logic modules are tested against realistic sample input, so they
can be verified with no live network or system privileges:

```bash
source venv/bin/activate
pip install pytest
python -m pytest tests/ -v
```

## Risk classification

`checks/risk_rules.py` is the single source of truth for what counts as
risky — e.g. Telnet (port 23) is always flagged critical, FTP (21) is
flagged high, an open port with an unrecognized service is flagged for
manual review rather than ignored. This table-driven design means adding
a new rule is a one-line change, and it's the module worth highlighting
in a writeup since it's where the tool's actual judgment lives.

## What makes this demo-worthy, not just a wrapper around nmap

- **Judgment layer, not just raw scan output** — the tool doesn't just
  say "port 21 is open," it explains *why that matters* and how
  confident it is (known-risky service vs. unrecognized/needs review).
- **Config auditing, not just network scanning** — SSH and firewall
  checks show you understand host-hardening, not just network recon.
- **Actionable reports** — each finding includes a one-line remediation
  suggestion, which is the difference between a scanner and an audit tool.

## Status

| Module | State |
|--------|-------|
| `checks/risk_rules.py` | Fully implemented and tested — the rule table is the core judgment logic |
| `checks/firewall_check.py` | `parse_ufw_status` implemented and tested; shelling out to `ufw`/`iptables` pending |
| `checks/ssh_check.py` | Pending — parsing + checks documented in the module docstring |
| `scan/host_discovery.py` | Pending — nmap `-sn` ping-scan wrapper |
| `scan/port_scanner.py` | Pending — nmap `-sV` version-detection scan |
| `report/report_generator.py` | `write_report` done; finding normalization + Markdown rendering pending |
| `scripts/run_audit.py` | CLI args done; stage wiring pending |

The implemented modules are pure logic with no live network/system
dependency, so they're fully covered by `tests/`. The remaining modules
define their interfaces and implementation plan in their docstrings.

## Roadmap ideas (post-scaffold)

- HTML report export with severity color-coding
- Scheduled runs (systemd timer, matching your existing pipeline pattern)
  with diffing against the previous report to highlight *new* findings
- CVE lookup for detected service versions (via a local CVE database dump,
  keeping with the no-paid-API theme)
- Expand config checks to nginx/Apache/Docker daemon exposure