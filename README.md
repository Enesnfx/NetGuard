# NetGuard

A Windows desktop app that watches your home or small-office network and tells you, in plain language, which devices are on it and which ones look risky.

## What it does

- **Finds every device.** Ping sweep, ARP scan, WS-Discovery and SSDP, then MAC vendor lookup and hostname resolution.
- **Scores the risk of each device.** Open ports from Nmap feed a weighted score with written reasons: Telnet or SOCKS open, RDP exposed, unknown hardware vendor, and so on.
- **Spots hidden IP cameras.** Known camera vendors, camera and DVR ports, and a live RTSP `OPTIONS` probe to confirm an active stream.
- **Watches traffic for attacks.** A Scapy sniffer raises alerts for **ARP spoofing** (one IP claimed by several MACs) and **rogue DHCP servers** (DHCP offers from anything other than the gateway).
- **Checks outside IPs** against AbuseIPDB, with a local cache so each address is looked up only once.
- **Reports and schedules.** Windows toast alerts, scheduled rescans, a device whitelist, and CSV or PDF export.

## Run it

Requires Windows 10/11 and Python 3.10+.

```bat
run.bat
```

On first run NetGuard installs its Python packages, offers to install Npcap and Nmap, and asks for an AbuseIPDB API key (free at abuseipdb.com). The key is saved to a local `config.json`, which is git-ignored and never committed.

## Stack

Python, Scapy, Nmap, CustomTkinter, APScheduler, ReportLab, AbuseIPDB API.
