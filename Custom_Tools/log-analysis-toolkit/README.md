#  Log Analysis Toolkit

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Category](https://img.shields.io/badge/Category-Blue%20Team%20%2F%20SOC-1f3864)

> مجموعة أدوات بنيتها بنفسي من الصفر لحل مشاكل تحليل شائعة في شغل الـ SOC — مش لابات محلولة من منصة، دي كود مكتوب، مُختبر، ومُصلح يدوياً.

---

## 🔍 Tools Overview

| Tool | What It Does | Key Concepts Demonstrated | Stack | Run It |
|---|---|---|---|---|
| **Brute-Force Detector** | Parses raw authentication logs, filters failed login attempts, and flags any source IP that exceeds a configurable threshold. | Data pipeline design (parse → clean → count → flag), defensive parsing of malformed input, function decomposition | Python (stdlib) | `python brute_force_detector.py` |
| **CLI SOC Investigator** | Command-line tool that scans a log file with regex, detects unauthorized (401) access attempts per IP, and writes a formatted alert report to disk. | Regex-based log parsing, CLI design with `argparse`, automated report generation, layered exception handling | Python (`argparse`, `re`) | `python cli_soc_investigator.py -f access.log -t 3 -o report.txt` |
| **DNS PCAP Parser** | Reads a `.pcapng` capture and extracts the source IP and queried domain from every DNS request (IPv4 and IPv6). | Packet-level protocol dissection, network forensics, graceful handling of corrupted/non-DNS packets | Python (`scapy`) | `python dns_pcap_parser.py` |

---

## ⚙️ Requirements

```bash
pip install scapy
```

The other two tools use only the Python standard library — no extra dependencies needed.

---

## 🧪 Testing Notes

Every script here was run end-to-end against sample data before being pushed, not just reviewed by eye:

- **Brute-Force Detector** — verified against a log set that includes a deliberately corrupted line; confirmed it flags high-attempt IPs correctly without crashing.
- **CLI SOC Investigator** — verified argument parsing and report generation via the CLI flags.
- **DNS PCAP Parser** — verified against a synthetic `.pcapng` capture containing real DNS query packets; confirmed correct IP/domain extraction.

---

## 📂 Folder Structure

```
log-analysis-toolkit/
├── brute_force_detector.py
├── cli_soc_investigator.py
├── dns_pcap_parser.py
└── README.md
```
