# 🛡️ SOC Log Analysis & Threat Intelligence Engine

A lightweight, high-performance Security Operations Center (SOC) Log Parser and Threat Correlation Engine written in Python. It ingests multi-source logs (**Windows EVTX**, **Linux Syslog**, and **Network PCAP**), normalizes them into a Unified Schema, correlates cross-source events, maps detected threats to the **MITRE ATT&CK Framework**, and enriches suspicious Indicators of Compromise (IOCs) via **AbuseIPDB**.

---

## 📐 Architecture Overview
┌────────────────┐    ┌────────────────┐    ┌────────────────┐
│ Windows EVTX   │    │  Linux Syslog  │    │  Network PCAP  │
└───────┬────────┘    └───────┬────────┘    └───────┬────────┘
│                     │                     │
▼                     ▼                     ▼
┌────────────────────────────────────────────────────────────┐
│                  Parser & Normalization Module             │
└─────────────────────────────┬──────────────────────────────┘
│
▼
┌────────────────────────────────────────────────────────────┐
│                 Unified Data Schema (Pandas)               │
└─────────────────────────────┬──────────────────────────────┘
│
▼
┌────────────────────────────────────────────────────────────┐
│       Threat Correlation Engine & MITRE Mapping            │
└─────────────────────────────┬──────────────────────────────┘
│
▼
┌────────────────────────────────────────────────────────────┐
│           AbuseIPDB Threat Intelligence Enrichment         │
└─────────────────────────────┬──────────────────────────────┘
│
▼
┌────────────────────────────────────────────────────────────┐
│             Reporting & Output (CSV / JSON)                │
└────────────────────────────────────────────────────────────┘
---

## ✨ Key Features

- **Multi-Source Log Ingestion**: Parses Windows EVTX logs, Linux SSH authentication logs, and Network PCAP traffic.
- **Unified Event Schema**: Standardizes heterogeneous log fields into `EventID`, `Timestamp`, `User Name`, `Workstation`, and `IP`.
- **Cross-Source Threat Correlation**: Correlates network activity (e.g., Port Scans) with host actions (e.g., Brute Force attempts) to escalate risk dynamically.
- **MITRE ATT&CK Mapping**: Maps event triggers automatically to MITRE ATT&CK Technique IDs (e.g., T1110 - Brute Force, T1046 - Network Service Discovery).
- **Automated IOC Enrichment**: Integrates with AbuseIPDB API to query IP confidence scores and ISP reputation.
- **Extensible Configuration**: Supports custom detection thresholds and external MITRE mapping YAML files.

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.9+
- `pcap` reading dependencies (e.g., `libpcap` or Wireshark/Npcap installed on host)

### 2. Installation
```bash
git clone [https://github.com/your-username/soc-analyzer.git](https://github.com/your-username/soc-analyzer.git)
cd soc-analyzer

# Install dependencies
pip install -r requirements.txt