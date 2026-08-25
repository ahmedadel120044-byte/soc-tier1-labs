# 🛡️ Cybersecurity & DFIR Labs Portfolio

![Labs](https://img.shields.io/badge/Labs-9%20Completed-1f3864)
![Focus](https://img.shields.io/badge/Focus-Blue%20Team%20%2F%20SOC-blue)
![Status](https://img.shields.io/badge/Status-Actively%20Updating-brightgreen)
![MITRE ATT&CK](https://img.shields.io/badge/Mapped%20To-MITRE%20ATT%26CK-red)

مجموعة تقارير وتحليلات عملية للأدوات والتحديات الأمنية على منصات متعددة، مع التوثيق الكامل للخطوات والـ Proof of Work.

---

## 📁 Repository Structure

```
soc-tier1-labs/
├── BOTSv1/                    # Splunk Boss of the SOC — threat hunting & DFIR
├── CyberDefenders/            # Network forensics & log analysis labs
├── tryhackme/                 # SIEM, Windows DFIR, and log analysis labs
├── Custom_Tools/               # Self-built Python tools (not platform labs)
│   └── log-analysis-toolkit/
└── README.md
```

---

## 📊 Completed Labs Index

| Lab Name | Category | Platform | Difficulty | Write-up Link | Key Skills / Tools |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **WireDive** | Network Forensics | CyberDefenders | Medium | [View Writeup](./CyberDefenders/WireDive) | Wireshark, TLS Decryption, SMB, DNS |
| **Hammered** | Log Analysis | CyberDefenders | Medium | [View Writeup](./CyberDefenders/Hammered) | Linux Auth Logs, SSH, Brute Force |
| **Hacked** | Log Analysis | CyberDefenders | Medium | [View Writeup](./CyberDefenders/Hacked) | FTK Imager, Ext4 Forensics, Deleted File Recovery, Linux Logs, Bash History |
| **Splunk: Exploring SPL** | SIEM & Queries | TryHackMe | Medium | [View Writeup](./tryhackme/Splunk:_Exploring_SPL) | Splunk Enterprise, SPL Queries, Log Correlation (join), GeoIP Enrichment (iplocation), Sysmon & Windows Logs, Anomaly Detection |
| **PacketMaze** | Network Forensics | CyberDefenders | Medium | [View Writeup](./CyberDefenders/PacketMaze) | Wireshark, TLS Decryption, DNS, FTP Analysis, EXIF Forensics |
| **Investigating Windows** | Windows DFIR | TryHackMe | Easy | [View Writeup](./tryhackme/investigating_windows) | Windows Forensics, PowerShell & Event Viewer, Sysmon Log Correlation, Persistence Detection, Timeline Analysis, IoC Extraction |
| **Splunk BOTSv1** | Threat Hunting & DFIR | Boss of the SOC | Hard | [View Writeup](./BOTSv1) | Splunk Enterprise, SPL Queries, Sysmon Analysis, Web Shell Detection, MITRE ATT&CK, Malware Execution |
| **Juicy Details** | Log Analysis | TryHackMe | Easy | [View Writeup](./tryhackme/JuicyDetails) | Web Log Forensics, SQLi Analysis, Brute-Force Investigation, Incident Response, Linux CLI (`awk`/`grep`) |
| **Detecting Web Attacks** | Log Analysis | TryHackMe | Easy | [View Writeup](./tryhackme/DetectingWebAttacks) | Web Attack Classification, User-Agent Fingerprinting, Authentication Log Analysis, Payload Analysis & Decoding, WAF Rule Creation |

---

## 🧰 Custom Tools & Scripts

بالإضافة للابات المحلولة من المنصات، الـ Repo فيه أدوات Python بنيتها من الصفر لحل مشاكل تحليل حقيقية:

| Project | Description | Link |
| :--- | :--- | :--- |
| **Log Analysis Toolkit** | Brute-force detection, CLI-based SOC log investigation, and DNS PCAP parsing — each built, tested, and debugged independently. | [View Toolkit](./Custom_Tools/log-analysis-toolkit) |

---

## 🎯 Skills Demonstrated Across This Portfolio

`Network Forensics` `Log Analysis` `SIEM (Splunk)` `Windows DFIR` `Threat Hunting` `MITRE ATT&CK Mapping` `Wireshark` `Python Scripting` `Incident Response`

---

## 📫 Connect

**Ahmed Adel** — Cybersecurity Student | Aspiring SOC Analyst
[LinkedIn](https://www.linkedin.com/in/ahmed-adel-cyber/)
