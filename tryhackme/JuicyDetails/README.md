# 🕵️‍♂️ BTLO Writeup: Juicy Details

![Platform](https://img.shields.io/badge/Platform-BTLO-blue?style=flat-square)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green?style=flat-square)
![Category](https://img.shields.io/badge/Category-Web%20Log%20Forensics-orange?style=flat-square)
![Author](https://img.shields.io/badge/Author-Ahmed%20Adel-purple?style=flat-square)

---

> [!IMPORTANT]
> **Scenario Overview:** Analysis of web server access logs (`access.log`) from an OWASP Juice Shop deployment following a security incident. The objective is to trace the complete cyber attack chain from initial recon to system compromise.

---

## 📌 Quick QA Summary Table

| # | Question / Task | Correct Answer | Key Evidence / Command |
|---|---|---|---|
| **1** | Attacker Tools Used | `nmap, hydra, sqlmap, curl, feroxbuster` | User-Agent parsing & request patterns |
| **2** | Vulnerable Login Endpoint | `/rest/user/login` | High-frequency `POST` requests |
| **3** | Vulnerable SQLi Endpoint | `/rest/products/search` | `UNION SELECT` in URI query |
| **4** | Vulnerable SQLi Parameter | `q` | Query string `?q=` |
| **5** | Exposed Directory Endpoint | `/ftp` | Direct HTTP GET requests to backup path |
| **6** | Scraped Section for Emails | `product reviews` | User feedback endpoint scraping |
| **7** | Brute-Force Outcome & Time | `Yay, 11/Apr/2021:09:16:31 +0000` | HTTP status code `200` after `401` sequence |
| **8** | Exfiltrated User Data | `email, password` | SQL payload selecting `email, password` |
| **9** | Target Backup Files | `coupons_2013.md.bak, www-data.bak` | FTP directory file downloads |
| **10**| FTP Service & Account | `ftp, anonymous` | Unauthenticated FTP GET requests |
| **11**| Shell Access Service & Account | `ssh, www-data` | SSH login using exfiltrated keys |

---

## 🔍 Detailed Attack Lifecycle

<details>
<summary><b>1️⃣ Phase 1: Reconnaissance & Tool Discovery</b> <i>(Click to expand)</i></summary>

### Methodology
Analyzed unique `User-Agent` strings from `access.log` using Linux text utilities to build the attacker's tool chronology.

```bash
awk -F'"' '{print $6}' access.log | sort | uniq -c | sort -nr
```

### Discovered Tools (In Order)
1. `nmap`: Service enumeration scan.
2. `hydra`: Password brute-force attack.
3. `sqlmap`: Automated SQL injection testing.
4. `curl`: Manual request manipulation & exfiltration.
5. `feroxbuster`: Directory & path discovery.

</details>

<details>
<summary><b>2️⃣ Phase 2: Web Exploitation (SQLi & File Leak)</b> <i>(Click to expand)</i></summary>

### SQL Injection Analysis
The search endpoint `/rest/products/search` was exploited via parameter `q` using a UNION-based payload:

```text
GET /rest/products/search?q=qwert%27))%20UNION%20SELECT%20id,%20email,%20password...
```

* **Target Data:** User table containing `email` and `password` hashes.

### Directory Traversal & Backup Harvesting
* Attacker navigated open directory `/ftp`.
* Downloaded sensitive server archives: `coupons_2013.md.bak` and `www-data.bak` via `ftp, anonymous`.

</details>

<details>
<summary><b>3️⃣ Phase 3: Brute-Force & Initial Access</b> <i>(Click to expand)</i></summary>

### Authentication Attack
High-density `POST` requests were targeted at `/rest/user/login`.

```bash
grep "/rest/user/login" access.log | grep " 200 "
```

* **Outcome:** Brute-force succeeded (`Yay`).
* **Timestamp:** `11/Apr/2021:09:16:31 +0000`.

### Remote Shell Execution
Using exfiltrated SSH keys/credentials from `www-data.bak`, the attacker logged in over **SSH** under the **`www-data`** service account.

</details>

---

## 🛡️ IoCs & ATT&CK Mapping

> [!NOTE]
> **Key Indicators of Compromise (IoCs):**
> * **Attacker IP:** `192.168.10.5`
> * **Exploited Endpoints:** `/rest/products/search`, `/rest/user/login`, `/ftp`
> * **Exfiltrated Files:** `coupons_2013.md.bak`, `www-data.bak`

| Tactic | Technique | Details |
|---|---|---|
| **Reconnaissance** | Active Scanning (`T1595`) | Nmap / Feroxbuster traffic |
| **Initial Access** | Exploit Public-Facing Application (`T1190`) | SQL Injection on `/rest/products/search` |
| **Credential Access** | Brute Force (`T1110`) | Hydra attack on `/rest/user/login` |
| **Lateral Movement** | Remote Services: SSH (`T1021.004`) | Interactive SSH session as `www-data` |

---
