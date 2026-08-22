# 🕵️‍♂️ TryHackMe Writeup: Detecting Web Attacks

![Platform](https://img.shields.io/badge/Platform-TryHackMe-red?style=flat-square)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green?style=flat-square)
![Category](https://img.shields.io/badge/Category-Web%20Log%20Forensics%20%26%20WAF-blue?style=flat-square)
![Author](https://img.shields.io/badge/Author-Ahmed%20Adel-purple?style=flat-square)

---

> [!IMPORTANT]
> **Scenario Overview:** Investigation of web server activity and HTTP access logs to detect client-side and server-side attacks, identify automated scanning tools, track authentication brute-force attempts, analyze SQL injection payloads, and construct Web Application Firewall (WAF) rule sets.

---

## 📌 Quick QA Summary Table

| # | Investigation Question | Correct Answer | Key Findings & Evidence |
|---|---|---|---|
| **1** | Attack class exploiting user behavior/device | `Client-Side` | Targets browsers/users directly |
| **2** | Most common client-side attack | `XSS` | Cross-Site Scripting payload execution |
| **3** | Attack class exploiting web servers | `Server-Side` | Targets backend code, database, & server OS |
| **4** | Server-side attack dumping databases | `SQLi` | SQL Injection exploiting dynamic query inputs |
| **5** | Attacker's User-Agent during directory fuzz | `FFUF v2.1.0` | Automated path discovery header |
| **6** | Targeted page for authentication brute-force | `/login.php` | High-frequency credential guessing endpoint |
| **7** | Complete, decoded SQLi payload used | `%' OR '1'='1` | Authentication bypass / OR-1=1 boolean logic |
| **8** | Password identified in brute-force attack | `astrongpassword123` | Valid credentials cracked via wordlist |
| **9** | Flag extracted from database via SQLi | `THM{dumped_the_db}` | Exfiltrated flag string |
| **10**| Component inspected/filtered by WAFs | `Web Requests` | Inbound HTTP/HTTPS traffic evaluation |
| **11**| Custom WAF rule to block User-Agent | `IF User-Agent CONTAINS "BotTHM" THEN block` | Rule logic filtering target user-agent string |

---

## 🛠️ Key Skills & Security Tools

### 🧰 Tools Utilized
* **FFUF (v2.1.0):** Directory and file fuzzing tool used for web application reconnaissance.
* **Web Application Firewall (WAF):** Inline inspect/filter system for HTTP/HTTPS web requests.
* **Linux Text Utilities (`grep`, `awk`, `cut`, `uniq`):** Access log manipulation and traffic analysis.
* **URL Decoders:** Decoding URL-encoded malicious query strings and SQL payloads.

### 🎯 Key Skills Demonstrated
* **Web Attack Classification:** Distinguishing between client-side (XSS) and server-side (SQLi) attack vectors.
* **User-Agent Fingerprinting:** Detecting automated scanners and tools from HTTP request headers.
* **Authentication Log Analysis:** Identifying brute-force patterns targeting endpoints like `/login.php`.
* **Payload Analysis & Decoding:** Extracting and decoding injected SQL logic (`%' OR '1'='1`).
* **WAF Rule Creation:** Writing custom signature-based detection rules for malicious User-Agents.

---

## 🔍 Detailed Attack Lifecycle

<details>
<summary><b>1️⃣ Phase 1: Attack Categorization & Fuzzing Detection</b> <i>(Click to expand)</i></summary>

### Classification
* **Client-Side Attacks:** Rely on user interactions, vulnerable browser contexts, or local devices (e.g., **XSS**).
* **Server-Side Attacks:** Target server-side application logic, backend databases, and server storage (e.g., **SQLi**).

### Automated Discovery Log Analysis
* Observed high-volume HTTP GET requests with custom signature header:
  ```http
  User-Agent: FFUF v2.1.0
  ```
* **Verdict:** Attacker utilized `FFUF` for directory enumeration.

</details>

<details>
<summary><b>2️⃣ Phase 2: Brute-Force & Authentication Bypass</b> <i>(Click to expand)</i></summary>

### Credential Brute-Force
* Attacker targeted `/login.php` using wordlists.
* **Cracked Credentials:** Password found was `astrongpassword123`.

### SQL Injection Payload Analysis
* Query targeted endpoint: `/changeusername.php`
* Encoded query extracted from logs: `%25%27%20OR%20%271%27%3D%271`
* **Decoded Payload:** `%' OR '1'='1`
* **Impact:** Database dumping resulting in flag retrieval: `THM{dumped_the_db}`.

</details>

<details>
<summary><b>3️⃣ Phase 3: Defense & Mitigation (WAF Logic)</b> <i>(Click to expand)</i></summary>

* WAFs inspect and filter **Web Requests** before reaching the web server.
* **Custom Detection Rule Definition:**
  ```text
  IF User-Agent CONTAINS "BotTHM" THEN block
  ```

</details>

---

## 🛡️ ATT&CK Mapping & IoCs

> [!NOTE]
> **Key Indicators of Compromise (IoCs):**
> * **User-Agent Signatures:** `FFUF v2.1.0`, `BotTHM`
> * **Exploited Form/Endpoints:** `/login.php`, `/changeusername.php`
> * **Detected Payload:** `%' OR '1'='1`

| Tactic | Technique ID & Name | Context / Evidence |
|---|---|---|
| **Reconnaissance** | Active Scanning (`T1595.002`) | FFUF directory discovery (`FFUF v2.1.0`) |
| **Credential Access** | Brute Force (`T1110.001`) | High-frequency password guessing on `/login.php` |
| **Initial Access** | Exploit Public-Facing App (`T1190`) | SQLi exploitation on `/changeusername.php` |

---
