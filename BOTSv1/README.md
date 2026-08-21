# Splunk BOTSv1 Security Incident Investigation Write-up
## Web Application Compromise & Malware Execution Analysis

**Author:** Ahmed Adel  
**Role:** SOC Analyst / Blue Team Specialist  
**Target Event Dataset:** Splunk Boss of the SOC (BOTSv1)  
**Investigation Date:** August 2026  

---

## Executive Summary

During a threat hunting exercise on the **BOTSv1** dataset, an adversary successfully reconnoitered, exploited, and compromised a web server hosting a Joomla CMS installation (`192.168.250.70`). The attack sequence progressed from automated vulnerability scanning using Acunetix, through brute-force credential stuffing against the Joomla administrator interface, to remote code execution via a web application vulnerability. Subsequent post-exploitation activity involved uploading a malicious binary (`3791.exe`), executing it via `cmd.exe` under the `NT AUTHORITY\IUSR` context, and altering website content (Defacement).

### Key Findings & IOCs
* **Victim Server IP:** `192.168.250.70` (Hostname: `we1149srv.waynecorpinc.local`)
* **Attacker IP:** `40.80.148.42`
* **Vulnerability Scanner:** Acunetix Web Vulnerability Scanner (WVS)
* **Initial Access Vector:** Unauthenticated PHP File Upload / Malicious Extension Package Upload via Joomla
* **Executed Malicious Payload:** `C:\inetpub\wwwroot\joomla\3791.exe`
* **Original Utility Name:** `ab.exe` (Apache Benchmark Tool)
* **Execution Context:** `NT AUTHORITY\IUSR` via `C:\Windows\System32\cmd.exe`
* **Malicious File Hashes:**
  * **MD5:** `52EF8037A22F0EB0083AA29EAC706495` / `59A1D4FACD7B333F76C4142CD42D3ABA`
  * **SHA256:** `E1A080E61FB1BAF0DA629D3BAEE6F0F9D0E0337BF6CED9F4B3AB9B1C23D91BA`
  * **IMPHASH:** `5B13496CE269DF7709AAB6B1BBF99CD3`

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Details |
| :--- | :--- | :--- | :--- |
| **Reconnaissance** | T1595.002 | Active Scanning: Vulnerability Scanning | Automated Acunetix WVS scan against web application endpoints |
| **Credential Access** | T1110.001 | Brute Force: Password Guessing | 400+ HTTP POST requests targeting `/joomla/administrator/` |
| **Initial Access** | T1190 | Exploit Public-Facing Application | Uploading PHP webshell / malicious plugin package |
| **Execution** | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | `cmd.exe` spawned by `w3wp.exe` to execute `3791.exe` |
| **Persistence / Impact** | T1491.001 | Defacement: Web Defacement | Replacing landing image with `poisonivy-is-coming-for-you-a4257f888041725d.jpeg` |

---

## Phase 1: Environment Setup & Data Verification

To ensure full coverage of the investigation, the index inventory was inspected to confirm dataset integrity and event count.

![Index Overview](images/01_index_overview.png)

```spl
index=botsv1
| stats count by index, provider, server
```
* **Observation:** The `botsv1` index contained **955,807** total log events, encompassing network stream data (`stream:http`), firewall logs (`fgt_utm`), and endpoint telemetry (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`).

---

## Phase 2: Reconnaissance & Vulnerability Scanning

Analyzing HTTP traffic revealed widespread automated scanning activity directed at the internal web server `192.168.250.70`.

![Vulnerability Scanning Payloads](images/02_vulnerability_scanning.png)

```spl
index=botsv1 sourcetype="stream:http" dest_ip="192.168.250.70"
| stats count by site, dest_ip
```
* **Observation:** Signature strings such as `acunetix_wvs_security_test`, `${@print(md5(...))}`, and `nslookup` confirmed that the attacker was actively fingerprinting the server for Remote Code Execution (RCE) and Command Injection vulnerabilities.

Further analysis of HTTP POST requests isolated the specific endpoints targeted for file upload vulnerabilities:

![Exploit Endpoints](images/03_exploit_endpoints.png)

```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST
| stats count by uri
| sort - count
```
* **Targeted Endpoints:**
  * `/libs/open-flash-chart/php-ofc-library/ofc_upload_image.php`
  * `/wp-content/plugins/wp-slimstat-ex/lib/ofc/php-ofc-library/ofc_upload_image.php`
  * `/joomla/administrator/index.php`

---

## Phase 3: Credential Access & Web Shell Upload

The adversary conducted brute-force login attempts against the Joomla administrative portal.

### Username Enumeration
![Brute Force Usernames](images/04_brute_force_usernames.png)

```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" uri="*administrator*" http_method=POST
| rex field=form_data "username=(?<username_tried>[^&]+)"
| stats count by username_tried
```
* **Result:** **413** POST requests targeted the `admin` account specifically.

### Password Dictionary Attack
![Brute Force Passwords](images/05_brute_force_passwords.png)

```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" uri="*administrator*" http_method=POST
| rex field=form_data "passwd=(?<Password_tried>[^&]+)"
| stats count by Password_tried
```
* **Result:** A sequential dictionary attack tested common passphrases (`000000`, `1111`, `123456`, `232323`, etc.).

### Malicious Package Upload
Following authentication/exploitation, a malicious payload was transferred via HTTP POST containing URL-encoded PHP code (`install_package`).

![Webshell Upload](images/06_webshell_upload.png)

```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST *filename*
| table _time, form_data
```
* **Observation:** The payload unpacked a webshell into the web application directory, granting the attacker initial arbitrary command execution privileges.

---

## Phase 4: Endpoint Investigation & Malware Execution

Telemetry from Sysmon (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`) was analyzed to trace process creation and binary execution on `we1149srv`.

### Process Creation (Event ID 1)
![Process Execution Sysmon](images/10_process_execution_sysmon.png)

```spl
index=botsv1 "3791.exe" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| table _time, _raw
```
* **Execution Summary:**
  * **Executable:** `C:\inetpub\wwwroot\joomla\3791.exe`
  * **Command Line:** `C:\Windows\system32\cmd.exe` executing `3791.exe`
  * **User Account:** `NT AUTHORITY\IUSR`
  * **Parent Process:** `w3wp.exe` (IIS Worker Process)
  * **Working Directory:** `C:\inetpub\wwwroot\joomla\`

### Hash Extraction & Artifact Identification
![MD5 Hash Extraction](images/07_md5_hash_extraction.png)

```spl
index=botsv1 "3791" "MD5"
| rex field=_raw "MD5=(?<md5_hash>[A-Fa-f0-9]{32})"
| table _time, md5_hash
```

![Sysmon Image Load](images/08_sysmon_image_load.png)

* **Loaded Modules (Sysmon Event ID 7):** The process initialized `winhttp.dll`, `wininet.dll`, `iertutil.dll`, and `gdi32.dll`, indicating network capability and potential C2 beaconing or HTTP flooding capabilities.

### HTTP Traffic & Directory Browsing
![HTTP Stream Analysis](images/09_http_stream_analysis.png)

```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"
| stats count by uri, dest_ip
```
* **Observation:** The web server responded to directory listing queries across `/joomla/administrator`, `/joomla/bin`, and media folders as the attacker staged final defacement assets.

---

## Phase 5: Incident Containment & Remediation Recommendations

1. **Host Isolation:** Immediately disconnect `192.168.250.70` (`we1149srv`) from the network to prevent lateral movement.
2. **Webshell Removal & File Cleanup:** Delete `3791.exe` from `C:\inetpub\wwwroot\joomla\` and remove unauthorized PHP scripts/extensions installed in Joomla directories.
3. **Credential Reset:** Enforce password resets across all web administrative accounts (`admin`) and service accounts (`NT AUTHORITY\IUSR`).
4. **Vulnerability Patching:** Upgrade Joomla CMS and all third-party extensions (especially Open Flash Chart / PHP OFC components) to current secure versions.
5. **SIEM / EDR Alerting Rule:** Deploy Splunk detection rules monitoring process creation where `w3wp.exe` spawns `cmd.exe` or `powershell.exe`.

---
*Created as part of SOC Analyst Portfolio Projects.*
