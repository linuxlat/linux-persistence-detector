# Linux Persistence Detector

Lightweight Linux incident-response tool designed to detect common persistence
mechanisms used after system compromise.

![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)

A simple **Bash script** to help system administrators and security enthusiasts detect persistence mechanisms, suspicious processes, and possible compromises on Linux systems.

> Note: This script **does not remove threats**, it only detects potential indicators of compromise.


Project by Linux Audit Team  
https://linux.lat

# Linux Persistence Detector v5.1

**Linux Persistence Detector** is a lightweight Bash-based security audit tool designed to detect **persistence mechanisms, stealth techniques, and attacker artifacts** on Linux systems.

It helps system administrators, blue teams, and incident responders quickly identify whether a Linux machine may have been modified to maintain unauthorized access.

Project site: https://linux.lat

---

# Overview

Attackers who compromise Linux systems often install **persistence mechanisms** so they can regain access after reboot or after being removed. These techniques are frequently subtle and distributed across many system components.

Linux Persistence Detector scans the system for **known persistence vectors, suspicious configurations, and forensic indicators** that commonly appear after compromise.

The tool is designed to be:

* **Fast** (pure Bash, minimal dependencies)
* **Readable** (easy to audit the code)
* **Portable** (works across major Linux distributions)
* **Blue-team friendly**

---

# Features

### Persistence detection

Detects common persistence mechanisms used by attackers:

* Cron backdoors (user and system)
* Systemd services and timers
* Init.d scripts
* rc.local modifications
* User profile backdoors
* SSH authorized_keys abuse
* SUID backdoors
* Hidden binaries
* Suspicious PATH manipulation
* LD_PRELOAD injection
* Modified shell configuration files

---

### Bash history removal detection

Detects potential **log tampering attempts**, including:

* Cleared or truncated `.bash_history`
* Suspiciously small history files
* History timestamps disabled
* Recent shell sessions without history updates

This helps identify attempts to **hide attacker commands** after system access.

---

### Rootkit and stealth indicators

Searches for indicators such as:

* Suspicious binaries in `/tmp`, `/dev/shm`, `/var/tmp`
* Hidden files and directories
* Suspicious network utilities
* Unexpected SUID files
* Potentially malicious startup scripts

---

### Forensic logging

All results are written to:

```
/tmp/linux-persistence-audit.log
```

This allows investigators to keep a record of findings for later analysis.

---

# MITRE ATT&CK Mapping

The detector focuses primarily on **Persistence techniques (TA0003)** from the MITRE ATT&CK framework.

## Tactic: TA0003 — Persistence

Examples of mapped techniques:

| Technique | Description                           |
| --------- | ------------------------------------- |
| T1053.003 | Scheduled Task / Cron                 |
| T1543.002 | Systemd Service                       |
| T1546.004 | Unix Shell Configuration Modification |
| T1548.001 | Setuid / Setgid Abuse                 |
| T1037     | Boot or Logon Initialization Scripts  |
| T1098     | Account Manipulation (SSH keys)       |

These mappings help security teams correlate findings with **standardized threat models**.

---

# Installation

Clone the repository:

```bash
git clone https://github.com/linuxlat/linux-persistence-audit.git
cd linux-persistence-audit
```

Make the script executable:

```bash
chmod +x persistence-detector.sh
```

Run it:

```bash
sudo ./persistence-detector.sh
```

Root privileges are recommended to allow full system inspection.

---

# Example Output

Example detection results:

```
[+] Suspicious cron job detected
[+] Unauthorized systemd service
[+] Potential SUID backdoor
[+] Bash history file cleared recently
```

Each finding is also saved in the log file.

---

# Tested Platforms

The tool has been tested on modern Linux distributions including:

* Ubuntu 24.04 LTS
* Ubuntu 25.04
* Debian 12
* Debian 13
* AlmaLinux 9
* Rocky Linux 9
* Kali Linux
* Linux Mint

Because the tool uses **standard Unix utilities**, it should work on most Linux systems.

---

# Comparison With Other Tools

## vs PANIX

PANIX is an **attack simulation framework** used to emulate persistence techniques.

| Feature               | Linux Persistence Detector | PANIX             |
| --------------------- | -------------------------- | ----------------- |
| Purpose               | Detection                  | Attack simulation |
| Blue Team Use         | Yes                        | Limited           |
| Red Team Use          | Limited                    | Yes               |
| Persistence discovery | Yes                        | No                |

Linux Persistence Detector is intended to **find real persistence**, not simulate it.

---

## vs OSQuery / Fleet

OSQuery is a powerful **query-based endpoint monitoring system**.

| Feature              | Linux Persistence Detector | OSQuery                |
| -------------------- | -------------------------- | ---------------------- |
| Setup complexity     | Very low                   | Medium                 |
| Dependencies         | None                       | Requires agents        |
| Detection style      | Heuristic scanning         | Query-based monitoring |
| Real-time monitoring | No                         | Yes                    |

Linux Persistence Detector is best suited for **quick forensic audits**, while OSQuery excels in **continuous monitoring**.

---

## vs Wazuh / Elastic Detection Rules

Wazuh and Elastic provide enterprise **SIEM and EDR capabilities**.

| Feature                 | Linux Persistence Detector    | Wazuh / Elastic          |
| ----------------------- | ----------------------------- | ------------------------ |
| Installation            | Single script                 | Full platform            |
| Infrastructure required | None                          | Servers + agents         |
| Detection scope         | Persistence artifacts         | Full security monitoring |
| Target users            | Sysadmins / incident response | SOC teams                |

Linux Persistence Detector complements these platforms by providing **rapid standalone forensic inspection**.

---

# When To Use This Tool

Typical scenarios:

* Suspected Linux server compromise
* Security incident investigation
* Malware persistence analysis
* Blue team system audits
* Post-incident validation after cleanup

---

# Limitations

* Not a real-time monitoring solution
* Does not replace EDR or SIEM platforms
* Relies on known persistence patterns

However, it remains extremely useful for **quick security assessments**.

---

# License

This project is released under the **GNU GPL v3** license.

---

# Author

Linux Audit Team
https://linux.lat

---

# Contributing

Contributions are welcome.

Examples:

* New persistence detection modules
* Support for additional Linux distributions
* MITRE mapping improvements
* False positive reduction

Submit pull requests or open issues in the repository.

---

# Security Disclaimer

This tool is intended **for defensive security and incident response purposes only**.
Always ensure you have authorization before auditing systems.

---
