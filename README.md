# Linux Persistence Detector

Lightweight Linux incident-response tool designed to detect common persistence
mechanisms used after system compromise.

Project by Linux Audit Team  
https://linux.lat

# Linux Persistence Detector v5.1

**Linux Persistence Detector** is a Bash-based forensic and security auditing tool that scans Linux systems for **persistence mechanisms, attacker artifacts, and stealth techniques** commonly used after system compromise.

The tool focuses on detecting **post-exploitation persistence techniques** described in modern threat research and frameworks.

Project: https://linux.lat

---

# General Script Summary (v5.1)

Version **5.1** provides a comprehensive detection framework designed for **post-compromise auditing of Linux systems**.

The script performs a wide range of inspections targeting persistence vectors used by attackers, malware, and red-team tools. It analyzes system configuration, startup mechanisms, privilege escalation paths, and shell activity artifacts.

Key characteristics of the tool include:

* Broad detection coverage across multiple persistence techniques
* Low-noise output using contextual filtering
* Structured result output for analysis and automation
* Compatibility with modern Linux distributions
* Simple deployment as a single Bash script

The tool is intended for:

* Incident response
* Threat hunting
* Security auditing
* Post-compromise investigation
* Blue-team defensive analysis

---

# Key Strengths

Linux Persistence Detector v5.1 has reached a mature level for an open-source defensive auditing tool.

## Strong coverage aligned with modern threat research (2025–2026)

The detector covers a wide set of persistence mechanisms that align with techniques described in modern Linux threat research, including:

* Elastic Security research series such as **"Hooked on Linux"** and **"Grand Finale"**
* Persistence techniques emulated by the PANIX adversary emulation framework
* Known Linux post-exploitation techniques observed in real intrusions

Coverage includes persistence vectors across:

* cron jobs
* systemd services and timers
* user-level systemd services
* shell initialization files
* PAM modules
* kernel modules
* SSH key manipulation
* dynamic linker configuration
* boot loader modifications
* scheduled execution mechanisms

---

## Controlled noise and practical detections

The tool prioritizes **high-value signals** while minimizing noise.

Key filtering mechanisms include:

* `--since-days` filtering for recent activity
* suspicious pattern matching
* threshold-based detection (for example: SSH accounts with more than 5 authorized keys)
* file size thresholds
* selective grep pattern scanning
* filtering of common benign entries

This approach helps reduce false positives while preserving meaningful alerts.

---

## Structured output

Findings are internally stored in an **ALERTS array**, allowing the script to produce structured output formats suitable for analysis.

Output formats include:

### JSON output

* Alerts are safely escaped
* Empty arrays are handled correctly
* Structured fields allow integration with log analysis tools

Example structure:

```json
{
  "alerts": [
    "Suspicious systemd service detected",
    "User bash history cleared recently"
  ]
}
```

### CSV output

A lightweight CSV export is also available for simple reporting and spreadsheet analysis.

Metadata such as timestamps and system information can be included.

---

## Clean logging architecture

The script implements a clean logging mechanism using:

* dedicated logging functions
* `tee` for real-time terminal output and log recording
* centralized logging file

This ensures both **interactive usability and forensic record keeping**.

---

## Reasonable portability

Linux Persistence Detector is designed to run on a wide range of Linux systems with minimal dependencies.

The script primarily relies on:

* Bash
* coreutils
* grep
* awk
* standard Unix utilities

It works well on most mainstream distributions.

However, some caveats may apply on:

* Alpine Linux
* BSD-based environments
* minimal containers

These environments may require minor adjustments.

---

# High-Value Security Checks

Version 5.1 introduces several **high-value persistence detection modules** that significantly improve coverage.

### Systemd user services

Detects persistence installed in:

```
~/.config/systemd/user/
```

This technique is frequently used by attackers because it runs **without root privileges**.

---

### Suspicious udev rules

Scans for malicious or unusual rules in:

```
/etc/udev/rules.d/
```

Attackers sometimes use udev triggers to execute payloads when devices are detected.

---

### GRUB and boot persistence

Detects suspicious or recently modified bootloader components such as:

* GRUB configuration changes
* suspicious boot parameters
* recently modified boot scripts

Boot persistence is rare but extremely high impact.

---

### PAM module abuse

Detects suspicious `pam_exec` entries or unusual PAM modules in authentication stacks.

Attackers can abuse PAM to execute commands during login events.

---

### Kernel module anomalies

Inspects loaded kernel modules and configuration paths to identify unusual modules that could indicate:

* rootkits
* stealth persistence
* privilege escalation helpers

---

### Scheduled execution mechanisms

Detects hidden or suspicious scheduled execution paths:

* cron jobs
* at jobs
* systemd timers

These mechanisms are frequently used for **periodic persistence execution**.

---

### Dynamic linker manipulation

Scans locations such as:

```
/etc/ld.so.conf.d/
```

Attackers sometimes add malicious libraries that are automatically loaded by the dynamic linker.

---

### Bash history removal detection

The script also detects possible attempts to hide attacker activity by analyzing:

* cleared `.bash_history` files
* suspiciously small history files
* recent shell sessions without corresponding history updates
* history timestamp configuration

This can reveal attempts to **erase command traces after compromise**.

---

# MITRE ATT&CK Mapping

The detector primarily focuses on techniques related to **Persistence (TA0003)**.

Examples of mapped techniques include:

| Technique | Description                           |
| --------- | ------------------------------------- |
| T1053.003 | Cron scheduled tasks                  |
| T1543.002 | Systemd service persistence           |
| T1546.004 | Unix shell configuration modification |
| T1548.001 | Setuid / Setgid abuse                 |
| T1037     | Boot or logon initialization scripts  |
| T1098     | Account manipulation (SSH keys)       |

These mappings help analysts correlate findings with standardized threat intelligence frameworks.

---

# Tested Platforms

Linux Persistence Detector v5.1 has been tested on:

* Ubuntu 24.04 LTS
* Ubuntu 25.04
* Debian 12
* Debian 13
* AlmaLinux 9
* Rocky Linux 9
* Kali Linux
* Linux Mint

Because the script relies on standard Unix tools, it should run on most Linux distributions.

---

# Comparison With Other Tools

## vs PANIX

PANIX is designed to **simulate persistence attacks** for red-team testing.

Linux Persistence Detector instead focuses on **detecting real persistence artifacts**.

---

## vs OSQuery / Fleet

OSQuery provides **continuous monitoring through structured queries**, while Linux Persistence Detector is designed for **quick forensic system audits** without installing agents.

---

## vs Wazuh / Elastic Detection Rules

Wazuh and Elastic operate as **full security monitoring platforms (SIEM/EDR)**.

Linux Persistence Detector complements them by providing:

* standalone incident-response scanning
* lightweight forensic inspection
* easy deployment without infrastructure

---

# Usage

Clone the repository:

```bash
git clone https://github.com/linuxlat/linux-persistence-detector.git
cd linux-persistence-detector/
```

Make the script executable:

```bash
chmod +x persistence-detector.sh
```

Run the scan:

```bash
sudo ./persistence-detector.sh
```

---

# License

GNU GPL v3

---

# Author

Linux Audit Team
https://linux.lat

---

# Security Disclaimer

This tool is intended **for defensive security research, auditing, and incident response**.
Always ensure you have authorization before scanning systems.
