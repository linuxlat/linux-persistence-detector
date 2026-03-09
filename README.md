# Linux Persistence Detector

Lightweight Linux incident-response tool designed to detect common persistence
mechanisms used after system compromise.

Project by Linux Audit Team  
https://linux.lat

## Features

The tool performs security checks for:

- cron persistence
- systemd service persistence
- SSH authorized_keys backdoors
- PATH hijacking risks
- SUID privilege escalation binaries
- possible reverse shells
- rootkit indicators
- recently modified system binaries
- hidden processes

Designed for:

- incident response
- Linux server auditing
- security diagnostics
- forensic triage

Tested on:

- Debian
- Ubuntu

## Usage

git clone https://github.com/linuxlat/linux-persistence-detector.git

cd linux-persistence-detector

chmod +x linux-persistence-detector.sh

```bash
sudo ./linux-persistence-detector.sh
