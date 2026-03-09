Usage Guide

Run the script as root:
sudo ./linux-persistence-detector.sh
The script performs multiple checks including:

cron jobs
systemd services
SSH keys
SUID binaries
suspicious processes

Results are saved in:
/tmp/linux-persistence-audit.log
