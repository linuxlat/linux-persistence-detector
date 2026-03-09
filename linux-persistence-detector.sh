#!/usr/bin/env bash
#
# Linux Persistence Detector
# https://linux.lat
#
# Linux Audit Team
# GNU GPL v3
#

set -o pipefail
set -o nounset

VERSION="3.0"
LOGFILE="/tmp/linux-persistence-audit.log"

echo "" > "$LOGFILE"

declare -a findings
declare -a clean
FOUND_ISSUES=0

log() {
echo "[*] $1" | tee -a "$LOGFILE"
}

warn() {
echo "[!] $1" | tee -a "$LOGFILE"
findings+=("$1")
((FOUND_ISSUES++))
}

ok() {
clean+=("$1")
}

check_root() {
if [[ "$EUID" -ne 0 ]]; then
echo "Run as root"
exit 1
fi
}

#################################################
# CRON PERSISTENCE
#################################################

check_cron_persistence() {

log "Checking cron persistence..."

found=0

crontab -l 2>/dev/null | tee -a "$LOGFILE" || true

for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do

if [ -d "$dir" ]; then
ls -la "$dir" | tee -a "$LOGFILE"
fi

done

if [[ "$found" -eq 0 ]]; then
ok "No suspicious cron persistence detected"
fi

}

#################################################
# SYSTEMD PERSISTENCE
#################################################

check_systemd_persistence() {

log "Checking systemd persistence..."

systemctl list-unit-files --type=service --state=enabled | tee -a "$LOGFILE"

systemctl list-timers --all | tee -a "$LOGFILE"

ok "Systemd services inspected"

}

#################################################
# SSH BACKDOORS
#################################################

check_ssh_backdoors() {

log "Checking SSH authorized_keys..."

found=0

find /home /root -name authorized_keys 2>/dev/null | while read -r file; do

echo "File: $file" | tee -a "$LOGFILE"
cat "$file" | tee -a "$LOGFILE"
found=1

done

if [[ "$found" -eq 0 ]]; then
ok "No suspicious SSH authorized_keys detected"
fi

}

#################################################
# PATH HIJACKING
#################################################

check_path_hijacking() {

log "Checking PATH hijacking..."

found=0

IFS=':' read -ra paths <<< "$PATH"

for p in "${paths[@]}"; do

if [ -d "$p" ]; then

perm=$(stat -c "%A" "$p")
echo "$p ($perm)" | tee -a "$LOGFILE"

if [ -w "$p" ]; then
warn "Writable PATH directory: $p"
found=1
fi

fi

done

if [[ "$found" -eq 0 ]]; then
ok "No writable directories in PATH"
fi

}

#################################################
# SUID ABUSE
#################################################

check_suid_abuse() {

log "Searching SUID binaries..."

find / -xdev -perm -4000 -type f 2>/dev/null | tee -a "$LOGFILE"

ok "SUID binaries listed"

}

#################################################
# REVERSE SHELLS
#################################################

check_reverse_shells() {

log "Checking reverse shells..."

found=0

patterns=(
"bash -i"
"nc -e"
"ncat -e"
"perl -e"
"python -c"
"php -r"
"socat TCP"
)

ps aux | while read -r line; do

for p in "${patterns[@]}"; do

if echo "$line" | grep -q "$p"; then
warn "Possible reverse shell process detected"
echo "$line" | tee -a "$LOGFILE"
found=1
fi

done

done

ss -tpn | grep ESTAB | while read -r conn; do

if echo "$conn" | grep -E "bash|sh|nc|perl|python|php|socat"; then
warn "Suspicious network connection"
echo "$conn" | tee -a "$LOGFILE"
found=1
fi

done

if [[ "$found" -eq 0 ]]; then
ok "No reverse shell indicators detected"
fi

}

#################################################
# ROOTKIT INDICATORS
#################################################

check_rootkit_indicators() {

log "Checking rootkit indicators..."

found=0

indicators=(
"/usr/bin/.sshd"
"/dev/.lib"
"/dev/.udev"
"/lib/modules/.cache"
"/usr/lib/libproc.so"
)

for f in "${indicators[@]}"; do

if [ -e "$f" ]; then
warn "Possible rootkit artifact: $f"
found=1
fi

done

if [[ "$found" -eq 0 ]]; then
ok "No common rootkit artifacts detected"
fi

}

#################################################
# LD_PRELOAD ROOTKIT
#################################################

check_ld_preload() {

log "Checking LD_PRELOAD..."

if [ -f /etc/ld.so.preload ]; then
warn "LD_PRELOAD file present"
cat /etc/ld.so.preload | tee -a "$LOGFILE"
else
ok "No LD_PRELOAD persistence detected"
fi

}

#################################################
# CAPABILITIES ABUSE
#################################################

check_capabilities() {

log "Checking Linux capabilities..."

if command -v getcap >/dev/null 2>&1; then

getcap -r / 2>/dev/null | tee -a "$LOGFILE"

ok "Capabilities inspected"

else

ok "getcap not installed, skipping capability scan"

fi

}

#################################################
# MODIFIED BINARIES
#################################################

check_recent_binaries() {

log "Checking recently modified binaries..."

find /usr/bin /usr/sbin /bin /sbin -type f -mtime -3 2>/dev/null | tee -a "$LOGFILE"

ok "Binary modification scan completed"

}

#################################################
# HIDDEN PROCESSES
#################################################

check_hidden_processes() {

log "Checking hidden processes..."

found=0

for pid in /proc/[0-9]*; do

pidnum=$(basename "$pid")

if ! ps -p "$pidnum" > /dev/null 2>&1; then
warn "Process in /proc but not visible in ps: $pidnum"
found=1
fi

done

if [[ "$found" -eq 0 ]]; then
ok "No hidden processes detected"
fi

}

#################################################
# RC.LOCAL PERSISTENCE
#################################################

check_rc_local() {

log "Checking rc.local..."

if [ -f /etc/rc.local ]; then

cat /etc/rc.local | tee -a "$LOGFILE"
warn "rc.local present (review recommended)"

else

ok "No rc.local persistence"

fi

}

#################################################
# SUSPICIOUS USERS
#################################################

check_users() {

log "Checking UID 0 users..."

awk -F: '$3 == 0 {print}' /etc/passwd | tee -a "$LOGFILE"

ok "User account scan completed"

}

#################################################
# BASH HISTORY TAMPERING
#################################################

check_bash_history() {

log "Checking bash history anomalies..."

found=0

for home in /root /home/*; do

hist="$home/.bash_history"

if [ -f "$hist" ]; then

size=$(stat -c%s "$hist")

if [[ "$size" -lt 20 ]]; then
warn "Possible bash history wiping: $hist"
found=1
fi

fi

done

if [[ "$found" -eq 0 ]]; then
ok "No bash history anomalies detected"
fi

}

#################################################
# FINAL REPORT
#################################################

report() {

echo ""
echo "================================================="
echo "LINUX PERSISTENCE DETECTOR - SECURITY REPORT"
echo "================================================="
echo ""

echo "Total suspicious findings: $FOUND_ISSUES"
echo ""

if [[ "$FOUND_ISSUES" -gt 0 ]]; then

echo "⚠ Suspicious indicators detected:"
echo ""

for i in "${findings[@]}"; do
echo " - $i"
done

else

echo "✔ No persistence or compromise indicators detected"

fi

echo ""
echo "✔ Checks completed without anomalies:"
echo ""

for i in "${clean[@]}"; do
echo " - $i"
done

echo ""
echo "Log file: $LOGFILE"

}

#################################################
# SUMMARY
#################################################

summary() {

echo ""
echo "===================================="
echo "Audit finished"
echo "Linux Persistence Detector v$VERSION"
echo "Linux Audit Team"
echo "https://linux.lat"
echo "===================================="

}

#################################################
# MAIN
#################################################

main() {

echo ""
echo "Linux Persistence Detector v$VERSION"
echo "Linux Audit Team"
echo "https://linux.lat"
echo ""

check_root

check_cron_persistence
check_systemd_persistence
check_ssh_backdoors
check_path_hijacking
check_suid_abuse
check_reverse_shells
check_rootkit_indicators
check_ld_preload
check_capabilities
check_recent_binaries
check_hidden_processes
check_rc_local
check_users
check_bash_history

report
summary

}

main "$@"
