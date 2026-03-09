#!/usr/bin/env bash
#
# Linux Persistence Detector
# https://linux.lat
#
# Linux Audit Team
# GNU GPL v3


VERSION="5.1"

OUTPUT_DIR="/tmp"
LOGFILE=""
JSON_OUT=""
CSV_OUT=""
SINCE_DAYS=7

ISSUES=0
CRITICAL=0
ALERTS=()

HOST=$(hostname)
DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

########################################
# Logging
########################################

info(){ echo "[INFO] $*" | tee -a "$LOGFILE"; }

warn(){
echo "[WARN] $*" | tee -a "$LOGFILE"
ALERTS+=("$*")
((ISSUES++))
}

crit(){
echo "[CRIT] $*" | tee -a "$LOGFILE"
ALERTS+=("$*")
((ISSUES++))
((CRITICAL++))
}

ok(){ echo "[OK] $*" | tee -a "$LOGFILE"; }

########################################
# Root check
########################################

if [[ $EUID -ne 0 ]]; then
echo "Warning: run as root for full coverage"
fi

########################################
# Argument parser
########################################

while [[ $# -gt 0 ]]; do
case "$1" in
--json) JSON_OUT="$2"; shift 2 ;;
--json=*) JSON_OUT="${1#*=}"; shift ;;
--csv) CSV_OUT="$2"; shift 2 ;;
--csv=*) CSV_OUT="${1#*=}"; shift ;;
--since) SINCE_DAYS="$2"; shift 2 ;;
--since=*) SINCE_DAYS="${1#*=}"; shift ;;
--output-dir) OUTPUT_DIR="$2"; shift 2 ;;
--output-dir=*) OUTPUT_DIR="${1#*=}"; shift ;;
*) echo "Unknown option $1"; exit 1 ;;
esac
done

mkdir -p "$OUTPUT_DIR"

LOGFILE="$OUTPUT_DIR/persistence_scan.log"

########################################
# Metadata
########################################

info "Linux Persistence Scanner v$VERSION"
info "Host: $HOST"
info "Date: $DATE"
info "Since days: $SINCE_DAYS"

########################################
# Cron
########################################

check_cron(){

info "Checking cron jobs"

for dir in /etc/cron* /var/spool/cron; do
[ -d "$dir" ] || continue
find "$dir" -type f -mtime -"${SINCE_DAYS}" 2>/dev/null | while read -r f; do
warn "Recent cron file: $f"
done
done

}

########################################
# Systemd services
########################################

check_systemd(){

info "Checking systemd persistence"

find /etc/systemd /usr/lib/systemd /lib/systemd \
-type f -name "*.service" -mtime -"${SINCE_DAYS}" 2>/dev/null \
| while read -r f; do
warn "Recent systemd service: $f"
done

}

########################################
# Systemd user units
########################################

check_systemd_user(){

info "Checking systemd user units"

find /home/*/.config/systemd/user \
-type f \( -name "*.service" -o -name "*.timer" \) 2>/dev/null \
| while read -r f; do
warn "User systemd unit: $f"
done

}

########################################
# SSH authorized_keys
########################################

check_ssh_backdoors(){

info "Checking SSH authorized_keys"

find /home /root -type f -name authorized_keys -mtime -"${SINCE_DAYS}" -print0 2>/dev/null |
while IFS= read -r -d '' file; do

count=$(wc -l < "$file")

if [[ "$count" -gt 5 ]]; then
warn "Many SSH keys in authorized_keys: $file ($count)"
head -n 3 "$file" >> "$LOGFILE"
else
warn "Recent authorized_keys modified: $file"
fi

done

}

########################################
# Bash history anomalies
########################################

check_bash_history(){

info "Checking bash history anomalies"

for h in /root/.bash_history /home/*/.bash_history; do

[ -f "$h" ] || continue

size=$(stat -c%s "$h")
mtime=$(stat -c %Y "$h")
now=$(date +%s)

age=$(( (now - mtime) / 86400 ))

if [[ "$size" -lt 10 ]]; then
warn "Suspicious small history file: $h"
fi

if [[ "$age" -lt 1 ]]; then
warn "Recently modified history file: $h"
fi

done

}

########################################
# Shell profiles
########################################

check_shell_profiles(){

info "Checking shell profiles"

local suspicious="curl|wget|nc|bash -i|python -c|sh -c|base64"

for file in /root/.{bashrc,bash_profile,profile,zshrc} \
/home/*/.{bashrc,bash_profile,profile,zshrc} \
/etc/profile \
/etc/profile.d/*.sh; do

[ -f "$file" ] || continue

if grep -Ei "$suspicious" "$file" > /tmp/susp.$$; then
warn "Suspicious shell profile: $file"
cat /tmp/susp.$$ >> "$LOGFILE"
fi

done

rm -f /tmp/susp.$$

}

########################################
# Writable PATH
########################################

check_path_writable(){

info "Checking writable PATH directories"

OLDIFS="$IFS"
IFS=":"

for p in $PATH; do
if [[ -w "$p" ]]; then
warn "Writable PATH directory: $p"
fi
done

IFS="$OLDIFS"

}

########################################
# XDG autostart
########################################

check_xdg_autostart(){

info "Checking XDG autostart"

for f in /home/*/.config/autostart/*.desktop; do
[ -f "$f" ] || continue

if grep -qiE "curl|wget|nc|bash -c|python -c|base64|chmod" "$f"; then
warn "Suspicious XDG autostart: $f"
grep Exec "$f" >> "$LOGFILE"
fi

done

}

########################################
# Hidden processes
########################################

check_hidden_processes(){

info "Checking hidden processes"

ps_pids=$(ps -eo pid= | tr -d ' ' | sort -n)
proc_pids=$(ls /proc | grep -E '^[0-9]+$' | sort -n)

hidden=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids"))

for pid in $hidden; do
[[ -d /proc/$pid ]] && warn "Hidden process: $pid"
done

}

########################################
# Network anomalies
########################################

check_network(){

info "Checking unusual outbound connections"

ss -tpn state established \
'( sport >= :1024 and dport != :22 and dport != :80 and dport != :443 )' \
>> "$LOGFILE" 2>/dev/null

}

########################################
# Udev persistence
########################################

check_udev(){

info "Checking udev rules"

grep -rE "RUN\+=" /etc/udev/rules.d /lib/udev/rules.d 2>/dev/null \
| grep -Ei "curl|wget|nc|bash|sh|python|perl|base64|chmod" \
| while read -r line; do
warn "Suspicious udev rule: $line"
done

}

########################################
# ld.so.preload
########################################

check_ld_preload(){

info "Checking ld.so.preload"

if [[ -f /etc/ld.so.preload ]]; then
crit "ld.so.preload present"
cat /etc/ld.so.preload >> "$LOGFILE"
fi

}

########################################
# ld.so.conf.d
########################################

check_ld_conf(){

info "Checking ld.so.conf.d"

find /etc/ld.so.conf.d -type f -mtime -"${SINCE_DAYS}" 2>/dev/null \
| while read -r f; do
warn "Recent ld.so.conf file: $f"
done

}

########################################
# SUID / SGID binaries
########################################

SUID_WHITELIST=(
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/umount
/usr/bin/chsh
/usr/bin/chfn
)

check_suid(){

info "Checking SUID/SGID binaries"

find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null |
while read -r f; do
if ! [[ " ${SUID_WHITELIST[*]} " =~ " ${f} " ]]; then
warn "Non-whitelisted SUID/SGID: $f"
fi
done

}

########################################
# PAM persistence
########################################

check_pam(){

info "Checking PAM modules"

grep -R "pam_exec" /etc/pam.d 2>/dev/null |
while read -r line; do
warn "Possible PAM exec persistence: $line"
done

}

########################################
# GRUB persistence
########################################

check_grub(){

info "Checking GRUB"

if [[ -f /boot/grub/grub.cfg ]]; then

if find /boot/grub/grub.cfg -mtime -"${SINCE_DAYS}" >/dev/null 2>&1; then
warn "Recent GRUB modification"
fi

grep -Ei "init=|rdinit=" /boot/grub/grub.cfg >> "$LOGFILE"

fi

}

########################################
# Kernel modules
########################################

check_kernel_modules(){

info "Checking kernel modules"

modules=$(lsmod | awk 'NR>1 {print $1}')

echo "$modules" >> "$LOGFILE"

echo "$modules" | grep -E '[0-9]{3,}|[A-Za-z]{10,}' |
while read m; do
warn "Potentially suspicious kernel module: $m"
done

}

########################################
# At jobs
########################################

check_at(){

info "Checking at/batch jobs"

if command -v atq >/dev/null; then
atq 2>/dev/null | while read line; do
warn "At job scheduled: $line"
done
fi

}

########################################
# Recent system changes
########################################

check_recent_changes(){

info "Checking recent system file changes"

changes=$(find /etc \
/usr/local \
/boot \
/etc/ld.so.conf.d \
-type f -mtime -"${SINCE_DAYS}" \
-size -1M 2>/dev/null | tee -a "$LOGFILE" | wc -l)

[[ "$changes" -gt 0 ]] && warn "Recent system changes detected ($changes files)"

}

########################################
# Run checks
########################################

check_cron
check_systemd
check_systemd_user
check_ssh_backdoors
check_bash_history
check_shell_profiles
check_path_writable
check_xdg_autostart
check_hidden_processes
check_network
check_udev
check_ld_preload
check_ld_conf
check_suid
check_pam
check_grub
check_kernel_modules
check_at
check_recent_changes

########################################
# JSON export
########################################

if [[ -n "$JSON_OUT" ]]; then

echo "{" > "$JSON_OUT"
echo "\"host\":\"$HOST\"," >> "$JSON_OUT"
echo "\"date\":\"$DATE\"," >> "$JSON_OUT"
echo "\"version\":\"$VERSION\"," >> "$JSON_OUT"
echo "\"issues\":$ISSUES," >> "$JSON_OUT"
echo "\"critical\":$CRITICAL," >> "$JSON_OUT"

if [[ ${#ALERTS[@]} -eq 0 ]]; then
echo "\"alerts\":[]" >> "$JSON_OUT"
else
echo "\"alerts\":[" >> "$JSON_OUT"

for a in "${ALERTS[@]}"; do
echo "\"${a//\"/\\\"}\"," >> "$JSON_OUT"
done

sed -i '$ s/,$//' "$JSON_OUT"

echo "]" >> "$JSON_OUT"
fi

echo "}" >> "$JSON_OUT"

fi

########################################
# CSV export
########################################

if [[ -n "$CSV_OUT" ]]; then
echo "host,date,issues,critical" > "$CSV_OUT"
echo "$HOST,$DATE,$ISSUES,$CRITICAL" >> "$CSV_OUT"
fi

########################################

info "Scan completed"
info "Issues: $ISSUES"
info "Critical: $CRITICAL"
