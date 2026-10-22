#!/usr/bin/env bash
# Drive the three CVE-2023-6553 states on the lab VM and record the marker evidence.
# Lab only. The PoC writes /tmp/rq-c1-poc-marker inside topup-wp and nothing else.
#
#   SSH='sshpass -p **** ssh -o StrictHostKeyChecking=no' \
#   BASE=http://127.0.0.1:8930 LOG=artifacts/marker-checks.txt \
#   bash run-6553-states.sh
#
# Assumes the stack from ../compose is up and ~/topup-lab/wpcli.sh exists (see ../README.md).
set -u
SSH="${SSH:-ssh}"
BASE="${BASE:?set BASE}"
LOG="${LOG:?set LOG}"
CASE_DIR="${CASE_DIR:-$(cd "$(dirname "$0")/../../CVE-2023-6553" && pwd)}"
PLUGDIR=~/topup-lab/wordpress/wp-content/plugins/backup-backup
MARKER=/tmp/rq-c1-poc-marker

say() { echo "$@" | tee -a "$LOG"; }
vm()  { $SSH <lab-user>@<lab-ip> "$@"; }

plugstate() { vm "~/topup-lab/wpcli.sh plugin list --fields=name,status,version | grep backup-backup"; }
set_137() { vm "rm -rf $PLUGDIR && cd ~/topup-lab && python3 -c \"import zipfile; zipfile.ZipFile('bb-1.3.7.zip').extractall('wordpress/wp-content/plugins')\" && chmod -R 777 $PLUGDIR 2>/dev/null; ~/topup-lab/wpcli.sh plugin activate backup-backup"; }
set_138() { vm "rm -rf $PLUGDIR && cd ~/topup-lab && python3 -c \"import zipfile; zipfile.ZipFile('bb-1.3.8.zip').extractall('wordpress/wp-content/plugins')\" && chmod -R 777 $PLUGDIR 2>/dev/null; ~/topup-lab/wpcli.sh plugin activate backup-backup"; }
clear_marker() { vm "docker exec topup-wp sh -c 'rm -f $MARKER; ls $MARKER 2>/dev/null || echo MARKER-ABSENT'"; }
check_marker() { vm "docker exec topup-wp sh -c 'ls -l $MARKER 2>/dev/null && cat $MARKER || echo MARKER-ABSENT'"; }
send() { python3 "$CASE_DIR/scripts/poc_6553.py" --base "$BASE" --out "$CASE_DIR/artifacts/run-$1-POST-filterchain.raw.txt"; }

say "### CVE-2023-6553 marker evidence — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "### BASE=$BASE (SSH tunnel to the VM loopback port)"

say ""; say "## state a — 1.3.7 ACTIVE"
set_137 >/dev/null; plugstate | tee -a "$LOG"
clear_marker | tee -a "$LOG"
send a | tee -a "$LOG"
check_marker | tee -a "$LOG"

say ""; say "## state b — 1.3.7 INACTIVE (files present)"
vm "~/topup-lab/wpcli.sh plugin deactivate backup-backup" >/dev/null
plugstate | tee -a "$LOG"
vm "ls -l $PLUGDIR/includes/backup-heart.php" | tee -a "$LOG"
clear_marker | tee -a "$LOG"
send b | tee -a "$LOG"
check_marker | tee -a "$LOG"

say ""; say "## state c — 1.3.8 ACTIVE (patched control)"
set_138 >/dev/null; plugstate | tee -a "$LOG"
clear_marker | tee -a "$LOG"
send c | tee -a "$LOG"
check_marker | tee -a "$LOG"

say ""; say "## final state"
plugstate | tee -a "$LOG"
