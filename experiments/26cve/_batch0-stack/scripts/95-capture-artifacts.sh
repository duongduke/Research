#!/usr/bin/env bash
# Batch 0 — capture reproduction artifacts into ~/batch0-lab/artifacts
set -uo pipefail
LAB="$HOME/batch0-lab"; A="$LAB/artifacts"; mkdir -p "$A"

echo "== CVE-2019-8942 =="
docker exec b0-wp-8942-vuln  bash -c 'rm -f /tmp/rq-c1-poc-marker'
docker exec b0-wp-8942-fixed bash -c 'rm -f /tmp/rq-c1-poc-marker'
docker exec b0-wp-8942-vuln  bash -c 'rm -f /var/www/html/wp-content/themes/twentynineteen/cropped-*' 2>/dev/null
python3 "$LAB/scripts/repro/42-cve-2019-8942.py" 8111 vuln-5.0.0  > "$A/8942-repro-vuln.txt" 2>&1
python3 "$LAB/scripts/repro/42-cve-2019-8942.py" 8112 fixed-5.0.1 > "$A/8942-repro-fixed.txt" 2>&1
{ echo "marker (vuln):"; docker exec b0-wp-8942-vuln  bash -c 'cat /tmp/rq-c1-poc-marker 2>/dev/null || echo "(none)"';
  echo "planted (vuln):"; docker exec b0-wp-8942-vuln bash -c 'find /var/www/html/wp-content/themes -name "cropped-*" 2>/dev/null';
  echo "marker (fixed):"; docker exec b0-wp-8942-fixed bash -c 'cat /tmp/rq-c1-poc-marker 2>/dev/null || echo "(none)"';
  echo "planted (fixed):"; docker exec b0-wp-8942-fixed bash -c 'find /var/www/html/wp-content/themes -name "cropped-*" 2>/dev/null';
} > "$A/8942-marker-and-planted.txt" 2>&1
{ echo "== vuln postmeta _wp_attached_file =="; docker exec b0-db mariadb -uroot -p${MARIADB_ROOT_PASSWORD:-changeme} wp_8942_vuln  -e "SELECT meta_key,LEFT(meta_value,90) FROM wp_postmeta WHERE meta_key='_wp_attached_file' ORDER BY meta_id DESC LIMIT 4;";
  echo "== fixed postmeta _wp_attached_file =="; docker exec b0-db mariadb -uroot -p${MARIADB_ROOT_PASSWORD:-changeme} wp_8942_fixed -e "SELECT meta_key,LEFT(meta_value,90) FROM wp_postmeta WHERE meta_key='_wp_attached_file' ORDER BY meta_id DESC LIMIT 4;";
} > "$A/8942-db-state.txt" 2>&1

echo "== CVE-2021-29447 =="
docker exec b0-wp-29447-vuln  bash -c 'echo RQ-C1-POC-MARKER > /tmp/rq-c1-poc-marker'
docker exec b0-wp-29447-fixed bash -c 'echo RQ-C1-POC-MARKER > /tmp/rq-c1-poc-marker'
bash "$LAB/scripts/repro/43-cve-2021-29447.sh" 8121 vuln-5.7.0  > "$A/29447-repro-vuln.txt" 2>&1
docker logs b0-attacker > "$A/29447-attacker-log-after-vuln.txt" 2>&1
bash "$LAB/scripts/repro/43-cve-2021-29447.sh" 8122 fixed-5.7.1 > "$A/29447-repro-fixed.txt" 2>&1
docker logs b0-attacker > "$A/29447-attacker-log-full.txt" 2>&1
cp "$LAB/attacker/evil.dtd" "$A/29447-evil.dtd"

echo "== CVE-2022-21661 =="
docker exec b0-db mariadb -uroot -p${MARIADB_ROOT_PASSWORD:-changeme} -e "SET GLOBAL general_log=ON; SET GLOBAL log_output='TABLE';" 2>/dev/null
docker exec b0-db mariadb -uroot -p${MARIADB_ROOT_PASSWORD:-changeme} -e "TRUNCATE mysql.general_log;" 2>/dev/null
bash "$LAB/scripts/repro/44-cve-2022-21661.sh" 8131 vuln-5.8.2  > "$A/21661-repro-vuln.txt" 2>&1
bash "$LAB/scripts/repro/44-cve-2022-21661.sh" 8132 fixed-5.8.3 > "$A/21661-repro-fixed.txt" 2>&1
docker exec b0-db mariadb -uroot -p${MARIADB_ROOT_PASSWORD:-changeme} -e "SELECT event_time,LEFT(argument,160) AS sql FROM mysql.general_log WHERE argument LIKE '%SLEEP%' ORDER BY event_time;" > "$A/21661-db-general-log.txt" 2>&1
docker exec b0-db mariadb -uroot -p${MARIADB_ROOT_PASSWORD:-changeme} -e "SET GLOBAL general_log=OFF;" 2>/dev/null

echo "DONE-CAPTURE"; ls -la "$A"
