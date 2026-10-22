#!/usr/bin/env bash
# Ca C — Roundcube XSS (CVE-2020-12625 pilot).
# Verifies the two versions run, seeds a test mailbox through the minimal IMAP/SMTP
# backend (GreenMail) and checks the Roundcube login page.
# GROUND TRUTH ONLY; no XSS payload is delivered here.
set -euo pipefail

echo "===== versions (ground truth) ====="
for c in pilot-roundcube-vuln pilot-roundcube-fixed; do
  echo -n "$c: "; docker exec "$c" head -4 /usr/src/roundcubemail/CHANGELOG | grep -oE 'RELEASE [0-9.]+'
done
echo "DB roundcube_version:"
docker exec pilot-db mariadb -uroot -p${MARIADB_ROOT_PASSWORD:-changeme} -N -e \
  "SELECT value FROM roundcube_vuln.system WHERE name='roundcube_version';" 2>/dev/null | sed 's/^/   vuln db: /'
docker exec pilot-db mariadb -uroot -p${MARIADB_ROOT_PASSWORD:-changeme} -N -e \
  "SELECT value FROM roundcube_fixed.system WHERE name='roundcube_version';" 2>/dev/null | sed 's/^/   fixed db: /'

echo "===== minimal mailbox: SMTP seed + IMAP read ====="
python3 - <<'PY'
import smtplib, imaplib
from email.mime.text import MIMEText
m = MIMEText("<p>pilot benign message</p>", "html")
m["Subject"] = "Pilot mailbox seed"; m["From"] = "test@localhost"; m["To"] = "test@localhost"
s = smtplib.SMTP("127.0.0.1", 3025, timeout=10)
s.sendmail("test@localhost", ["test@localhost"], m.as_string()); s.quit()
print("   SMTP: seeded 1 message to test@localhost")
c = imaplib.IMAP4("127.0.0.1", 3143); c.login("test", "test")
typ, data = c.select("INBOX")
print("   IMAP: login OK, INBOX messages =", data[0].decode())
c.logout()
PY

echo "===== Roundcube HTTP (login page) ====="
for p in 8085:roundcube-vuln 8086:roundcube-fixed; do
  port=${p%%:*}; name=${p##*:}
  code=$(curl -s -o /tmp/rc.$port -w '%{http_code}' "http://127.0.0.1:$port/?_task=login")
  echo "   [$name :$port] GET /?_task=login -> $code  bytes=$(wc -c </tmp/rc.$port)"
done

echo "===== functional login against IMAP backend (vuln) ====="
curl -s -c /tmp/rc.cookie -o /tmp/rc.login -w '   POST login -> %{http_code}\n' \
  -d 'action=login' -d '_task=login' -d '_user=test' -d '_pass=test' -d '_url=' \
  "http://127.0.0.1:8085/"
grep -oE '_task=[a-z]+' /tmp/rc.login | sort -u | head -3 || true
