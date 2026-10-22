#!/usr/bin/env bash
# Batch 0 — method-visible HTTP observations (collected BEFORE any PoC; D-003).
# GET/HEAD only, fixed path lists, well under the 20-request/case budget.
set -uo pipefail

hdr() { curl -s -D - -o /dev/null --max-time 10 "$1"; }

echo "# Batch 0 — HTTP observations (pre-PoC, loopback)"
echo "# timestamp: $(date -u +%FT%TZ)"
echo

observe() { # $1=port $2=label
  local p="$1" n="$2"
  echo "## $n  (http://127.0.0.1:$p)"
  echo "  GET /            -> $(curl -s -o /tmp/b0home -w '%{http_code}' --max-time 10 http://127.0.0.1:$p/)"
  echo "     generator meta: $(grep -oE 'content="WordPress [^"]+"' /tmp/b0home | head -1)"
  echo "     theme asset   : $(grep -oE '/wp-content/themes/[a-z0-9-]+/' /tmp/b0home | sort -u | head -1)"
  echo "  GET /readme.html -> $(curl -s -o /tmp/b0r -w '%{http_code}' --max-time 10 http://127.0.0.1:$p/readme.html)  version line: $(grep -oiE 'Version [0-9.]+' /tmp/b0r | head -1)"
  echo "  GET /wp-login.php-> $(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:$p/wp-login.php)"
  echo "  GET /wp-json/    -> $(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:$p/wp-json/)"
  echo "  Server header    : $(hdr http://127.0.0.1:$p/ | tr -d '\r' | grep -iE '^(Server|X-Powered-By|X-Pingback):' | paste -sd' | ' -)"
  echo "  ECS fixture asset: $(grep -oE 'ele-custom-skin[^"]*ver=[0-9.]+|ecs_ajax_pagination[^"]*ver=[0-9.]+' /tmp/b0home | sort -u | head -1)"
  echo
}

observe 8111 "CVE-2019-8942  WP 5.0.0 (vuln)"
observe 8112 "CVE-2019-8942  WP 5.0.1 (fixed)"
observe 8121 "CVE-2021-29447 WP 5.7.0 (vuln)"
observe 8122 "CVE-2021-29447 WP 5.7.1 (fixed)"
observe 8131 "CVE-2022-21661 WP 5.8.2 (vuln)"
observe 8132 "CVE-2022-21661 WP 5.8.3 (fixed)"

echo "## CVE-2021-23017 nginx jammy (127.0.0.1:8190)"
echo "  HEAD / -> $(curl -sI -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:8190/)"
echo "  Server header: $(hdr http://127.0.0.1:8190/ | tr -d '\r' | grep -iE '^Server:' | paste -sd' | ' -)"
echo

echo "## listening sockets (must be 127.0.0.1 only)"
ss -tlnp 2>/dev/null | grep -E ':(8111|8112|8121|8122|8131|8132|13307|8190|8199)\b' | awk '{print "  "$4"  "$6}'
