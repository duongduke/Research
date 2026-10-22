#!/usr/bin/env bash
# Final read-only HTTP verification of the 3-CVE pilot deployment.
# Loopback-only GET/HEAD probes. No exploitation, no payloads.
set -uo pipefail
TS=$(date -u +%FT%TZ)
echo "# Pilot 3-CVE deployment — HTTP verification"
echo "# timestamp: $TS"
echo

echo "## Listening sockets (must all be 127.0.0.1)"
ss -tlnp 2>/dev/null | grep -E ':(8081|8082|8083|8084|8085|8086|13306|3143|3025)\b' || true
echo

echo "## Ca A — WordPress + Really Simple Security"
for p in 8081:wp-vuln-9.1.1.1 8082:wp-fixed-9.1.2; do
  port=${p%%:*}; name=${p##*:}
  echo "-- [$name] http://127.0.0.1:$port"
  echo "   GET /            -> $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$port/)"
  echo "   GET /wp-login.php-> $(curl -s -o /tmp/wpl -w '%{http_code}' http://127.0.0.1:$port/wp-login.php)"
  echo "   plugin asset ver -> $(grep -oE 'really-simple-ssl[^"]*ver=[0-9.]+' /tmp/wpl | grep -oE 'ver=[0-9.]+' | sort -u | paste -sd, -)"
  echo "   generator meta   -> $(curl -s http://127.0.0.1:$port/ | grep -oE 'content="WordPress [^"]+"' | head -1)"
  echo "   GET /wp-json/    -> $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$port/wp-json/)"
done
echo

echo "## Ca B — Drupal 8.6.x REST/web-services"
for p in 8083:drupal-vuln-8.6.9 8084:drupal-fixed-8.6.10; do
  port=${p%%:*}; name=${p##*:}
  echo "-- [$name] http://127.0.0.1:$port"
  echo "   GET /                       -> $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$port/)"
  echo "   GET /core/CHANGELOG.txt     -> $(curl -s -o /tmp/dcl -w '%{http_code}' http://127.0.0.1:$port/core/CHANGELOG.txt)"
  echo "     first line: $(head -1 /tmp/dcl | cut -c1-80)"
  echo "   GET /core/install.php       -> $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$port/core/install.php)"
  echo "   REST   /node/1?_format=hal_json -> $(curl -s -o /dev/null -w '%{http_code}' -u admin:${WP_ADMIN_PASSWORD:-changeme} -H 'Accept: application/hal+json' "http://127.0.0.1:$port/node/1?_format=hal_json")"
  echo "   JSONAPI /jsonapi/node/article   -> $(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: application/vnd.api+json' "http://127.0.0.1:$port/jsonapi/node/article")"
done
echo

echo "## Ca C — Roundcube XSS"
for p in "8085:roundcube-vuln-1.4.3:pilot-roundcube-vuln" "8086:roundcube-fixed-1.4.4:pilot-roundcube-fixed"; do
  port=${p%%:*}; rest=${p#*:}; name=${rest%%:*}; cname=${rest##*:}
  echo "-- [$name] http://127.0.0.1:$port"
  echo "   GET /?_task=login -> $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/?_task=login")"
  echo "   GET /CHANGELOG    -> $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/CHANGELOG")"
  echo "   version (ground truth, image CHANGELOG): $(docker exec "$cname" head -4 /usr/src/roundcubemail/CHANGELOG | grep -oE 'RELEASE [0-9.]+' | head -1)"
done
echo
echo "## IMAP backend"
echo "   IMAP :3143 banner -> $( (exec 3<>/dev/tcp/127.0.0.1/3143; head -c 60 <&3) 2>/dev/null )"
echo "   SMTP :3025 banner -> $( (exec 3<>/dev/tcp/127.0.0.1/3025; head -c 60 <&3) 2>/dev/null )"
