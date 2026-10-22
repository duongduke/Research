#!/usr/bin/env bash
# Ca A — 2FA config state for Really Simple Security (CVE-2024-10924 precondition).
# GROUND TRUTH ONLY: wp-cli toggles the setting; it is never a scanner input.
#
# The plugin stores settings in the serialized option `rsssl_options`; the 2FA
# master switch is `login_protection_enabled` (1 = on, 0 = off) in both 9.1.1.1
# and 9.1.2. We set it through the plugin's own setter so the array stays valid.
set -euo pipefail
LAB="$HOME/pilot-lab"
CLI_IMG="wordpress:cli-php8.2"

wpcli() { local dir="$1" db="$2"; shift 2
  docker run --rm -u 33 --network pilot-net \
    -v "$LAB/$dir:/var/www/html" \
    -e WORDPRESS_DB_HOST=db:3306 -e WORDPRESS_DB_NAME="$db" \
    -e WORDPRESS_DB_USER=labuser -e WORDPRESS_DB_PASSWORD=${DB_PASSWORD:-changeme} -e WORDPRESS_TABLE_PREFIX=wp_ \
    "$CLI_IMG" wp "$@"
}

set_2fa() { # $1=dir $2=db $3=value(0|1) $4=roles-php-array-literal
  local dir="$1" db="$2" val="$3" roles="$4"
  wpcli "$dir" "$db" eval \
    "rsssl_update_option('login_protection_enabled', $val); rsssl_update_option('two_fa_enabled_roles_email', $roles);"
}

for inst in "vuln:wordpress/vuln/html:wp_vuln" "fixed:wordpress/fixed/html:wp_fixed"; do
  name=${inst%%:*}; rest=${inst#*:}; dir=${rest%%:*}; db=${rest##*:}
  ver=$(wpcli "$dir" "$db" plugin get really-simple-ssl --field=version)
  echo "===== $name (plugin $ver) ====="
  echo "-- 2FA ON --"
  set_2fa "$dir" "$db" 1 "array('administrator')"
  wpcli "$dir" "$db" option get rsssl_options --format=json | tr ',' '\n' | grep -E 'login_protection_enabled|two_fa_enabled_roles_email' || true
  echo "-- 2FA OFF --"
  set_2fa "$dir" "$db" 0 "array()"
  wpcli "$dir" "$db" option get rsssl_options --format=json | tr ',' '\n' | grep -E 'login_protection_enabled|two_fa_enabled_roles_email' || true
  echo "-- restore 2FA ON (final state) --"
  set_2fa "$dir" "$db" 1 "array('administrator')"
  wpcli "$dir" "$db" option get rsssl_options --format=json | tr ',' '\n' | grep -E 'login_protection_enabled' || true
done
