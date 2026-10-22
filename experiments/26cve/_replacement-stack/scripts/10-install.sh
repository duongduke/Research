#!/usr/bin/env bash
# Replacement case CVE-2023-5798 — install WP + Assistant 1.4.3 (vuln) / 1.4.4 (fixed) + editor.
set -uo pipefail
LAB="$HOME/brepl-lab"; CLI="wordpress:cli-php8.2"
wpcli() { local dir="$1" db="$2"; shift 2
  docker run --rm -u 33 --network brepl-net -v "$LAB/$dir:/var/www/html" -v "$LAB/releases:/releases:ro" \
    -e WORDPRESS_DB_HOST=db:3306 -e WORDPRESS_DB_NAME="$db" -e WORDPRESS_DB_USER=labuser \
    -e WORDPRESS_DB_PASSWORD=${DB_PASSWORD:-changeme} -e WORDPRESS_TABLE_PREFIX=wp_ "$CLI" wp "$@"; }

for pair in "vuln:8611:wp_assist_vuln:1.4.3" "fixed:8612:wp_assist_fixed:1.4.4"; do
  IFS=: read -r inst port db ver <<< "$pair"
  dir="wordpress/$inst"
  echo "== $inst ($db, assistant $ver) =="
  wpcli "$dir" "$db" core is-installed 2>/dev/null || \
    wpcli "$dir" "$db" core install --url="http://127.0.0.1:$port" --title="Repl Assistant $ver" \
      --admin_user=admin --admin_password=${WP_ADMIN_PASSWORD:-changeme} --admin_email=admin@lab.test --skip-email
  wpcli "$dir" "$db" user get editor >/dev/null 2>&1 || \
    wpcli "$dir" "$db" user create editor editor@lab.test --role=editor --user_pass=${WP_EDITOR_PASSWORD:-changeme} --display_name=editor
  wpcli "$dir" "$db" plugin is-installed assistant 2>/dev/null || \
    wpcli "$dir" "$db" plugin install /releases/assistant.$ver.zip --activate
  echo -n "   core="; wpcli "$dir" "$db" core version
  echo -n "   assistant="; wpcli "$dir" "$db" plugin get assistant --field=version
  echo -n "   editor role="; wpcli "$dir" "$db" user get editor --field=roles
done
echo DONE-INSTALL
