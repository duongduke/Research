#!/usr/bin/env bash
# Ca A — WordPress + Really Simple Security plugin (CVE-2024-10924 pilot)
# Installs WP core into both instances, installs the plugin version under test,
# activates it. 2FA config toggle is applied separately (see 11-wp-2fa.sh).
#
# Ground truth only: wp-cli is used here, never as scanner input.
set -euo pipefail
LAB="$HOME/pilot-lab"
CLI_IMG="wordpress:cli-php8.2"
PHP_IMG="drupal:8.6.9-apache"     # any image with the PHP zip extension

# host has no unzip -> use a throwaway container with ZipArchive, then fix owner
extract_plugin() { # $1=zip filename  $2=plugins dir subpath (relative to $LAB)
  docker run --rm --entrypoint bash \
    -v "$LAB/releases:/src:ro" \
    -v "$LAB/$2:/p" \
    "$PHP_IMG" -c \
    "php -r '\$z=new ZipArchive(); \$z->open(\"/src/$1\"); \$z->extractTo(\"/p\");' && chown -R 33:33 /p"
}

wpcli() { # $1=instance subpath $2=db name ; remaining args passed to wp
  local dir="$1" db="$2"; shift 2
  docker run --rm -u 33 --network pilot-net \
    -v "$LAB/$dir:/var/www/html" \
    -e WORDPRESS_DB_HOST=db:3306 \
    -e WORDPRESS_DB_NAME="$db" \
    -e WORDPRESS_DB_USER=labuser \
    -e WORDPRESS_DB_PASSWORD=${DB_PASSWORD:-changeme} \
    -e WORDPRESS_TABLE_PREFIX=wp_ \
    "$CLI_IMG" wp "$@"
}

echo "== Ca A: extract plugin versions =="
extract_plugin "really-simple-ssl.9.1.1.1.zip" "wordpress/vuln/html/wp-content/plugins"
extract_plugin "really-simple-ssl.9.1.2.zip"    "wordpress/fixed/html/wp-content/plugins"

echo "== plugin header versions on disk =="
grep -m1 'Version:' "$LAB/wordpress/vuln/html/wp-content/plugins/really-simple-ssl/rlrsssl-really-simple-ssl.php"
grep -m1 'Version:' "$LAB/wordpress/fixed/html/wp-content/plugins/really-simple-ssl/rlrsssl-really-simple-ssl.php"

echo "== Ca A: install WP core (vuln =8081, fixed =8082) =="
if ! wpcli "wordpress/vuln/html" wp_vuln core is-installed 2>/dev/null; then
  wpcli "wordpress/vuln/html" wp_vuln core install \
    --url=http://127.0.0.1:8081 --title="Pilot WP 9.1.1.1" \
    --admin_user=admin --admin_password=${WP_ADMIN_PASSWORD:-changeme} --admin_email=admin@lab.test --skip-email
fi
if ! wpcli "wordpress/fixed/html" wp_fixed core is-installed 2>/dev/null; then
  wpcli "wordpress/fixed/html" wp_fixed core install \
    --url=http://127.0.0.1:8082 --title="Pilot WP 9.1.2" \
    --admin_user=admin --admin_password=${WP_ADMIN_PASSWORD:-changeme} --admin_email=admin@lab.test --skip-email
fi

echo "== Ca A: activate plugin =="
wpcli "wordpress/vuln/html"  wp_vuln  plugin activate really-simple-ssl || true
wpcli "wordpress/fixed/html" wp_fixed plugin activate really-simple-ssl || true

echo "== Ca A: plugin status + versions =="
echo "--- vuln ---";  wpcli "wordpress/vuln/html"  wp_vuln  plugin get really-simple-ssl --field=version
                      wpcli "wordpress/vuln/html"  wp_vuln  plugin status really-simple-ssl
echo "--- fixed ---"; wpcli "wordpress/fixed/html" wp_fixed plugin get really-simple-ssl --field=version
                      wpcli "wordpress/fixed/html" wp_fixed plugin status really-simple-ssl
