#!/usr/bin/env bash
# Batch 0 — install WP core for all 6 instances, create admin + author accounts,
# install the CVE-2022-21661 fixture plugin (Ele Custom Skin 3.1.3).
# Ground truth only: wp-cli is used to build/label state, never as scanner input.
#
# (v2) WordPress 5.0.x cannot run under PHP 8 (curly-brace string offsets were
# removed in PHP 8), so the 8942 instances use a PHP 7.4 wp-cli image.
set -uo pipefail
LAB="$HOME/batch0-lab"
CLI82="wordpress:cli-php8.2"
CLI74="wordpress:cli-php7.4"

wpcli() { # $1=cli image $2=instance subpath $3=db name ; remaining args pass to wp
  local cli="$1" dir="$2" db="$3"; shift 3
  docker run --rm -u 33 --network batch0-net \
    -v "$LAB/$dir:/var/www/html" \
    -v "$LAB/releases:/releases:ro" \
    -e WORDPRESS_DB_HOST=db:3306 \
    -e WORDPRESS_DB_NAME="$db" \
    -e WORDPRESS_DB_USER=labuser \
    -e WORDPRESS_DB_PASSWORD=${DB_PASSWORD:-changeme} \
    -e WORDPRESS_TABLE_PREFIX=wp_ \
    "$cli" wp "$@"
}

install_one() { # $1=cli $2=subpath $3=db $4=port $5=title
  local cli="$1" dir="$2" db="$3" port="$4" title="$5"
  echo "== install $title ($dir db=$db port=$port)"
  if ! wpcli "$cli" "$dir" "$db" core is-installed 2>/dev/null; then
    wpcli "$cli" "$dir" "$db" core install \
      --url="http://127.0.0.1:$port" --title="$title" \
      --admin_user=admin --admin_password=${WP_ADMIN_PASSWORD:-changeme} \
      --admin_email=admin@lab.test --skip-email
  fi
  if ! wpcli "$cli" "$dir" "$db" user get author >/dev/null 2>&1; then
    wpcli "$cli" "$dir" "$db" user create author author@lab.test \
      --role=author --user_pass=${WP_AUTHOR_PASSWORD:-changeme} --display_name=author
  fi
  echo -n "   core version: "; wpcli "$cli" "$dir" "$db" core version
  echo -n "   author role : "; wpcli "$cli" "$dir" "$db" user get author --field=roles
}

install_one "$CLI74" "wordpress/8942-vuln"  wp_8942_vuln  8111 "B0 WP 5.0.0"
install_one "$CLI74" "wordpress/8942-fixed" wp_8942_fixed 8112 "B0 WP 5.0.1"
install_one "$CLI82" "wordpress/29447-vuln"  wp_29447_vuln  8121 "B0 WP 5.7.0-php8"
install_one "$CLI82" "wordpress/29447-fixed" wp_29447_fixed 8122 "B0 WP 5.7.1-php8"
install_one "$CLI82" "wordpress/21661-vuln"  wp_21661_vuln  8131 "B0 WP 5.8.2"
install_one "$CLI82" "wordpress/21661-fixed" wp_21661_fixed 8132 "B0 WP 5.8.3"

echo "== CVE-2022-21661 fixture: Ele Custom Skin 3.1.3 =="
for pair in "wp_21661_vuln:wordpress/21661-vuln" "wp_21661_fixed:wordpress/21661-fixed"; do
  db="${pair%%:*}"; dir="${pair##*:}"
  if ! wpcli "$CLI82" "$dir" "$db" plugin is-installed ele-custom-skin 2>/dev/null; then
    wpcli "$CLI82" "$dir" "$db" plugin install /releases/ele-custom-skin.3.1.3.zip --activate --force
  fi
  echo -n "   $dir fixture version: "
  wpcli "$CLI82" "$dir" "$db" plugin get ele-custom-skin --field=version
  wpcli "$CLI82" "$dir" "$db" plugin status ele-custom-skin | head -1
done

echo "== CVE-2021-29447 controlled marker file inside vuln/fixed containers =="
docker exec b0-wp-29447-vuln  bash -c 'echo RQ-C1-POC-MARKER > /tmp/rq-c1-poc-marker' && echo "   vuln marker created"
docker exec b0-wp-29447-fixed bash -c 'echo RQ-C1-POC-MARKER > /tmp/rq-c1-poc-marker' && echo "   fixed marker created"
echo "DONE-INSTALL"
