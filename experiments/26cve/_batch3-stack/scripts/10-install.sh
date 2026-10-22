#!/usr/bin/env bash
# Batch 3 — install WP core + admin + a post (comments open) on all 6 instances.
set -uo pipefail
LAB="$HOME/batch3-lab"
wpcli() { local cli="$1" dir="$2" db="$3"; shift 3
  docker run --rm -u 33 --network b3-net -v "$LAB/$dir:/var/www/html" \
    -e WORDPRESS_DB_HOST=db:3306 -e WORDPRESS_DB_NAME="$db" -e WORDPRESS_DB_USER=labuser \
    -e WORDPRESS_DB_PASSWORD=${DB_PASSWORD:-changeme} -e WORDPRESS_TABLE_PREFIX=wp_ "$cli" wp "$@"; }

setup() { # cli subpath db port title
  local cli="$1" dir="$2" db="$3" port="$4" title="$5"
  echo "== $dir ($db @$port) =="
  wpcli "$cli" "$dir" "$db" core is-installed 2>/dev/null || \
    wpcli "$cli" "$dir" "$db" core install --url="http://127.0.0.1:$port" --title="$title" \
      --admin_user=admin --admin_password=${WP_ADMIN_PASSWORD:-changeme} --admin_email=admin@lab.test --skip-email
  wpcli "$cli" "$dir" "$db" user get author >/dev/null 2>&1 || \
    wpcli "$cli" "$dir" "$db" user create author author@lab.test --role=author --user_pass=${WP_AUTHOR_PASSWORD:-changeme}
  # a post with comments open (for the comment-XSS case) + a plain post for id-based exploit
  if ! wpcli "$cli" "$dir" "$db" post list --post_type=post --format=ids 2>/dev/null | grep -q .; then
    wpcli "$cli" "$dir" "$db" post create --post_title="Hello B3" --post_content="hi" \
      --post_status=publish --post_author=1 --comment_status=open --ping_status=open
  fi
  echo -n "   core="; wpcli "$cli" "$dir" "$db" core version
  echo -n "   posts="; wpcli "$cli" "$dir" "$db" post list --post_type=post --format=ids | tr '\n' ' '; echo
}

setup wordpress:cli-php7.4 wordpress/1701-vuln  wp_1701_vuln  8711 "B3 WP 4.7.1"
setup wordpress:cli-php7.4 wordpress/1701-fixed wp_1701_fixed 8712 "B3 WP 4.7.2"
setup wordpress:cli-php8.2 wordpress/2745-vuln  wp_2745_vuln  8721 "B3 WP 6.2"
setup wordpress:cli-php8.2 wordpress/2745-fixed wp_2745_fixed 8722 "B3 WP 6.2.1"
setup wordpress:cli-php7.4 wordpress/3440-vuln  wp_3440_vuln  8731 "B3 WP 4.2.0"
setup wordpress:cli-php7.4 wordpress/3440-fixed wp_3440_fixed 8732 "B3 WP 4.2.1"
echo DONE-INSTALL
