#!/usr/bin/env bash
# Ca B — Drupal 8.6.x REST/web-services (CVE-2019-6340 pilot).
# Installs Drush 9 (via Composer 2.2, PHP 7.2 in-image) and installs the Drupal
# site into the shared MariaDB. GROUND TRUTH ONLY.
#
# Drupal 8.6 requires PHP >= 7.0.8; the image ships PHP 7.2.15, so Drush must run
# on the container's own PHP (the drush/drush:9 image ships PHP 7.0.7 = too old).
set -euo pipefail

C_NAME="$1"     # pilot-drupal-vuln | pilot-drupal-fixed
C_DB="$2"       # drupal_vuln | drupal_fixed
SITE_NAME="$3"  # e.g. "Pilot Drupal 8.6.9"

echo "===== $C_NAME ($SITE_NAME) ====="

echo "-- install composer + drush 9 (container-local) --"
# Drupal 8.6 requires Twig 1.x; a default `composer global require drush/drush`
# resolves Twig 2.x and breaks full Drupal bootstrap, so Twig 1 is pinned.
docker exec "$C_NAME" bash -c '
  set -e
  if [ ! -x /opt/drush/vendor/bin/drush ]; then
    curl -s -o /usr/local/bin/composer.phar https://getcomposer.org/download/2.2.25/composer.phar
    export COMPOSER_HOME=/opt/drush COMPOSER_ALLOW_SUPERUSER=1
    php /usr/local/bin/composer.phar global require drush/drush:^9.7 twig/twig:^1.38 --no-interaction --no-progress -q
  fi
  ln -sf /opt/drush/vendor/bin/drush /usr/local/bin/drush
  drush --version
'

echo "-- Drupal version reported by drush --"
docker exec -w /var/www/html "$C_NAME" drush status 2>&1 | head -14 || true

echo "-- site-install (standard profile) --"
docker exec -w /var/www/html "$C_NAME" drush site-install standard \
  --db-url="mysql://labuser:${DB_PASSWORD:-changeme}@db:3306/$C_DB" \
  --account-name=admin --account-pass=${WP_ADMIN_PASSWORD:-changeme} \
  --site-name="$SITE_NAME" -y 2>&1 | tail -8

echo "-- status after install --"
docker exec -w /var/www/html "$C_NAME" drush status 2>&1 | head -16 || true
echo "-- version (direct) --"
docker exec -w /var/www/html "$C_NAME" drush status --field=drupal-version 2>&1 || true
