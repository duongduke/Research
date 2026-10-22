#!/usr/bin/env bash
# Batch 3 — prep the custom WP 4.2.0 (vuln) / 4.2.1 (fixed) core bind dirs.
# No pullable image exists for 4.2.x (legacy manifest v1); we run the 4.2.x core
# on the pullable wordpress:4.7.1-apache base (PHP 5.6 / Apache 2.4).
set -euo pipefail
LAB="$HOME/batch3-lab"; R="$LAB/releases"; mkdir -p "$R"
cd "$R"
[ -f wordpress-4.2.1.tar.gz ] || curl -sSL -o wordpress-4.2.1.tar.gz https://wordpress.org/wordpress-4.2.1.tar.gz
[ -f wpdev-4.2.0.tar.gz ]     || curl -sSL -o wpdev-4.2.0.tar.gz https://github.com/WordPress/wordpress-develop/archive/refs/tags/4.2.0.tar.gz
rm -rf /tmp/wp421 /tmp/wp420; mkdir -p /tmp/wp421 /tmp/wp420
tar xzf wordpress-4.2.1.tar.gz -C /tmp/wp421
tar xzf wpdev-4.2.0.tar.gz     -C /tmp/wp420
mkdir -p "$LAB/wordpress/3440-vuln" "$LAB/wordpress/3440-fixed"
rm -rf "$LAB/wordpress/3440-vuln"/* "$LAB/wordpress/3440-fixed"/*
cp -a /tmp/wp420/wordpress-develop-4.2.0/src/. "$LAB/wordpress/3440-vuln/"
# develop repo's src/ omits wp-config-sample.php (generated at repo root); supply the 4.2.x one
cp -f /tmp/wp421/wordpress/wp-config-sample.php "$LAB/wordpress/3440-vuln/"
cp -a /tmp/wp421/wordpress/. "$LAB/wordpress/3440-fixed/"
chmod -R a+rX "$LAB/wordpress/3440-vuln" "$LAB/wordpress/3440-fixed"
echo -n "vuln  version: "; grep 'wp_version =' "$LAB/wordpress/3440-vuln/wp-includes/version.php"
echo -n "fixed version: "; grep 'wp_version =' "$LAB/wordpress/3440-fixed/wp-includes/version.php"
echo PREP-DONE
