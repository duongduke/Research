#!/usr/bin/env bash
# Batch 1 — prepare Drupal core bind dirs from official ftp.drupal.org tarballs.
# (The old drupal:X.Y.Z Docker tags are unpullable: deprecated manifest v1.)
set -euo pipefail
LAB="$HOME/batch1-lab"; R="$LAB/releases"; mkdir -p "$R"
cd "$R"
# tag:version  (vuln/fixed pairs)
declare -A V=(
  [d7-731]=7.31 [d7-732]=7.32
  [d8-850]=8.5.0 [d8-851]=8.5.1
  [d8-852]=8.5.2 [d8-853]=8.5.3
  [d8-898]=8.9.8 [d8-899]=8.9.9
  [d8-8612]=8.6.12 [d8-8613]=8.6.13
)
for tag in "${!V[@]}"; do
  ver="${V[$tag]}"
  tgz="drupal-$ver.tar.gz"
  [ -f "$tgz" ] || curl -sSL -o "$tgz" "https://ftp.drupal.org/files/projects/$tgz"
  d="$LAB/drupal/$tag/html"
  mkdir -p "$d"
  if [ ! -f "$d/index.php" ]; then
    rm -rf "$d"/* "$d"/.[!.]* 2>/dev/null || true
    tar xzf "$tgz" -C /tmp
    cp -a "/tmp/drupal-$ver/." "$d/"
  fi
  echo "$tag -> $ver  ($(grep -oE "const VERSION = '[^']+'" "$d/core/lib/Drupal.php" 2>/dev/null || grep -oE "define\('VERSION', '[^']+'" "$d/includes/bootstrap.inc" 2>/dev/null | head -1))"
done
echo PREP-DONE
