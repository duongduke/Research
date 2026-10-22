#!/usr/bin/env bash
#
# RQ-C1 — CVE-2023-3460 fixture alignment  (2026-10-16)
#
# PROBLEM (reviews/Review_v2_captures_phanquyet_2026-10-15.md §3, D-V2-4):
#   vuln  b2-wp-v (8830, UM 2.6.6): registration fixture reachable at ?page_id=6
#         (post 6 = page "[ultimatemember form_id=\"7\"]"; um_core_forms.register=7)
#   fixed b2-wp-f (8831, UM 2.6.7): post 6 is the um_form post id 6 -> ?page_id=6 = 404
#   -> the two states were NOT ID-comparable; probe page_id=6 matched only the vuln state.
#
# FIX: make the fixed instance's site data IDENTICAL to the vulnerable instance's site data
#      (same posts/pages/forms/options ids), while keeping the UM 2.6.7 plugin files in the
#      fixed html dir.  Mechanism = "clone the vuln WordPress DB into the fixed DB, then
#      restore the options that MUST differ per instance (site URL / blog name / UM sitekey /
#      UM version)."
#
# NON-GOALS / invariants:
#   * No exploit payload is sent. Ground-truth labels, registry, mapping, snapshot untouched.
#   * Ports stay loopback (no compose/port/label change).
#   * wp_b2_v (vulnerable) is only READ (mariadb-dump), never modified.
#
# DELIBERATE, DOCUMENTED DEVIATIONS FROM A 1:1 CLONE (see report):
#   (1) siteurl/home/blogname/UM sitekey  -> must differ per instance (environment identity).
#   (2) um_version / um_last_version_upgrade = 2.6.7 (the plugin actually installed here;
#       UM has no DB migration package after 2.6.0, so this is what an upgrade would leave).
#   (3) rows for the non-admin users (ids 2..6) are removed: they are artefacts CREATED BY
#       THE PoC RUNS ON THE VULNERABLE STATE (rqpwnv, rqpwnv5 = CVE-2023-3460 admin accounts,
#       rqlsvuln = litespeed case, rqwc = woocommerce-payments case, umuser1 = fixture test).
#       Leaving exploit-created administrator accounts inside the FIXED control would be a
#       contamination/hygiene defect. Only user id 1 (admin) is kept, as in the pre-fix
#       fixed DB.
#
set -euo pipefail

TS=2026-10-16
LAB=~/batch2-lab
BK=$LAB/backups
mkdir -p "$BK"

DB=v
say() { printf '\n=== %s ===\n' "$*"; }

say "0. preconditions"
docker inspect -f '{{.Name}} {{.State.Status}}' b2-wp-v b2-wp-f b2-db
curl -sS -o /dev/null -w 'vuln  8830 pre  ?page_id=6 -> %{http_code}\n' "http://127.0.0.1:8830/?page_id=6"
curl -sS -o /dev/null -w 'fixed 8831 pre  ?page_id=6 -> %{http_code}\n' "http://127.0.0.1:8831/?page_id=6"
ls -la "$LAB/backups/"

say "1. stop fixed WP container (keep db + vuln running)"
docker stop b2-wp-f

say "2. drop + recreate wp_b2_f, import the vulnerable DB (read-only source dump)"
docker exec b2-db mariadb -uroot -p${MARIADB_ROOT_PASSWORD:-changeme} -e "DROP DATABASE IF EXISTS wp_b2_f; CREATE DATABASE wp_b2_f;"
docker exec -i b2-db mariadb -uroot -p${MARIADB_ROOT_PASSWORD:-changeme} wp_b2_f < "$BK/wp_b2_v-$TS.sql"

say "3. per-instance options (URL rewrite is length-preserving: 8830 -> 8831)"
docker exec -i b2-db mariadb -uroot -p${MARIADB_ROOT_PASSWORD:-changeme} wp_b2_f <<'SQL'
UPDATE wp_options SET option_value = REPLACE(option_value,'127.0.0.1:8830','127.0.0.1:8831')
  WHERE option_value LIKE '%127.0.0.1:8830%';
UPDATE wp_posts    SET guid         = REPLACE(guid,        '127.0.0.1:8830','127.0.0.1:8831')
  WHERE guid LIKE '%127.0.0.1:8830%';
UPDATE wp_posts    SET post_content = REPLACE(post_content,'127.0.0.1:8830','127.0.0.1:8831')
  WHERE post_content LIKE '%127.0.0.1:8830%';
UPDATE wp_postmeta SET meta_value   = REPLACE(meta_value,  '127.0.0.1:8830','127.0.0.1:8831')
  WHERE meta_value LIKE '%127.0.0.1:8830%';
UPDATE wp_usermeta SET meta_value   = REPLACE(meta_value,  '127.0.0.1:8830','127.0.0.1:8831')
  WHERE meta_value LIKE '%127.0.0.1:8830%';
UPDATE wp_options SET option_value='http://127.0.0.1:8831' WHERE option_name IN ('siteurl','home');
UPDATE wp_options SET option_value='B2 f'                  WHERE option_name='blogname';
UPDATE wp_options SET option_value='127.0.0.1:8831-i0j37bHJI4VzcyWq5o5V'
  WHERE option_name='__ultimatemember_sitekey';
UPDATE wp_options SET option_value='2.6.7'
  WHERE option_name IN ('um_version','um_last_version_upgrade');
SQL

say "4. remove PoC-created user residue (ids 2..6) + their UM caches / auto-draft"
docker exec -i b2-db mariadb -uroot -p${MARIADB_ROOT_PASSWORD:-changeme} wp_b2_f <<'SQL'
DELETE FROM wp_usermeta WHERE user_id <> 1;
DELETE FROM wp_users    WHERE ID <> 1;
DELETE FROM wp_options  WHERE option_name LIKE 'um_cache_userdata_%'
                          AND option_name <> 'um_cache_userdata_1';
UPDATE wp_posts SET post_author = 1 WHERE post_author <> 1;
SQL

say "5. start fixed WP container"
docker start b2-wp-f
sleep 3
docker inspect -f '{{.Name}} {{.State.Status}}' b2-wp-f

say "6. verify"
for p in 8830 8831; do
  printf -- '--- port %s ---\n' "$p"
  curl -i -sS "http://127.0.0.1:$p/?page_id=6" -o "/tmp/fix-$p.txt" \
       -w 'status=%{http_code} content_type=%{content_type}\n'
  printf 'um-form=%s  user_login-[id]=%s  _wpnonce=%s\n' \
    "$(grep -c 'um-form' /tmp/fix-$p.txt)" \
    "$(grep -oE 'user_login-[0-9]+' /tmp/fix-$p.txt | sort -u | tr '\n' ' ')" \
    "$(grep -c '_wpnonce' /tmp/fix-$p.txt)"
  printf 'readme Stable tag: %s\n' \
    "$(curl -sS "http://127.0.0.1:$p/wp-content/plugins/ultimate-member/readme.txt" | grep -m1 -i 'Stable tag' | tr -d '\r')"
done
