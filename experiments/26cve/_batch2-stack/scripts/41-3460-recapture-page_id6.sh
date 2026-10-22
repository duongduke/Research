#!/usr/bin/env bash
#
# RQ-C1 — CVE-2023-3460 re-capture after the 2026-10-16 fixture alignment.
# Produces the four raw `curl -i -sS` transcripts (header lines + verbatim response).
# Loopback only; benign GET requests; no payload.
#
# Header convention: the `#` lines deliberately avoid the literal marker tokens
# ('um-form', 'user_login-7', '_wpnonce', 'Stable tag') so that a whole-file grep
# counts exactly the occurrences in the RAW BODY (same convention as the 2026-10-15 files).
set -euo pipefail
OUT=/tmp/cap3460
mkdir -p "$OUT"
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# --- 8830 (vulnerable, UM 2.6.6) : registration page at ?page_id=6 ---
{
  echo "# CVE-2023-3460 - state: Ultimate Member 2.6.6 (vulnerable), container b2-wp-v, host port 8830"
  echo "# request: GET /?page_id=6"
  echo "# produced by: ssh <lab-user>@<lab-ip> -> curl -i -sS \"http://127.0.0.1:8830/?page_id=6\""
  echo "# collected (UTC): $TS"
  echo "# note: RE-CAPTURE 2026-10-16 (the vulnerable instance was NOT modified; identical state to the"
  echo "#   2026-10-15 capture of this name). post 6 = page [ultimatemember form_id=\"7\"]; um_core_forms ="
  echo "#   {register:7,login:8,profile:9}. 200; raw-body counts: form container = 7, one login field"
  echo "#   (suffix = form id 7), one WP nonce input = 1."
  echo
  curl -i -sS "http://127.0.0.1:8830/?page_id=6"
} > "$OUT/8830-um266-GET-register-page.txt"

# --- 8831 (fixed, UM 2.6.7) : registration page at ?page_id=6 (work-package request) ---
{
  echo "# CVE-2023-3460 - state: Ultimate Member 2.6.7 (fixed), container b2-wp-f, host port 8831"
  echo "# request: GET /?page_id=6"
  echo "# produced by: ssh <lab-user>@<lab-ip> -> curl -i -sS \"http://127.0.0.1:8831/?page_id=6\""
  echo "# collected (UTC): $TS"
  echo "# note: RE-CAPTURE after the 2026-10-16 fixed-fixture alignment (see README-2026-10-16-fixture-fix.md)."
  echo "#   SUPERSEDES the 2026-10-15 file of this name, which recorded 404 Not Found (on that build post 6"
  echo "#   was the um_form 'Default Registration', um_core_forms.register=6, zero form markers)."
  echo "#   After the alignment the fixed DB is ID-aligned with the vulnerable instance: post 6 = page"
  echo "#   [ultimatemember form_id=\"7\"]; um_core_forms = {register:7,login:8,profile:9}. Plugin files are"
  echo "#   still ultimate-member 2.6.7 (readme version string 2.6.7; asset ver=2.6.7)."
  echo "#   200; raw-body counts: form container = 7, one login field (suffix = form id 7), one WP nonce"
  echo "#   input = 1; field inventory identical to the 8830 capture."
  echo
  curl -i -sS "http://127.0.0.1:8831/?page_id=6"
} > "$OUT/8831-um267-GET-page_id6-AS-SPECIFIED.txt"

# --- readme.txt version string, both states ---
{
  echo "# CVE-2023-3460 - state: Ultimate Member 2.6.6 (vulnerable), container b2-wp-v, host port 8830"
  echo "# request: GET /wp-content/plugins/ultimate-member/readme.txt"
  echo "# produced by: ssh <lab-user>@<lab-ip> -> curl -i -sS \"http://127.0.0.1:8830/wp-content/plugins/ultimate-member/readme.txt\""
  echo "# collected (UTC): $TS"
  echo "# note: RE-CAPTURE 2026-10-16; plugin files untouched. The readme's version line in the body reads 2.6.6."
  echo
  curl -i -sS "http://127.0.0.1:8830/wp-content/plugins/ultimate-member/readme.txt"
} > "$OUT/8830-um266-GET-readme.txt"

{
  echo "# CVE-2023-3460 - state: Ultimate Member 2.6.7 (fixed), container b2-wp-f, host port 8831"
  echo "# request: GET /wp-content/plugins/ultimate-member/readme.txt"
  echo "# produced by: ssh <lab-user>@<lab-ip> -> curl -i -sS \"http://127.0.0.1:8831/wp-content/plugins/ultimate-member/readme.txt\""
  echo "# collected (UTC): $TS"
  echo "# note: RE-CAPTURE 2026-10-16 after the fixed-fixture alignment; only the fixed WordPress DATABASE"
  echo "#   was re-synced to the vulnerable fixture, the plugin files are unchanged. Version line in the"
  echo "#   body reads 2.6.7."
  echo
  curl -i -sS "http://127.0.0.1:8831/wp-content/plugins/ultimate-member/readme.txt"
} > "$OUT/8831-um267-GET-readme.txt"

# --- self-check: counts are computed on the RAW BODY only (after the first blank line) ---
echo "--- self-check (body-only counts) ---"
for f in "$OUT"/*.txt; do
  body=$(mktemp); awk 'BEGIN{h=1} h && /^$/{h=0; next} !h' "$f" > "$body"
  printf '%-46s %-22s um-form=%-2s user_login=%-14s _wpnonce=%-2s stable=%s\n' \
    "$(basename "$f")" \
    "$(grep -m1 -oE 'HTTP/1\.1 [0-9]{3}.*' "$body" | tr -d '\r')" \
    "$(grep -c 'um-form' "$body")" \
    "$(grep -oE 'user_login-[0-9]+' "$body" | sort -u | tr '\n' ' ')" \
    "$(grep -c '_wpnonce' "$body")" \
    "$(grep -m1 -i 'stable tag' "$body" | tr -d '\r' | sed -E 's/^# //')"
  rm -f "$body"
done
echo "--- whole-file counts (header must not contain the tokens) ---"
for f in "$OUT"/*.txt; do printf '%-46s um-form=%-2s _wpnonce=%-2s\n' "$(basename "$f")" "$(grep -c 'um-form' "$f")" "$(grep -c '_wpnonce' "$f")"; done
ls -la "$OUT"
