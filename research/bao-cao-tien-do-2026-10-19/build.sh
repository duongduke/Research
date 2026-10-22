#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
TEX="bao-cao-tien-do-2026-10-19.tex"
PDF="bao-cao-tien-do-2026-10-19.pdf"
command -v lualatex >/dev/null || { echo "ERROR: lualatex not found" >&2; exit 1; }
lualatex -interaction=nonstopmode -halt-on-error "$TEX"
lualatex -interaction=nonstopmode -halt-on-error "$TEX"
[ -f "$PDF" ] && echo "OK: $PDF" || { echo "ERROR: no PDF" >&2; exit 1; }
