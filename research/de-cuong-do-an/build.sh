#!/usr/bin/env bash
# Render de-cuong-do-an.tex -> de-cuong-do-an.pdf (lualatex, chạy 2 lần để resolve citation).
set -euo pipefail

cd "$(dirname "$0")"

TEX="de-cuong-do-an.tex"
PDF="de-cuong-do-an.pdf"
LOG="de-cuong-do-an.log"

command -v lualatex >/dev/null || { echo "ERROR: lualatex not found" >&2; exit 1; }

echo "==> [1/2] lualatex (pass 1)"
lualatex -interaction=nonstopmode -halt-on-error "$TEX"

echo "==> [2/2] lualatex (pass 2: resolve citations)"
lualatex -interaction=nonstopmode -halt-on-error "$TEX"

if [ -f "$PDF" ]; then
  echo "==> OK: $PDF ($(du -h "$PDF" | cut -f1))"
  if grep -qi 'Citation .* undefined' "$LOG"; then
    echo "==> WARNING: còn citation chưa resolve (thiếu \\bibitem?)" >&2
  fi
  if grep -qi 'Missing character' "$LOG"; then
    echo "==> WARNING: có glyph bị thiếu (xem $LOG)" >&2
  fi
else
  echo "==> ERROR: không tạo được PDF (xem $LOG)" >&2
  exit 1
fi
