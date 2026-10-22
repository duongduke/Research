#!/usr/bin/env bash
# Render plan-so-bo.tex -> plan-so-bo.pdf (lualatex, chạy 2 lần để resolve citation).
set -euo pipefail

cd "$(dirname "$0")"

TEX="plan-so-bo.tex"
PDF="plan-so-bo.pdf"

command -v lualatex >/dev/null || { echo "ERROR: lualatex not found" >&2; exit 1; }

echo "==> [1/2] lualatex (pass 1)"
lualatex -interaction=nonstopmode -halt-on-error "$TEX"

echo "==> [2/2] lualatex (pass 2: resolve citations)"
lualatex -interaction=nonstopmode -halt-on-error "$TEX"

if [ -f "$PDF" ]; then
  echo "==> OK: $PDF ($(du -h "$PDF" | cut -f1))"
  if grep -qi 'Citation .* undefined' plan-so-bo.log; then
    echo "==> WARNING: còn citation chưa resolve (thiếu \\bibitem?)" >&2
  fi
  if grep -qi 'Missing character' plan-so-bo.log; then
    echo "==> WARNING: có glyph bị thiếu (xem plan-so-bo.log)" >&2
  fi
else
  echo "==> ERROR: không tạo được PDF (xem plan-so-bo.log)" >&2
  exit 1
fi
