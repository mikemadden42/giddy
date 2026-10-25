#!/usr/bin/env bash
# Regenerate data/oui.tsv.gz from Wireshark's manufacturer database.
# Output format (one entry per line): <hex prefix>\t<manufacturer>
# The prefix is 6 hex digits for MA-L (/24), 7 for MA-M (/28), 9 for MA-S (/36).
set -euo pipefail
cd "$(dirname "$0")/.."
src="${1:-https://www.wireshark.org/download/automated/data/manuf}"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
if [[ -f "$src" ]]; then cp "$src" "$tmp"; else curl -fsSL -o "$tmp" "$src"; fi
awk -F'\t' '
  /^#/ || NF < 2 { next }
  {
    split($1, p, "/"); hex = toupper(p[1]); gsub(/[:.-]/, "", hex); gsub(/[ \t]+$/, "", hex)
    bits = (p[2] == "" ? 24 : p[2] + 0)
    name = (NF >= 3 && $3 != "" ? $3 : $2); gsub(/^[ \t]+|[ \t]+$/, "", name)
    if (bits % 4 != 0 || name == "") next
    printf "%s\t%s\n", substr(hex, 1, bits / 4), name
  }' "$tmp" | LC_ALL=C sort -u | gzip -9n > data/oui.tsv.gz
echo "wrote data/oui.tsv.gz ($(gzip -dc data/oui.tsv.gz | wc -l) entries)"
