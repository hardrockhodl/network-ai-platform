#!/bin/bash
# Usage:
#   ./concat.sh . > all_code.txt
#   ./concat.sh . data/exports/all_code_$(date +%F).txt

set -euo pipefail

DIR="${1:-.}"
OUTFILE="${2:-/dev/stdout}"

# Absolute repo root
ROOT="$(cd "$DIR" && pwd)"

# Empty the outfile
: > "$OUTFILE"

# Build find prune for dirs we don't want in the concat
# (add/remove to taste)
PRUNE_DIRS='
  -name .git -o
  -name node_modules -o
  -name __pycache__ -o
  -name .venv -o -name venv -o
  -name dist -o -name build -o
  -path '"$ROOT"'/frontend/public -o
  -path '"$ROOT"'/docs/screenshots -o
  -path '"$ROOT"'/data/uploads -o
  -path '"$ROOT"'/data/backups -o
  -path '"$ROOT"'/data/exports -o
  -path '"$ROOT"'/data/logs
'

# Exclude common binary/asset extensions
EXCL_EXT='.*\.\(png\|jpg\|jpeg\|gif\|svg\|ico\|pdf\|zip\|gz\|tgz\|bz2\|7z\|mp4\|webm\|mp3\|wav\|woff2\|woff\|ttf\|otf\|sqlite\|db\|log\)$'

# Find all files, skip pruned dirs and excluded extensions
# Use -print0 / sort -z to be safe with spaces/newlines
eval find \""$ROOT"\" \
  \( -type d \( $PRUNE_DIRS \) -prune \) -o \
  -type f ! -regex \""$EXCL_EXT"\" -print0 |
  sort -z |
while IFS= read -r -d '' file; do
  rel="${file#$ROOT/}"
  {
    printf '%s\n' "$rel"
    printf '%0.s-' {1..40}; printf '\n'
    cat "$file"
    printf '\n\n'
  } >> "$OUTFILE"
done