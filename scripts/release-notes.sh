#!/usr/bin/env bash
# Prints the CHANGELOG.md section for a version, e.g. `release-notes.sh 0.2.0`.
set -euo pipefail

version="${1:?usage: $0 <version>}"
changelog="${2:-CHANGELOG.md}"

notes="$(awk -v version="$version" '
  /^## \[/ { if (found) exit; found = index($0, "## [" version "]") == 1; next }
  /^\[[^]]+\]: / { next }
  found
' "$changelog")"

if [ -z "${notes//[[:space:]]/}" ]; then
  echo "No entry for $version in $changelog" >&2
  exit 1
fi

printf '%s\n' "$notes" | sed -e '/./,$!d'
