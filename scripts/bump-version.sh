#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
current="$(sed -nE 's/^const Version = "([^"]+)"/\1/p' "$root/config/config.go")"

if [[ -z "$current" ]]; then
  echo "failed to read current version" >&2
  exit 1
fi

if [[ "${1:-}" != "" ]]; then
  next="$1"
else
  major="${current%%.*}"
  minor="${current#*.}"
  next="$major.$((10#$minor + 1))"
fi

perl -0pi -e "s/const Version = \"[^\"]+\"/const Version = \"$next\"/" "$root/config/config.go"
perl -0pi -e "s/\"version\": \"[^\"]+\"/\"version\": \"$next\"/" "$root/version.json"
perl -0pi -e "s/image: kiro-go:\\\$\\{KIRO_GO_VERSION:-[^}]+\\}/image: kiro-go:\\\${KIRO_GO_VERSION:-$next}/" "$root/docker-compose.yml"

echo "$current -> $next"
