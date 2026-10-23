#!/usr/bin/env bash
# Prints the version to build.
#
#   version.sh dev              <VERSION>-dev-<UTC date>-<time>, for pushed changes
#   version.sh release [X.Y.Z]  the given version, or VERSION with the fix
#                               (patch) number increased by 1, for a release
#
# VERSION in the repository root holds the current version.
set -euo pipefail
cd "$(dirname "$0")/../.."
current=$(tr -d ' \r\n' < VERSION)
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
if [[ ! $current =~ $semver ]]; then
  echo "VERSION holds '$current', expected X.Y.Z" >&2
  exit 1
fi
case "${1:-}" in
  dev)
    echo "$current-dev-$(date -u +%Y%m%d-%H%M%S)"
    ;;
  release)
    want="${2:-}"
    want="${want#v}"
    if [[ -z $want ]]; then
      IFS=. read -r major minor fix <<< "$current"
      want="$major.$minor.$((fix + 1))"
    elif [[ ! $want =~ $semver ]]; then
      echo "version '$want' is not of the form X.Y.Z" >&2
      exit 1
    fi
    if git rev-parse -q --verify "refs/tags/v$want" >/dev/null ||
       git ls-remote --exit-code --tags origin "refs/tags/v$want" >/dev/null 2>&1; then
      echo "release v$want exists already" >&2
      exit 1
    fi
    echo "$want"
    ;;
  *)
    echo "usage: $0 dev | release [X.Y.Z]" >&2
    exit 2
    ;;
esac
