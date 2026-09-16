#!/usr/bin/env bash
# Generates a strict agent-secure policy for the locally installed scanners.
#
# Usage: bootstrap-policy.sh [gitleaks-path] [osv-scanner-path] > policy.json
#
# The policy pins each scanner by absolute path and SHA-256 so agent-secure
# refuses to run tampered or swapped binaries. Regenerate after every scanner
# upgrade (e.g. `brew upgrade gitleaks osv-scanner`); a stale digest is
# reported by `agent-secure doctor` as an error, never silently ignored.
#
# keep_network=false by default: scanners run offline (see README). Opting in
# to remote lookups is an explicit policy edit, not a default.
set -euo pipefail

# Homebrew and other managers expose scanners as shims. The engine refuses
# symlink tool paths (TOCTOU), so pin the regular file the shim resolves to.
canonicalize() {
  python3 -c '
import os, sys
path = os.path.realpath(sys.argv[1])
if not os.path.isfile(path) or os.path.islink(path):
    sys.stderr.write("error: scanner path must resolve to a regular file\n")
    sys.exit(1)
print(path)
' "$1"
}

resolve() {
  local name="$1" given="${2:-}"
  if [ -n "$given" ]; then
    if [ ! -x "$given" ]; then
      echo "error: $given is not executable" >&2
      exit 1
    fi
    canonicalize "$given"
    return
  fi
  local found
  found="$(command -v "$name" 2>/dev/null || true)"
  if [ -z "$found" ]; then
    # Homebrew keg path (works when the brew bin dir is not on PATH).
    for candidate in /opt/homebrew/opt/"$name"/bin/"$name" /usr/local/opt/"$name"/bin/"$name"; do
      if [ -x "$candidate" ]; then
        found="$candidate"
        break
      fi
    done
  fi
  if [ -z "$found" ]; then
    echo "error: $name not found; pass its path as an argument" >&2
    exit 1
  fi
  canonicalize "$found"
}

digest() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

GITLEAKS="$(resolve gitleaks "${1:-}")"
OSV="$(resolve osv-scanner "${2:-}")"

cat <<JSON
{
  "version": 1,
  "allow_network": false,
  "scanners": ["gitleaks", "osv-scanner"],
  "tools": {
    "gitleaks": {
      "path": "$GITLEAKS",
      "sha256": "$(digest "$GITLEAKS")"
    },
    "osv-scanner": {
      "path": "$OSV",
      "sha256": "$(digest "$OSV")"
    }
  }
}
JSON
