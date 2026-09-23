#!/usr/bin/env bash
# Regenerate SHA256SUMS.txt over every file tracked by git (run from the repository root after git add).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
if command -v sha256sum >/dev/null; then H="sha256sum"; else H="shasum -a 256"; fi
git ls-files -z | grep -zv '^SHA256SUMS.txt$' | LC_ALL=C sort -z | xargs -0 $H > SHA256SUMS.txt
echo "SHA256SUMS.txt: $(wc -l < SHA256SUMS.txt) files"
