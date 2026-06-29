#!/usr/bin/env bash
set -euo pipefail

expected="5.0.0"
version="$(tr -d '[:space:]' < VERSION)"

if [[ "$version" != "$expected" ]]; then
  echo "VERSION is '$version', expected '$expected'" >&2
  exit 1
fi

include_paths=(
  README.md
  ROADMAP.md
  SECURITY.md
  CHANGELOG.md
  docs
  frontend/src
  backend/app
)

stale_pattern='Current release: v4|Current release: v4\.0\.0|Current release: v4\.1\.0|Recently Shipped \(v0\.7\.0\)|current v4|Current v4|currently pre-v1|pre-v1\.0|pre 1\.0|AdversaryGraph v4\.1\.0'

if grep -RInE \
  --exclude-dir=release-notes \
  --exclude-dir=assets \
  --exclude='release-summary-v4*.md' \
  --exclude='*.png' \
  --exclude='*.json' \
  "$stale_pattern" "${include_paths[@]}"; then
  echo "Found stale current-version wording. Update it before release." >&2
  exit 1
fi

required_files=(
  docs/version-matrix.md
  docs/reviewer-guide.md
  docs/security-threat-model.md
  docs/validation-and-limitations.md
  docs/public-demo-privacy.md
  docs/attack-simulation.md
  docs/attack-simulation-siem-forwarding-security.md
  docs/malware-analysis-boundary.md
  demo/README.md
)

for file in "${required_files[@]}"; do
  if [[ ! -s "$file" ]]; then
    echo "Required release/reviewer artifact missing or empty: $file" >&2
    exit 1
  fi
done

if ! grep -Eq "Current release: \\*\\*v5\\.0\\.0\\*\\*" README.md; then
  echo "README.md must state the current release as v5.0.0." >&2
  exit 1
fi

if ! grep -Eq "Current release: \\*\\*v5\\.0\\.0\\*\\*" ROADMAP.md; then
  echo "ROADMAP.md must state the current release as v5.0.0." >&2
  exit 1
fi

echo "Version consistency OK: v$expected"
