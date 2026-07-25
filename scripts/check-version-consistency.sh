#!/usr/bin/env bash
set -euo pipefail

expected="$(tr -d '[:space:]' < VERSION)"
version="$expected"

if [[ ! "$expected" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "VERSION must be semantic X.Y.Z, got '$expected'" >&2
  exit 1
fi

python - "$expected" <<'PY'
import json
import pathlib
import re
import sys

expected = sys.argv[1]
root = pathlib.Path(".")


def yaml_scalar(path: pathlib.Path, keys: tuple[str, ...]) -> str | None:
    """Read a simple nested scalar without adding a PyYAML release dependency."""
    parents: list[str] = []
    for raw_line in path.read_text().splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#") or ":" not in raw_line:
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent % 2:
            continue
        key, value = raw_line.strip().split(":", 1)
        depth = indent // 2
        parents = parents[:depth]
        current = (*parents, key)
        if value.strip():
            if current == keys:
                return value.strip().strip('"\'')
        else:
            parents.append(key)
    return None


helm_values = root / "helm/adversarygraph/values.yaml"

checks = [
    ("frontend/package.json", json.loads((root / "frontend/package.json").read_text()).get("version")),
    ("frontend/package-lock.json", json.loads((root / "frontend/package-lock.json").read_text()).get("version")),
    ("helm/adversarygraph/Chart.yaml", re.search(r'^appVersion:\s*"?([^"\n]+)"?', (root / "helm/adversarygraph/Chart.yaml").read_text(), re.M).group(1)),
    ("helm/adversarygraph/values.yaml image.tag", yaml_scalar(helm_values, ("image", "tag"))),
    ("helm/adversarygraph/values.yaml frontend.image.tag", yaml_scalar(helm_values, ("frontend", "image", "tag"))),
    ("helm/adversarygraph/values.yaml malwaregraph.image.tag", yaml_scalar(helm_values, ("malwaregraph", "image", "tag"))),
    ("backend/app/core/version.py", re.search(r'^APP_VERSION\s*=\s*"([^"]+)"', (root / "backend/app/core/version.py").read_text(), re.M).group(1)),
]
failed = False
for path, value in checks:
    if value != expected:
        print(f"{path} version is '{value}', expected '{expected}'", file=sys.stderr)
        failed = True
if failed:
    sys.exit(1)
PY

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
  "docs/release-notes/v${expected}.md"
  "docs/release-summary-v${expected}.md"
  docs/version-matrix.md
  docs/module-reference.md
  docs/reviewer-guide.md
  docs/security-threat-model.md
  docs/validation-and-limitations.md
  docs/public-demo-privacy.md
  docs/attack-simulation.md
  docs/attack-simulation-siem-forwarding-security.md
  docs/malware-analysis-boundary.md
  demo/README.md
)

if [[ "$expected" == 6.* ]]; then
  required_files+=(
    docs/release-readiness-v6.md
    docs/case-studies-v6.md
    docs/assets/adversarygraph-v6/manifest.md
    docs/assets/adversarygraph-v6/sha256sums.txt
  )
fi

atlas_expected_ref="$(awk -F= '$1 == "ATLAS_REPOSITORY_REF" {print $2; exit}' .env.example)"
atlas_snapshot_ref="$(tr -d '[:space:]' < anomaly_detection/docs-site/.atlas-source-ref)"
if [[ ! "$atlas_expected_ref" =~ ^[a-f0-9]{40}$ ]]; then
  echo ".env.example ATLAS_REPOSITORY_REF must be a full lowercase commit SHA." >&2
  exit 1
fi
if [[ "$atlas_snapshot_ref" != "$atlas_expected_ref" ]]; then
  echo "Atlas snapshot provenance '$atlas_snapshot_ref' does not match reviewed ref '$atlas_expected_ref'." >&2
  echo "Run ATLAS_REPOSITORY_REF=$atlas_expected_ref make sync-atlas-release and review the result." >&2
  exit 1
fi

for file in "${required_files[@]}"; do
  if [[ ! -s "$file" ]]; then
    echo "Required release/reviewer artifact missing or empty: $file" >&2
    exit 1
  fi
done

escaped_expected="${expected//./\\.}"

if ! grep -Eq "Current release: \\*\\*v${escaped_expected}\\*\\*" README.md; then
  echo "README.md must state the current release as v${expected}." >&2
  exit 1
fi

if ! grep -Eq "Current release: \\*\\*v${escaped_expected}\\*\\*" ROADMAP.md; then
  echo "ROADMAP.md must state the current release as v${expected}." >&2
  exit 1
fi

echo "Version consistency OK: v$expected"
