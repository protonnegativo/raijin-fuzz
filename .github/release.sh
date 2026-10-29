#!/usr/bin/env bash
# Tags HEAD with the next release (v0.1.0 when there is none) and creates its GitHub Release.
# Usage: .github/release.sh [patch|minor|major] [base-sha]
# Skips when HEAD already has a tag, or when base-sha is given and the changes since it only touch files
# that are not in the binary (bench/fixtures/, *.md, docs/, .github/). engines.json does release: the
# binary embeds it. Needs GH_TOKEN for gh (with actions: write, to start the binaries workflow).
set -euo pipefail

bump=${1:-patch}
base=${2:-}

if [ -n "$(git tag --points-at HEAD 'v*')" ]; then
  echo "HEAD is already tagged: $(git tag --points-at HEAD 'v*' | tr '\n' ' ')"
  exit 0
fi

if [ -n "$base" ] && git cat-file -e "$base^{commit}" 2>/dev/null; then
  changed=$(git diff --name-only "$base" HEAD | grep -vE '^(bench/fixtures/|docs/|\.github/)|\.md$' || true)
  if [ -z "$changed" ]; then
    echo "no binary change since $base; not releasing"
    exit 0
  fi
fi

last=$(git tag -l 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
if [ -z "$last" ]; then
  next=v0.1.0
else
  IFS=. read -r major minor patch <<<"${last#v}"
  case "$bump" in
    major) next=v$((major + 1)).0.0 ;;
    minor) next=v$major.$((minor + 1)).0 ;;
    patch) next=v$major.$minor.$((patch + 1)) ;;
    *) echo "unknown bump: $bump" >&2; exit 1 ;;
  esac
fi

git config user.name >/dev/null || git config user.name "github-actions[bot]"
git config user.email >/dev/null || git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git tag -a "$next" -m "$next"
git push origin "$next"
gh release create "$next" --generate-notes --title "$next"
# A tag and a Release created with GITHUB_TOKEN do not start other workflows: dispatch the binaries one.
gh workflow run goreleaser.yml -f tag="$next"
echo "released $next"
