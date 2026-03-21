#!/usr/bin/env bash
set -euo pipefail

# ─── Release script for Cloak ────────────────────────────────────────────────
# Usage: ./scripts/release.sh <patch|minor|major> [commit message]
# Example: ./scripts/release.sh patch "Add cloak export command"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
DIM='\033[2m'
RESET='\033[0m'

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI_TOML="$ROOT/cli/Cargo.toml"
EXT_JSON="$ROOT/extension/package.json"

die() { echo -e "${RED}error:${RESET} $1" >&2; exit 1; }
info() { echo -e "${CYAN}→${RESET} $1"; }
ok() { echo -e "${GREEN}✓${RESET} $1"; }

# ─── Args ─────────────────────────────────────────────────────────────────────

BUMP="${1:-}"
COMMIT_MSG="${2:-}"

[[ "$BUMP" =~ ^(patch|minor|major)$ ]] || die "Usage: $0 <patch|minor|major> [commit message]"

# ─── Read current version ─────────────────────────────────────────────────────

CURRENT=$(grep '^version = ' "$CLI_TOML" | head -1 | sed 's/version = "\(.*\)"/\1/')
[[ -n "$CURRENT" ]] || die "Could not read version from $CLI_TOML"

IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"

case "$BUMP" in
    major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
    minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
    patch) PATCH=$((PATCH + 1)) ;;
esac

NEW="${MAJOR}.${MINOR}.${PATCH}"
TAG="v${NEW}"

info "Bumping ${DIM}${CURRENT}${RESET} → ${GREEN}${NEW}${RESET}"

# ─── Check clean working tree ─────────────────────────────────────────────────

cd "$ROOT"

if ! git diff --quiet HEAD 2>/dev/null; then
    die "Working tree has uncommitted changes. Commit or stash first."
fi

# ─── Check tag doesn't exist ──────────────────────────────────────────────────

if git rev-parse "$TAG" >/dev/null 2>&1; then
    die "Tag $TAG already exists. Delete it first or pick a different version."
fi

# ─── Bump versions ────────────────────────────────────────────────────────────

info "Updating $CLI_TOML"
sed -i '' "s/^version = \"${CURRENT}\"/version = \"${NEW}\"/" "$CLI_TOML"

info "Updating $EXT_JSON"
sed -i '' "s/\"version\": \"${CURRENT}\"/\"version\": \"${NEW}\"/" "$EXT_JSON"

# Regenerate Cargo.lock
info "Regenerating Cargo.lock"
(cd "$ROOT/cli" && cargo generate-lockfile 2>/dev/null)

ok "Versions bumped to ${NEW}"

# ─── Commit ───────────────────────────────────────────────────────────────────

[[ -z "$COMMIT_MSG" ]] && COMMIT_MSG="Release ${TAG}"

git add "$CLI_TOML" "$ROOT/cli/Cargo.lock" "$EXT_JSON"

# Also stage any other tracked changes
STAGED=$(git diff --cached --name-only)
if [[ -z "$STAGED" ]]; then
    die "Nothing to commit after version bump — versions may already be ${NEW}"
fi

info "Committing: ${COMMIT_MSG}"
git commit -m "$COMMIT_MSG"
ok "Committed"

# ─── Tag ──────────────────────────────────────────────────────────────────────

info "Tagging ${TAG}"
git tag "$TAG"
ok "Tagged ${TAG}"

# ─── Push ─────────────────────────────────────────────────────────────────────

info "Pushing main + tag"
git push origin main
git push origin "$TAG"
ok "Pushed"

# ─── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}Release ${TAG} triggered.${RESET}"
echo -e "${DIM}GitHub Actions will build binaries and attach them to the release.${RESET}"
echo ""
echo -e "After CI completes, publish the extension manually:"
echo -e "  cd extension && npm run build && npx vsce package --no-dependencies"
echo -e "  npx vsce publish"
echo -e "  npx ovsx publish *.vsix -p <token>"
