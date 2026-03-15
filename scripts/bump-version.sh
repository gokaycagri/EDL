#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/bump-version.sh <new_version>
# Example: ./scripts/bump-version.sh 1.21.0
#
# This script:
# 1. Updates version.py
# 2. Updates README.md badge
# 3. Adds a CHANGELOG.md entry header
# 4. Creates a git commit and tag
# 5. Prints push instructions

if [ $# -ne 1 ]; then
    echo "Usage: $0 <new_version>"
    echo "Example: $0 1.21.0"
    exit 1
fi

NEW_VERSION="$1"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION_FILE="${REPO_ROOT}/threat-feed-aggregator/threat_feed_aggregator/version.py"
README_FILE="${REPO_ROOT}/README.md"
CHANGELOG_FILE="${REPO_ROOT}/CHANGELOG.md"
TODAY=$(date +%Y-%m-%d)

# Validate semver format
if ! printf '%s' "${NEW_VERSION}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "Error: Version must be in semver format (e.g. 1.21.0)"
    exit 1
fi

# Read current version
CURRENT_VERSION=$(python3 -c "
with open('${VERSION_FILE}') as f:
    for line in f:
        if '__version__' in line:
            print(line.split(\"'\")[1])
            break
")
echo "Bumping version: ${CURRENT_VERSION} -> ${NEW_VERSION}"

# 1. Update version.py
printf "__version__ = '%s'\n" "${NEW_VERSION}" > "${VERSION_FILE}"
echo "  Updated: version.py"

# 2. Update README.md badge
sed -i "s/Version-[0-9]*\.[0-9]*\.[0-9]*/Version-${NEW_VERSION}/g" "${README_FILE}"
echo "  Updated: README.md badge"

# 3. Prepend CHANGELOG entry
TEMP_FILE=$(mktemp)
{
    head -1 "${CHANGELOG_FILE}"
    printf '\n## [%s] - %s\n\n### Added\n\n### Fixed\n\n### Changed\n\n' "${NEW_VERSION}" "${TODAY}"
    tail -n +2 "${CHANGELOG_FILE}"
} > "${TEMP_FILE}"
mv "${TEMP_FILE}" "${CHANGELOG_FILE}"
echo "  Updated: CHANGELOG.md"

# 4. Stage, commit, and tag
git -C "${REPO_ROOT}" add "${VERSION_FILE}" "${README_FILE}" "${CHANGELOG_FILE}"
git -C "${REPO_ROOT}" commit -m "release: v${NEW_VERSION}"
git -C "${REPO_ROOT}" tag -a "v${NEW_VERSION}" -m "v${NEW_VERSION}"

echo ""
echo "Done! Version bumped to ${NEW_VERSION}."
echo ""
echo "To publish:"
echo "  git push origin master --tags"
echo ""
echo "This will trigger:"
echo "  1. CI: lint -> test -> docker build and push"
echo "  2. Release: GitHub Release with auto-generated changelog"
