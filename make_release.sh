#!/bin/sh
# Build the files for a GitHub release of secaudit, with their SHA256SUMS.
# Runs on the development machine, not the router. Publishes nothing: it prints
# the gh command to run once you have checked dist/v<version>/.
# Usage: ./make_release.sh
# Copyright (C) 2026 kstamand
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
cd "$(dirname "$0")"

FILES="audit_security.sh gen_hashes.sh baseline.conf.example"
version="$(sed -n 's/^SCRIPT_VERSION="\([0-9][0-9.]*\)"$/\1/p' audit_security.sh)"
[ -n "$version" ] || { echo "no SCRIPT_VERSION in audit_security.sh" >&2; exit 1; }
tag="v$version"

if [ "$(git rev-parse --abbrev-ref HEAD)" != "main" ]; then
    echo "releases are cut from main; merge develop into main first" >&2
    exit 1
fi
if [ -n "$(git status --porcelain)" ]; then
    echo "commit or stash your changes first; a release must match a commit" >&2
    exit 1
fi
if ! grep -q "^## $version " CHANGELOG.md || grep -q "^## $version (unreleased)" CHANGELOG.md; then
    echo "CHANGELOG.md needs a dated '## $version (YYYY-MM-DD)' entry" >&2
    exit 1
fi
if git rev-parse -q --verify "refs/tags/$tag" > /dev/null; then
    echo "tag $tag already exists; bump SCRIPT_VERSION for a new release" >&2
    exit 1
fi
for f in $FILES; do
    case "$f" in
        *.sh) shellcheck -s dash "$f" || { echo "shellcheck failed: $f" >&2; exit 1; } ;;
    esac
done

out="dist/$tag"
rm -rf "$out"
mkdir -p "$out"
for f in $FILES; do
    cp "$f" "$out/"
done
chmod 755 "$out/audit_security.sh" "$out/gen_hashes.sh"
if command -v sha256sum > /dev/null; then sum="sha256sum"; else sum="shasum -a 256"; fi
# shellcheck disable=SC2086  # $sum and $FILES split on purpose
(cd "$out" && $sum $FILES > SHA256SUMS)

# Release notes: this version's CHANGELOG entry, without the next heading.
notes="dist/$tag-notes.md"
awk -v h="## $version " 'index($0, h) == 1 { on = 1; next } on && /^## / { exit } on' CHANGELOG.md > "$notes"

printf 'Built %s:\n' "$out"
cat "$out/SHA256SUMS"
cat <<EOF

Check the files and $notes, then tag and publish:
  git tag -a $tag -m "secaudit $version" && git push origin $tag
  gh release create $tag $out/* --title "secaudit $version" --notes-file $notes
EOF
