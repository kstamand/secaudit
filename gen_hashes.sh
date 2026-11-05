#!/bin/sh
# gen_hashes.sh - Generate refreshed file_hash assertions for baseline.conf.
# Usage: ./gen_hashes.sh [/path/to/baseline.conf]
#
# This utility only refreshes existing check=file_hash assertions in the
# [integrity] category. It does not add files or modify the baseline.
# Copyright (C) 2026 kstamand
# SPDX-License-Identifier: GPL-3.0-or-later

CONF_FILE="${1:-./baseline.conf}"

if [ ! -f "$CONF_FILE" ] || [ ! -r "$CONF_FILE" ]; then
    printf 'Error: baseline file is missing or unreadable: %s\n' "$CONF_FILE" >&2
    exit 1
fi

# Extract the path of each existing file_hash assertion.
paths="$(awk '
    /^\[integrity\][[:space:]]*$/ { in_integrity = 1; next }
    /^\[/ { in_integrity = 0; next }
    in_integrity && /^[[:space:]]*check=file_hash:/ {
        sub(/^[[:space:]]*check=file_hash:/, "")
        sub(/:.*$/, "")
        print
    }
' "$CONF_FILE")"

if [ -z "$paths" ]; then
    printf 'Error: no file_hash assertions found in [integrity].\n' >&2
    exit 1
fi

# Accumulate the complete result before writing to stdout, so a missing file or
# hash failure cannot leave the user with a misleading partial replacement.
output='# Refreshed file_hash assertions for [integrity].'
count=0
failed=0
while IFS= read -r path; do

    if [ ! -f "$path" ] || [ ! -r "$path" ]; then
        printf 'Error: monitored file is missing or unreadable: %s\n' "$path" >&2
        failed=1
        continue
    fi

    hash_output="$(sha256sum "$path" 2>/dev/null)"
    hash_ret=$?
    hash="${hash_output%% *}"

    case "$hash" in
        *[!0123456789abcdefABCDEF]*|"")
            printf 'Error: unable to calculate SHA-256 for: %s\n' "$path" >&2
            failed=1
            continue
            ;;
    esac
    if [ "$hash_ret" -ne 0 ] || [ "${#hash}" -ne 64 ]; then
        printf 'Error: unable to calculate a valid SHA-256 for: %s\n' "$path" >&2
        failed=1
        continue
    fi

    output="$output
check=file_hash:$path:$hash"
    count=$((count + 1))
done <<EOF_PATHS
$paths
EOF_PATHS

if [ "$failed" -ne 0 ]; then
    printf 'Error: no assertions emitted because one or more hashes could not be generated.\n' >&2
    exit 1
fi

printf '%s\n' "$output"
printf '# Generated %s file_hash assertion(s) from %s\n' "$count" "$CONF_FILE" >&2
exit 0
