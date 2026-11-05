#!/bin/sh
# Smoke test for secaudit. Runs on the router against a disposable /tmp copy, with
# email off, and leaves the source install unchanged.
# Works with any valid baseline: each deliberate mismatch is made generically, not
# from one router's values. Checks your [scope] switches off are reported as skipped.
# Usage: sh smoke_test.sh [install-dir]   (default: this script's directory)
# Copyright (C) 2026 kstamand
# SPDX-License-Identifier: GPL-3.0-or-later
LOG_TAG="my_SECAUDIT_SMOKE"
SOURCE_DIR="${1:-$(cd "$(dirname "$0")" && pwd)}"
WORK_DIR="/tmp/secaudit_smoke_$$"
FAILED=0
PASSED=0

pass() { PASSED=$((PASSED + 1)); printf 'PASS: %s\n' "$1"; }
fail() { FAILED=$((FAILED + 1)); printf 'FAIL: %s\n' "$1"; }
check() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (got '$1', expected '$2')"; fi; }

# Print the warn + alert count of one module's summary.
findings() {
    awk -F: -v name="$1-summary" '$1 == name { print $4 + $5 } ' "$WORK_DIR/secaudit.log"
}

# stdin is closed, so a question (e.g. the self-test's firmware offer) fails
# instead of waiting.
run_audit() {
    SECAUDIT_ATTENDED=1 SECAUDIT_NO_MAIL=1 SECAUDIT_LOG_DIR="$WORK_DIR" \
        sh "$WORK_DIR/audit_security.sh" "$@" > "$WORK_DIR/stdout" 2>&1 < /dev/null
}

notify() {
    SECAUDIT_ATTENDED="" SECAUDIT_NO_MAIL=1 SECAUDIT_LOG_DIR="$WORK_DIR/notify" \
        SECAUDIT_REVIEW_JSON="$WORK_DIR/review.json" \
        SECAUDIT_RWATCH_STATE="${SMOKE_RWATCH_STATE:-/tmp/reaper/rwatch.state}" \
        SECAUDIT_RWATCH_WITNESS="$WORK_DIR/rwatch_witness" \
        SECAUDIT_SYSLOG="$WORK_DIR/syslog.log" \
        sh "$WORK_DIR/audit_security.sh" --notify
}

# Lines in the notifier's reported state, excluding its header.
reported() { grep -c -v '^# reported$' "$WORK_DIR/notify/review.state"; }

write_review() {
    printf '{"ok":1,"enabled":1,"armed":1,"ts":%s,"unreviewed":1,"total":1,"truncated":0,"items":[%s],"notices":[],"notices_n":0,"ww":0,"ww_p":""}\n' \
        "$(date +%s)" "$1" > "$WORK_DIR/review.json"
}

# True if the baseline has a [$1] section.
has_section() { grep -qE "^[[:space:]]*\[$1\][[:space:]]*\$" "$SOURCE_DIR/baseline.conf"; }

# Change the baseline with awk program $2 and expect a finding from module $1.
# The program sees each line and prints the result; it is never router-specific.
expect_finding() {
    if ! has_section "$1" && [ "$1" != "reaper" ]; then
        printf 'SKIP: %s (no [%s] section in this baseline)\n' "$1" "$1"
        return
    fi
    awk "$2" "$SOURCE_DIR/baseline.conf" > "$WORK_DIR/baseline.conf"
    if cmp -s "$SOURCE_DIR/baseline.conf" "$WORK_DIR/baseline.conf"; then
        fail "$1: the mismatch could not be made in this baseline"
        return
    fi

    run_audit --module "$1"
    if [ "$1" = "authentication" ] && ! grep -q '^authentication-detail|' "$WORK_DIR/secaudit.log"; then
        printf 'SKIP: authentication (no admin logins in the router log to test with)\n'
        return
    fi
    if [ "$(findings "$1")" -ge 1 ] 2>/dev/null; then
        pass "$1 reports a deliberate mismatch"
    else
        fail "$1 reported no finding for a deliberate mismatch"
    fi
}

trap 'rm -rf "$WORK_DIR"' 0
trap 'exit 1' 1 2 15

umask 077
mkdir -p "$WORK_DIR/notify" || exit 1
cp "$SOURCE_DIR/audit_security.sh" "$SOURCE_DIR/baseline.conf" "$WORK_DIR/" || exit 1

# Known-good run: every module reports, and every check is accounted for.
MODULES="$(sed -n 's/^MODULES="\(.*\)"$/\1/p' "$WORK_DIR/audit_security.sh")"
run_audit --run-all
check "$?" 0 "known-good --run-all exits 0"

for module in $MODULES; do
    summary="$(grep "^$module-summary:" "$WORK_DIR/secaudit.log")"
    if [ -n "$summary" ]; then
        pass "$module wrote a summary"
    elif grep -qx "$module-skipped" "$WORK_DIR/secaudit.log"; then
        pass "$module is skipped by [scope] and reported as skipped"
    else
        fail "$module wrote no summary"
    fi
done

check "$(awk -F: '/-summary:/ && $2 != $3 + $4 + $5 + $6 { print }' "$WORK_DIR/secaudit.log")" "" \
    "summary totals add up"

# One deliberate mismatch per module, made the same way for any baseline:
#   authentication  only 192.0.2.1 (a documentation address) may log in
#   configuration   the first nvram value expected becomes "smoke_<value>"
#   firewall        a rule that cannot exist is expected
#   integrity       every file fingerprint becomes 64 zeros
#   listeners       no port is allowed, so any listening port is a finding
#   processes       programs may only run from /smoke
#   segmentation    a bridge br99 is expected
#   reaper          the firmware is expected to be "smoke_firmware"
expect_finding authentication '
    /^check=auth_source:/ { next }
    { print }
    /^[[:space:]]*\[authentication\][[:space:]]*$/ { print "check=auth_source:192.0.2.1" }'
expect_finding configuration '
    /^check=nvram:/ && !done { sub(/^check=nvram:[^:]*:/, "&smoke_"); done = 1 }
    { print }'
expect_finding firewall '
    /^check=rule:/ { next }
    { print }
    /^[[:space:]]*\[firewall\][[:space:]]*$/ { print "check=rule:OUTPUT -o br99 -j DROP:present" }'
# shellcheck disable=SC2016  # an awk program, not shell
expect_finding integrity '
    BEGIN { for (i = 0; i < 64; i++) zero = zero "0" }
    /^check=file_hash:/ { sub(/[[:space:]]+#.*$/, ""); n = split($0, f, ":"); f[3] = zero; line = f[1]
                          for (i = 2; i <= n; i++) line = line ":" f[i]; $0 = line }
    { print }'
expect_finding listeners '
    /^check=allowed_port:/ { next }
    { print }'
expect_finding processes '
    /^check=exec_origin:/ { next }
    { print }
    /^[[:space:]]*\[processes\][[:space:]]*$/ { print "check=exec_origin:/smoke" }'
expect_finding segmentation '
    { print }
    /^[[:space:]]*\[segmentation\][[:space:]]*$/ { print "check=bridge:br99:present" }'
expect_finding reaper '
    /^check=firmware:/ { next }
    { print }
    /^[[:space:]]*\[reaper\][[:space:]]*$/ { print "check=firmware:smoke_firmware"; seen = 1 }
    END { if (!seen) print "\n[reaper]\ndefault_criticality=warn\ncheck=firmware:smoke_firmware" }'

# The firmware self-test passes on the firmware the baseline was verified on.
cp "$SOURCE_DIR/baseline.conf" "$WORK_DIR/baseline.conf"
run_audit --selftest
check "$?" 0 "--selftest exits 0"

# An invalid baseline stops the audit before any module runs.
{ cat "$SOURCE_DIR/baseline.conf"; echo "check=bogus:x:y"; } > "$WORK_DIR/baseline.conf"
run_audit --run-all
check "$?" 1 "invalid baseline exits 1"
check "$(grep -c -- '-summary:' "$WORK_DIR/secaudit.log")" 0 "invalid baseline runs no modules"
cp "$SOURCE_DIR/baseline.conf" "$WORK_DIR/baseline.conf"

# Notifier: one alert per change, none on acceptance, and alerts on a bad report.
item='{"t":"S","k":"/jffs/scripts/smoke","st":"changed","v":"abc"}'
write_review "$item"
notify
check "$(reported)" 1 "notifier records a change"
check "$(wc -l < "$WORK_DIR/notify/review_mail.log" | tr -d ' ')" 1 "notifier reports the change"

write_review ""
notify
check "$(reported)" 0 "notifier clears an accepted change"

printf 'not json\n' > "$WORK_DIR/review.json"
notify
check "$(grep -c 'could not be read' "$WORK_DIR/notify/review_mail.log")" 1 "notifier alerts on an unreadable report"

# Reaper: a failing watchdog is an alert, and the watchdog notifier reports the
# failure and the recovery once each. Both are skipped during the boot grace.
if [ "$(cut -d. -f1 /proc/uptime)" -ge 900 ]; then
    printf 'FAIL 0 3\n' > "$WORK_DIR/rwatch.state"
    : > "$WORK_DIR/syslog.log"

    export SECAUDIT_RWATCH_STATE="$WORK_DIR/rwatch.state"
    run_audit --module reaper
    unset SECAUDIT_RWATCH_STATE
    if [ "$(findings reaper)" -ge 1 ] 2>/dev/null; then
        pass "reaper reports a failing watchdog"
    else
        fail "reaper reported no finding for a failing watchdog"
    fi

    SMOKE_RWATCH_STATE="$WORK_DIR/rwatch.state"
    notify
    check "$(grep -c '^rwatch failure' "$WORK_DIR/notify/watch_mail.log")" 1 "watch notifier reports a failure"
    notify
    check "$(cat "$WORK_DIR/notify/watch.rwatch")" "FAIL 0" "watch notifier records the failure once"

    printf 'OK\n' > "$WORK_DIR/rwatch.state"
    notify
    check "$(grep -c '^rwatch recovered' "$WORK_DIR/notify/watch_mail.log")" 1 "watch notifier reports a recovery"
    SMOKE_RWATCH_STATE=""
else
    printf 'SKIP: reaper checks (uptime under 900s boot grace)\n'
fi

printf '\n%s passed, %s failed\n' "$PASSED" "$FAILED"
logger -t "$LOG_TAG" "$PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
