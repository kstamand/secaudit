#!/bin/sh
# Addon-management test for secaudit: install, schedule, menu, update, uninstall.
# Runs on the router entirely under /tmp. cru is a stub, and services-start and
# profile.add are /tmp copies, so the real schedule and files are never touched.
# Usage: sh addon_test.sh <dir holding audit_security.sh, gen_hashes.sh,
#                          baseline.conf.example and a ready baseline.conf>
# Copyright (C) 2026 kstamand
# SPDX-License-Identifier: GPL-3.0-or-later
LOG_TAG="my_SECAUDIT_ADDON_TEST"
SRC="${1:?usage: sh addon_test.sh <source-dir>}"
T="/tmp/secaudit_addon_test_$$"
FAILED=0
PASSED=0

# Menu output without colour codes.
ESC="$(printf '\033')"
plain() { sed "s/${ESC}\[[0-9;]*m//g"; }

pass() { PASSED=$((PASSED + 1)); printf 'PASS: %s\n' "$1"; }
fail() { FAILED=$((FAILED + 1)); printf 'FAIL: %s\n' "$1"; }
check() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (got '$1', expected '$2')"; fi; }

# Also remove the /tmp run directories the test copies create.
trap 'rm -rf "$T" /tmp/secaudit_tmp_secaudit_addon_test_$$_*' 0
trap 'exit 1' 1 2 15

mkdir -p "$T/repo" "$T/bin" || exit 1
cp "$SRC/audit_security.sh" "$SRC/gen_hashes.sh" "$SRC/baseline.conf.example" "$T/repo/" || exit 1
# The test "release": its files and their SHA256SUMS, as make_release.sh builds.
sums() { (cd "$T/repo" && sha256sum audit_security.sh gen_hashes.sh baseline.conf.example > SHA256SUMS); }
sums
printf '#!/bin/sh\n\n# Cru jobs\ncru a other "0 2 * * * /bin/true"\n' > "$T/services-start"
printf '# profile.add\nalias ll="ls -la"\n' > "$T/profile.add"

# Stub cru: jobs are lines "<schedule> <command> #<id>#" in $T/cron.
cat > "$T/bin/cru" <<STUB
#!/bin/sh
f="$T/cron"
touch "\$f"
case "\$1" in
    l) cat "\$f" ;;
    a) id=\$2; shift 2; grep -v "#\$id#\\\$" "\$f" > "\$f.t"; printf '%s #%s#\n' "\$*" "\$id" >> "\$f.t"; mv "\$f.t" "\$f" ;;
    d) grep -v "#\$2#\\\$" "\$f" > "\$f.t"; mv "\$f.t" "\$f" ;;
esac
STUB
# shellcheck disable=SC2016  # $1 belongs to the stub editor
printf '#!/bin/sh\necho "check=bogus:x" >> "$1"\n' > "$T/bin/editor_bad"
chmod +x "$T/bin/cru" "$T/bin/editor_bad"
# The self-test expects Reaper's own watchdog job.
"$T/bin/cru" a rwatch "*/5 * * * * /bin/true"

export PATH="$T/bin:$PATH" SECAUDIT_ATTENDED=1 SECAUDIT_NO_MAIL=1 \
    SECAUDIT_ADDON_DIR="$T/addon" SECAUDIT_REPO_URL="file://$T/repo" \
    SECAUDIT_SERVICES_START="$T/services-start" SECAUDIT_PROFILE_ADD="$T/profile.add" \
    SECAUDIT_EMAIL_LIB_DIR="$T/shared-libs" SECAUDIT_AMTM_EMAIL_CONF="$T/amtm/mail/email.conf" \
    SECAUDIT_EMAIL_LIB_URL="file://$T/emaillib/CustomEMailFunctions.lib.sh"
# A stub email library at the "download" address: it records each subject sent.
mkdir -p "$T/emaillib"
email_lib() {
    # shellcheck disable=SC2016  # $1 belongs to the stub library
    printf '#!/bin/sh\nCEM_LIB_VERSION="v%s"\n_SendEMailNotification_CEM_() { printf "%%s\\n" "$1" >> %s/sent; }\n' \
        "$1" "$T" > "$T/emaillib/CustomEMailFunctions.lib.sh"
}
email_lib 1.0.0
S="$T/addon/audit_security.sh"
HOOK="$S --startup & # secaudit"
ALIAS="alias secaudit=\"sh $S\" # secaudit"
cp "$T/services-start" "$T/services-start.orig"
cp "$T/profile.add" "$T/profile.add.orig"

# Install, and reinstall over an edited baseline.
printf 'n\n' | sh "$T/repo/audit_security.sh" --install > "$T/out" 2>&1
check "$?" 0 "install exits 0"
for f in audit_security.sh gen_hashes.sh baseline.conf.example baseline.conf; do
    if [ -f "$T/addon/$f" ]; then pass "install created $f"; else fail "install did not create $f"; fi
done
if [ -x "$S" ]; then pass "installed script is executable"; else fail "installed script is not executable"; fi
check "$(grep -cxF "$ALIAS" "$T/profile.add")" 1 "install added the alias once"
check "$(grep -c 'audit_security' "$T/cron")" 0 "install did not schedule anything"

echo "# kept" >> "$T/addon/baseline.conf"
printf 'n\n' | sh "$T/repo/audit_security.sh" --install > "$T/out" 2>&1
check "$(tail -n 1 "$T/addon/baseline.conf")" "# kept" "reinstall kept baseline.conf"
check "$(grep -cxF "$ALIAS" "$T/profile.add")" 1 "reinstall did not duplicate the alias"

# Schedule refusals.
sh "$S" --schedule on > "$T/out" 2>&1
check "$?" 1 "schedule on refused with REPLACE values"

cp "$SRC/baseline.conf" "$T/addon/baseline.conf"
menu_schedule() { printf 'e\n' | sh "$S" 2>&1 | plain | grep -e 'Schedule:' -e '  6  '; }

# A hand-written schedule for this copy, as the old README set up: shown as
# "set up by hand"; "n" changes nothing; "y" replaces it with the managed one.
HAND="cru a SecAudit \"0 1 * * * $S --run-all\""
printf '%s\n' "$HAND" >> "$T/services-start"
"$T/bin/cru" a SecAudit "0 1 * * * $S --run-all"
check "$(menu_schedule)" "  Schedule:     on (set up by hand)
  6  Let secaudit manage the schedule" "menu shows a hand-written schedule"
printf 'n\n' | sh "$S" --schedule on > "$T/out" 2>&1
check "$?" 1 "take-over declined exits 1"
check "$(grep -cxF "$HAND" "$T/services-start"; grep -c '#SecAudit#' "$T/cron")" "1
1" "declined take-over changed nothing"
printf 'y\n' | sh "$S" --schedule on > "$T/out" 2>&1
check "$?" 0 "take-over exits 0"
check "$(grep -cxF "$HAND" "$T/services-start"; grep -c '#SecAudit#' "$T/cron")" "0
0" "take-over removed the hand-written line and job"
check "$(grep -cxF "$HOOK" "$T/services-start"; grep -c 'secaudit_' "$T/cron")" "1
2" "take-over added the managed schedule"
sh "$S" --schedule off > "$T/out" 2>&1

# A take-over that would break services-start is undone.
printf 'if true; then\n    %s\nfi\n' "$HAND" >> "$T/services-start"
cp "$T/services-start" "$T/services-start.block"
printf 'y\n' | sh "$S" --schedule on > "$T/out" 2>&1
check "$?" 1 "take-over refused when it would break services-start"
if cmp -s "$T/services-start.block" "$T/services-start"; then
    pass "services-start restored after a refused take-over"
else
    fail "services-start changed after a refused take-over"
fi
cp "$T/services-start.orig" "$T/services-start"

# Another copy's jobs use the same names: shown as that copy's, left alone by
# schedule off, and moved here on "y".
OTHER="/jffs/addons/other/audit_security.sh"
"$T/bin/cru" a secaudit_run "0 3 * * * $OTHER --run-all"
"$T/bin/cru" a secaudit_notify "*/10 * * * * $OTHER --notify"
check "$(menu_schedule)" "  Schedule:     on, runs /jffs/addons/other
  6  Switch the schedule to $T/addon" "menu shows another copy's schedule"
sh "$S" --schedule off > "$T/out" 2>&1
check "$(grep -c "$OTHER" "$T/cron")" 2 "schedule off kept another copy's jobs"
printf 'y\n' | sh "$S" --schedule on > "$T/out" 2>&1
check "$(grep -c "$OTHER" "$T/cron"; grep -c " $S --" "$T/cron")" "0
2" "move replaced the other copy's jobs with this copy's"
sh "$S" --schedule off > "$T/out" 2>&1
check "$(menu_schedule)" "  Schedule:     off
  6  Turn the schedule on" "menu shows the schedule off"

# Schedule on, twice, then --startup after the jobs are gone.
sh "$S" --schedule on > "$T/out" 2>&1
check "$?" 0 "schedule on exits 0"
sh "$S" --schedule on > "$T/out" 2>&1
check "$(grep -cxF "$HOOK" "$T/services-start")" 1 "services-start has the hook once"
check "$(grep -c 'secaudit_' "$T/cron")" 2 "two cron jobs, no duplicates"
check "$(grep -c '#other#' "$T/cron"; grep -c 'cru a other' "$T/services-start")" "0
1" "other services-start lines untouched"

"$T/bin/cru" d secaudit_run
"$T/bin/cru" d secaudit_notify
SECAUDIT_ATTENDED='' sh "$S" --startup < /dev/null
check "$?" 0 "--startup exits 0"
check "$(grep -c 'secaudit_' "$T/cron")" 2 "--startup re-added both jobs"
check "$(grep -c -e "^0 3 \* \* \* $S --run-all #" -e "^\*/10 \* \* \* \* $S --notify #" "$T/cron")" 2 \
    "default times are 03:00 and every 10 minutes"

# Schedule times: saved, applied at once while on, and shown in the menu.
printf '7\n1\n15\n\ne\n' | sh "$S" > "$T/out" 2>&1
check "$(grep -v '^#' "$T/addon/settings.conf")" "RUN_HOUR=1
NOTIFY_MINUTES=15" "change times saved settings.conf"
check "$(grep -c -e "^0 1 \* \* \* $S --run-all #" -e "^\*/15 \* \* \* \* $S --notify #" "$T/cron")" 2 \
    "change times rescheduled the jobs"
check "$(printf 'e\n' | sh "$S" 2>&1 | plain | grep 'Schedule:')" \
    "  Schedule:     on (audit 01:00, alerts every 15 min)" "menu shows the schedule times"

# Bad answers are asked again; 60 minutes is "0 * * * *"; Enter keeps a value.
printf '7\n25\nx\n02\n7\n60\n\ne\n' | sh "$S" > "$T/out" 2>&1
check "$(grep -c 'Please type a whole hour' "$T/out"; grep -c 'Please choose 5, 10' "$T/out")" "2
1" "bad answers are asked again"
check "$(grep -c -e "^0 2 \* \* \* $S --run-all #" -e "^0 \* \* \* \* $S --notify #" "$T/cron")" 2 \
    "hour 02 and 60 minutes scheduled"
printf '7\n\n\n\ne\n' | sh "$S" 2>&1 | plain > "$T/out"
if grep -q 'Nothing was changed' "$T/out"; then pass "Enter keeps both times"; else fail "Enter did not keep both times"; fi

# --startup uses the saved times; a damaged settings.conf falls back to defaults.
"$T/bin/cru" d secaudit_run
SECAUDIT_ATTENDED='' sh "$S" --startup < /dev/null
check "$(grep -c "^0 2 \* \* \* $S --run-all #" "$T/cron")" 1 "--startup used the saved hour"
cp "$T/addon/settings.conf" "$T/settings.good"
printf 'RUN_HOUR=99\nNOTIFY_MINUTES=7\nRUN_HOUR=4; echo injected\n' > "$T/addon/settings.conf"
SECAUDIT_ATTENDED='' sh "$S" --startup < /dev/null
check "$(grep -c -e "^0 3 \* \* \* $S --run-all #" -e "^\*/10 \* \* \* \* $S --notify #" "$T/cron")" 2 \
    "a damaged settings.conf falls back to the defaults"
cp "$T/settings.good" "$T/addon/settings.conf"

# Menu.
printf 'e\n' | sh "$S" 2>&1 | plain > "$T/out"
if grep -q 'Baseline:     ready' "$T/out" && grep -q 'Schedule:     on' "$T/out"; then
    pass "menu shows baseline ready and schedule on"
else
    fail "menu status is wrong"
fi
printf '2\n7\n\ne\n' | sh "$S" > "$T/out" 2>&1
if grep -q 'secaudit running the segmentation check' "$T/out"; then
    pass "menu runs one check"
else
    fail "menu did not run the segmentation check"
fi
EDITOR=editor_bad sh -c "printf '5\n\ne\n' | sh '$S'" > "$T/out" 2>&1
if grep -q 'Baseline validation failed' "$T/out"; then
    pass "edit baseline reports a broken baseline"
else
    fail "edit baseline did not report a broken baseline"
fi
sed -i '/^check=bogus:x$/d' "$T/addon/baseline.conf"

# Email: amtm settings first, then the library, offered (never fetched unattended).
menu_email() { printf 'e\n' | sh "$S" 2>&1 | plain | grep 'Email:'; }
LIB="$T/shared-libs/CustomEMailFunctions.lib.sh"
check "$(menu_email)" "  Email:        not set up in amtm (results show here only)" "menu: email not set up in amtm"
printf '8\n\ne\n' | sh "$S" 2>&1 | plain > "$T/out"
if grep -q "Email isn't set up in amtm yet" "$T/out" && [ ! -f "$LIB" ]; then
    pass "test email without amtm points to amtm em"
else
    fail "test email without amtm did not point to amtm em"
fi
mkdir -p "$T/amtm/mail"
: > "$T/amtm/mail/email.conf"
: > "$T/amtm/mail/emailpw.enc"
check "$(menu_email)" "  Email:        library missing (option 8 sets it up)" "menu: email library missing"
printf '8\nn\n\ne\n' | sh "$S" > "$T/out" 2>&1
if [ ! -f "$LIB" ]; then pass "declining leaves the library uninstalled"; else fail "library installed after declining"; fi
printf '8\n\n\ne\n' | SECAUDIT_NO_MAIL='' sh "$S" 2>&1 | plain > "$T/out"
if [ -x "$LIB" ] && grep -q '^SecAudit test email' "$T/sent" 2>/dev/null && grep -q 'Sent. Check your inbox' "$T/out"; then
    pass "Enter installs the library and sends a test email"
else
    fail "library install or test email failed"
fi
check "$(menu_email)" "  Email:        set up" "menu: email set up"

# A download that isn't the library is rejected.
rm -f "$LIB"
printf 'not a script\n' > "$T/emaillib/CustomEMailFunctions.lib.sh"
printf '8\ny\n\ne\n' | sh "$S" 2>&1 | plain > "$T/out"
if grep -q 'does not look right' "$T/out" && [ ! -f "$LIB" ]; then
    pass "a bad library download is rejected"
else
    fail "a bad library download was not rejected"
fi
email_lib 1.0.0
printf '8\ny\n\ne\n' | sh "$S" > "$T/out" 2>&1

# Check for updates offers a newer library.
email_lib 1.0.1
printf 'y\n' | sh "$S" --update > "$T/out" 2>&1
check "$(sed -n 's/^CEM_LIB_VERSION="v\(.*\)"$/\1/p' "$LIB")" "1.0.1" "update installs a newer email library"
printf 'n\n' | sh "$S" --update 2>&1 | plain > "$T/out"
if grep -q 'email library 1.0.1 is up to date' "$T/out"; then pass "an up-to-date library is reported"; else fail "library up-to-date not reported"; fi

# An unattended run never downloads the library.
rm -f "$LIB"
SECAUDIT_ATTENDED='' sh "$S" --notify < /dev/null > /dev/null 2>&1
if [ ! -f "$LIB" ]; then pass "unattended runs never download the library"; else fail "an unattended run downloaded the library"; fi

# A fresh install offers the library when amtm email is set up.
printf 'y\nn\n' | SECAUDIT_ADDON_DIR="$T/addon2" SECAUDIT_PROFILE_ADD="$T/profile2" \
    sh "$T/repo/audit_security.sh" --install 2>&1 | plain > "$T/out"
if grep -q 'Email library 1.0.1 installed' "$T/out" && [ -x "$LIB" ]; then
    pass "install offers and installs the email library"
else
    fail "install did not offer the email library"
fi

# Firmware change: the menu flags it; a clean self-test offers to accept it.
FW_NOW="$(nvram get innerver)"
cp "$T/addon/baseline.conf" "$T/baseline.fw"
sed -i 's/^check=firmware:.*/check=firmware:Old_firmware_1.0/' "$T/addon/baseline.conf"
if printf 'e\n' | sh "$S" 2>&1 | plain | grep -q 'Baseline:     ready, but the firmware changed'; then
    pass "menu flags a firmware change"
else
    fail "menu did not flag a firmware change"
fi
printf '4\nn\n\ne\n' | sh "$S" > "$T/out" 2>&1
check "$(grep '^check=firmware:' "$T/addon/baseline.conf")" "check=firmware:Old_firmware_1.0" \
    "declining keeps the old firmware"
printf '4\ny\n\ne\n' | sh "$S" > "$T/out" 2>&1
check "$(grep '^check=firmware:' "$T/addon/baseline.conf")" "check=firmware:$FW_NOW" \
    "accepting sets the current firmware"
if cmp -s "$T/baseline.fw" "$T/addon/baseline.conf"; then
    pass "accepting changed only the firmware line"
else
    fail "accepting changed more than the firmware line"
fi
if printf 'e\n' | sh "$S" 2>&1 | plain | grep -q 'Baseline:     ready$'; then
    pass "menu shows the baseline ready again"
else
    fail "menu still flags the firmware"
fi

# Scope: [scope] skip= lines, validation, reports, --module, and the menu screen.
B="$T/addon/baseline.conf"
cp "$B" "$T/baseline.scope"
audit() { SECAUDIT_LOG_DIR="$T/log" sh "$S" "$@" 2>&1 | plain; }
valid() { if audit --module segmentation | grep -q 'Baseline validation failed'; then echo invalid; else echo valid; fi; }
# Put lines $2 into the [scope] section of a copy of baseline $1 (adds the section if absent).
scope_into() {
    if grep -q '^\[scope\]' "$1"; then
        awk -v add="$2" '{ print } /^\[scope\]/ { print add }' "$1" > "$B"
    else
        cp "$1" "$B"; printf '\n[scope]\n%s\n' "$2" >> "$B"
    fi
}
with_scope() { scope_into "$T/baseline.scope" "$1"; }

with_scope "skip=firewall
skip=reaper"
audit --run-all > "$T/out"
if grep -q 'secaudit running a full audit' "$T/out"; then pass "full audit start line"; else fail "full audit start line missing"; fi
check "$(grep -c 'skipped (\[scope\] in baseline.conf)' "$T/out")" 2 "full audit lists the skipped checks"
if grep -q '6 of 8 checks ran; \[scope\] in baseline.conf skips: firewall reaper' "$T/out"; then
    pass "full audit states reduced coverage"
else
    fail "full audit did not state reduced coverage"
fi
if grep -q "Reaper's own health" "$T/out"; then pass "skipping reaper is called out"; else fail "skipping reaper not called out"; fi
check "$(grep -c '^firewall-summary:' "$T/log/secaudit.log")" 0 "a skipped check does not run"
audit --module firewall > "$T/out"
if grep -q 'running it because you asked for it by name' "$T/out" && grep -q '^firewall-summary:' "$T/log/secaudit.log"; then
    pass "--module runs a skipped check, with a note"
else
    fail "--module did not run a skipped check"
fi

# A skipped check's section may be left out; otherwise it is required.
awk '/^\[firewall\]/ { drop = 1; next } /^\[/ { drop = 0 } !drop' "$T/baseline.scope" > "$T/baseline.nofw"
cp "$T/baseline.nofw" "$B"
check "$(valid)" invalid "a missing section is invalid when not skipped"
scope_into "$T/baseline.nofw" "skip=firewall"
check "$(valid)" valid "a skipped check's section may be left out"
audit --module firewall > "$T/out"
if grep -q 'has no \[firewall\] section' "$T/out"; then pass "--module refuses a skipped check with no section"; else fail "--module ran a check with no section"; fi

with_scope "skip=firewal"
check "$(valid)" invalid "an unknown skip= is invalid"
with_scope "skip=firewall
skip=firewall"
check "$(valid)" invalid "a duplicate skip= is invalid"
with_scope "check=firmware:x"
check "$(valid)" invalid "a non-skip line in [scope] is invalid"
with_scope "$(for m in authentication configuration firewall integrity listeners processes segmentation reaper; do echo "skip=$m"; done)"
check "$(valid)" invalid "skipping every check is invalid"

# Menu: firewall (3rd) off, then on again; the file ends as it started.
cp "$T/baseline.scope" "$B"
printf '3\n3\n\ne\n' | sh "$S" 2>&1 | plain > "$T/out"
check "$(sed -n '/^\[scope\]/,/^\[/p' "$B" | grep -c '^skip=firewall$')" 1 "menu switched firewall off"
if printf 'e\n' | sh "$S" 2>&1 | plain | grep -q 'Checks:       7 of 8 (off: firewall'; then
    pass "menu shows 7 of 8 checks"
else
    fail "menu does not show the reduced checks"
fi
printf '3\n3\n\ne\n' | sh "$S" > "$T/out" 2>&1
if cmp -s "$T/baseline.scope" "$B"; then pass "menu switched firewall back on, file unchanged"; else fail "baseline differs after off and on"; fi
# Switching on a check with no section offers to copy it from the example.
scope_into "$T/baseline.nofw" "skip=firewall"
printf '3\n3\nn\n\ne\n' | sh "$S" 2>&1 | plain > "$T/out"
if grep -q 'firewall stays off' "$T/out" && grep -q '^skip=firewall$' "$B" && ! grep -q '^\[firewall\]' "$B"; then
    pass "declining the copy leaves the check off"
else
    fail "declining the copy changed the baseline"
fi
printf '3\n3\ny\n\ne\n' | sh "$S" 2>&1 | plain > "$T/out"
copied="$(awk '/^\[firewall\]/ { on = 1 } /^\[/ && !/^\[firewall\]/ { on = 0 } on' "$B")"
example="$(awk '/^\[firewall\]/ { on = 1 } /^\[/ && !/^\[firewall\]/ { on = 0 } on' "$T/addon/baseline.conf.example")"
if grep -q 'Copied the example \[firewall\] section' "$T/out" && [ "$copied" = "$example" ] && ! grep -q '^skip=firewall$' "$B"; then
    pass "accepting copies the example section and switches the check on"
else
    fail "copy from the example did not work"
fi
check "$(valid)" valid "the baseline is valid after the copy"
cp "$T/baseline.scope" "$B"

# Update: up to date, newer, then a broken download.
sh "$S" --update > "$T/out" 2>&1
if grep -q 'is up to date' "$T/out"; then pass "update: up to date"; else fail "update: not reported up to date"; fi
sed -i 's/^SCRIPT_VERSION=".*"$/SCRIPT_VERSION="99.0.0"/' "$T/repo/audit_security.sh"
sums
cp "$T/addon/baseline.conf" "$T/baseline.before"
printf 'y\n' | sh "$S" --update > "$T/out" 2>&1
check "$(sh "$S" --version)" "secaudit 99.0.0" "update installed the newer version"
if cmp -s "$T/baseline.before" "$T/addon/baseline.conf"; then pass "update left baseline.conf alone"; else fail "update changed baseline.conf"; fi
if cmp -s "$T/settings.good" "$T/addon/settings.conf"; then pass "update left settings.conf alone"; else fail "update changed settings.conf"; fi
sed -i 's/^SCRIPT_VERSION=".*"$/SCRIPT_VERSION="99.0.1"/' "$T/repo/audit_security.sh"
cp "$T/repo/gen_hashes.sh" "$T/gen_hashes.good"
printf 'not a script\n' > "$T/repo/gen_hashes.sh"
sums
printf 'y\n' | sh "$S" --update > "$T/out" 2>&1
check "$?" 1 "update rejects a broken download"
check "$(sh "$S" --version)" "secaudit 99.0.0" "rejected update changed nothing"

# Checksums: a file that does not match, or no SHA256SUMS, is rejected.
cp "$T/gen_hashes.good" "$T/repo/gen_hashes.sh"
sums
printf '# tampered\n' >> "$T/repo/baseline.conf.example"
printf 'y\n' | sh "$S" --update > "$T/out" 2>&1
check "$?" 1 "update rejects a file that does not match its checksum"
if grep -q 'does not match its checksum' "$T/out"; then pass "checksum mismatch is reported"; else fail "checksum mismatch not reported"; fi
sums
rm -f "$T/repo/SHA256SUMS"
printf 'y\n' | sh "$S" --update > "$T/out" 2>&1
check "$?" 1 "update rejects a release with no SHA256SUMS"
check "$(sh "$S" --version)" "secaudit 99.0.0" "rejected updates changed nothing"
sums

# Uninstall, keeping the baseline.
printf 'y\nn\n' | sh "$S" --uninstall > "$T/out" 2>&1
check "$?" 0 "uninstall exits 0"
check "$(ls -A "$T/addon")" "baseline.conf
settings.conf" "uninstall kept only baseline.conf and settings.conf"
if cmp -s "$T/services-start.orig" "$T/services-start"; then pass "services-start restored"; else fail "services-start differs from the original"; fi
if cmp -s "$T/profile.add.orig" "$T/profile.add"; then pass "profile.add restored"; else fail "profile.add differs from the original"; fi
check "$(grep -c 'secaudit_' "$T/cron")" 0 "uninstall removed the cron jobs"

# Management commands need a terminal.
SECAUDIT_ATTENDED='' sh "$T/repo/audit_security.sh" --install < /dev/null > /dev/null 2>&1
check "$?" 1 "unattended --install is refused"

printf '\n%d passed, %d failed\n' "$PASSED" "$FAILED"
logger -t "$LOG_TAG" "$PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
