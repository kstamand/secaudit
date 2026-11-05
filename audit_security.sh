#!/bin/sh
## ==================================================================================
# Name: audit_security.sh
# Copyright (C) 2026 kstamand
# SPDX-License-Identifier: GPL-3.0-or-later
# Purpose: Local, read-only security audit of a Reaper router, covering what
#          Reaper's Security Review does not - unattended email alerts (cron job), and
#          additional checks you add (using supported modules + grammar).
# Layout:  baseline parsing, reporting, one audit_<module>() per module, mainline.
# Design:  Reaper watches its own posture; this script checks that Reaper is
#          healthy and adds the checks Reaper does not make.
#   Reaper built-in (consumed, not re-implemented; see [reaper] module + --notify):
#           - Security Review (rwatch_review, review.json): drift on /jffs and the
#             exposure/protection nvram switches (RV_NV_S in rc/rwatch.c).
#             Do NOT add those back to baseline.conf [configuration].
#           - rwatch watchdog (rwatch_enable, cru #rwatch#, rwatch.state, CRITICAL
#             syslog lines). Not evaluable for 900s after boot (HEALGRACE).
#           - Firewall witnesses (reaper_fwsim, fwstatus.json, rwatch_witness):
#             INPUT/FORWARD hooks (F8i/F8f), guest/VLAN zone isolation -> br0 (F2.*).
#   My specifics (baseline.conf; things Reaper does not cover):
#           - [configuration] my service/hardening choices (USB apps, Wi-Fi auth,
#             DNS Director/DNSSEC/DoT, SSH key-only, WPS/SNMP/IPv6 off).
#           - [authentication] admin logins only from approved IPs;
#             [processes] executables only from firmware roots.
#           - [listeners] approved ports/scopes; [segmentation] bridges + members;
#             [integrity] /etc/passwd hash, /tmp + /var forbidden-file sweep;
#             [firewall] OUTPUT REAPER_HOOK_O (no witness covers OUTPUT).
#   Rule of thumb: if Reaper already watches it, check it in [reaper], not in
#   baseline.conf. All state lives in /tmp, so this script causes no Review drift.
# Manage:  no arguments at a terminal opens a menu (install, update, schedule,
#          edit baseline, uninstall); see "Addon management" below.
# Run:     cron --run-all nightly (emails only on findings or errors);
#          cron --notify every ~10 min (emails each Reaper change once).
#          Interactive (tty) runs print and never email or commit state.
#          After any firmware upgrade: --selftest, then docs §13 (see [reaper]).
# Exit:    0 = ran cleanly (findings alone do not fail a run); 1 = bad arguments,
#          setup or module failure, or (--notify only) a failed email.
# Test:    SECAUDIT_NO_MAIL=1 suppresses email; SECAUDIT_ATTENDED=1 forces
#          interactive mode over ssh; SECAUDIT_* paths below redirect inputs.
# ====================================================================================
# shellcheck disable=SC1090,SC2059,SC3043

#set -x

# ----- Version: bump on every release and add a CHANGELOG.md entry.
SCRIPT_VERSION="0.1.0"

# ----- Script directories and files
SCRIPT_NAME=$(basename "$0")
# Everything is relative to this script, so a test install never touches production.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
BASELINE_CONF="${SCRIPT_DIR}/baseline.conf"
# Run output stays in /tmp, one directory per install, so it causes no /jffs drift
# in Reaper's Security Review.
LOG_DIR="${SECAUDIT_LOG_DIR:-/tmp/secaudit$(printf '%s' "$SCRIPT_DIR" | tr '/' '_')}"
LOG_FILE="$LOG_DIR/secaudit.log"
LOG_TAG="my_SECAUDIT"
MAIL_LOG="$LOG_DIR/secaudit_mail.log"
PARSED_BASELINE="$LOG_DIR/baseline.parsed"

# ----- Reaper internals (UNDOCUMENTED: re-verify after every firmware update;
#       see docs "Before updating Reaper"). If a path or format moves, the
#       [reaper] module and --notify alert as unreadable rather than go silent.
#       selftest() checks each of these; when you add a Reaper path, nvram key
#       or field here, add a matching selftest() check and a docs §13 bullet.
# Security Review's report, and what the notifier has already reported.
REVIEW_JSON="${SECAUDIT_REVIEW_JSON:-/tmp/reaper/review.json}"
REVIEW_STATE="$LOG_DIR/review.state"
# Login lines already reported; committed only after a run's notification succeeds.
AUTH_SEEN="$LOG_DIR/auth.seen"
# Reaper's watchdog state, firewall witnesses and rules-candidate marker.
RWATCH_STATE="${SECAUDIT_RWATCH_STATE:-/tmp/reaper/rwatch.state}"
FWSTATUS_JSON="${SECAUDIT_FWSTATUS_JSON:-/tmp/reaper/fwstatus.json}"
FW_ARMED="/tmp/reaper_fw/armed"
# rwatch's current red-witness list (absent when none) and the syslog it writes to.
RWATCH_WITNESS="${SECAUDIT_RWATCH_WITNESS:-/tmp/reaper/rwatch_witness}"
SYSLOG_FILE="${SECAUDIT_SYSLOG:-/jffs/syslog.log}"
# What the watchdog notifier last reported; committed only after its email went out.
WATCH_RWATCH="$LOG_DIR/watch.rwatch"
WATCH_RULES="$LOG_DIR/watch.rules"
WATCH_CRIT_LINE="$LOG_DIR/watch.crit_line"
WATCH_CRIT_ON="$LOG_DIR/watch.crit_on"
# rwatch skips its checks for this long after boot (HEALGRACE in rc/rwatch.c).
REAPER_GRACE_SECONDS=900

# ----- Audit result counters
AUDIT_EXECUTION_FAILED=0

# ----- ANSI display colors
RED_TEXT='\033[31m'
GREEN_TEXT='\033[32m'
YELLOW_TEXT='\033[33m'
CYAN_TEXT='\033[36m'
RESET='\033[0m'
# Muted 256-colour palette for the menu (attended only).
MENU_RULE='\033[38;5;60m'   # slate: header and footer rules
MENU_TITLE='\033[38;5;110m' # soft blue: title and option keys
MENU_LABEL='\033[38;5;245m' # grey: status labels
MENU_GOOD='\033[38;5;108m'  # sage green
MENU_WARN='\033[38;5;180m'  # sand
MENU_BAD='\033[38;5;174m'   # dusty rose

# ----- shared email notification library
# Martinski W.'s CustomEMailFunctions (GPL-3.0), shared by many Merlin addons. It
# sends mail with amtm's email settings (amtm, then em). If it is missing, audits
# still run but nothing is emailed (logged via logger -t $LOG_TAG). SecAudit
# downloads it only when someone at the terminal agrees (install, menu, update),
# never in an unattended run.
EMAIL_LIB_DIR="${SECAUDIT_EMAIL_LIB_DIR:-/jffs/addons/shared-libs}"
EMAIL_LIB="$EMAIL_LIB_DIR/CustomEMailFunctions.lib.sh"
EMAIL_LIB_URL="${SECAUDIT_EMAIL_LIB_URL:-https://raw.githubusercontent.com/Martinski4GitHub/CustomMiscUtils/master/EMail/CustomEMailFunctions.lib.sh}"
AMTM_EMAIL_CONF="${SECAUDIT_AMTM_EMAIL_CONF:-/jffs/addons/amtm/mail/email.conf}"

# ----- Addon management (menu, --install, --update, --schedule, --uninstall)
# --install puts the addon here; --update and --uninstall act on the running copy.
ADDON_DIR="${SECAUDIT_ADDON_DIR:-/jffs/addons/secaudit}"
# Downloads come from the latest GitHub release, whose files include SHA256SUMS
# (made by make_release.sh). The repo must be public for other routers to reach.
REPO_URL="${SECAUDIT_REPO_URL:-https://github.com/kstamand/secaudit/releases/latest/download}"
CHECKSUMS="SHA256SUMS"
ADDON_FILES="audit_security.sh gen_hashes.sh baseline.conf.example"
# The schedule lives in one marked line of services-start, which re-adds the
# cron jobs after every reboot (--startup). Other lines are edited only to take
# over an existing secaudit schedule, after the user agrees (take_over_schedule).
SERVICES_START="${SECAUDIT_SERVICES_START:-/jffs/scripts/services-start}"
PROFILE_ADD="${SECAUDIT_PROFILE_ADD:-/jffs/configs/profile.add}"
# Schedule times: the menu's "Change the schedule times" saves them here.
# Updates never touch this file. Defaults apply if it is missing or invalid.
SETTINGS_CONF="${SCRIPT_DIR}/settings.conf"
DEFAULT_RUN_HOUR=3
DEFAULT_NOTIFY_MINUTES=10
NOTIFY_CHOICES="5 10 15 30 60"   # keep in step with change_schedule_times()

# ----- audit modules, in run and report order
# Adding a module: add its name here, write audit_<name>(), teach
# validate_baseline() its check types, add a [<name>] section to
# baseline.conf, and update docs §2 and §8.
MODULES="authentication configuration firewall integrity listeners processes segmentation reaper"
# Modules with fixed checks: their baseline category may be omitted.
OPTIONAL_MODULES="reaper"

#----- My Standard Functions -----
cyan() { printf "${CYAN_TEXT}%s${RESET}
" "$1"; }
red() { printf "${RED_TEXT}%s${RESET}
" "$1"; }
green() { printf "${GREEN_TEXT}%s${RESET}
" "$1"; }
yellow() { printf "${YELLOW_TEXT}%s${RESET}
" "$1"; }

log_msg() {
    if [ "$MODE" = "interactive" ]; then
        cyan "$1"
    else
        logger -t "$LOG_TAG" "$1"
    fi
}

show_help () {
    printf '%b\n' "$YELLOW_TEXT"
    cat <<EOF
secaudit $SCRIPT_VERSION
Usage: $SCRIPT_NAME [command]
With no command at a terminal, opens the menu.

Available Commands:
   --run-all              run all modules
   --module modulename    run a given module
   --notify               email new Security Review changes and notices,
                          and changes in rwatch's state, red witnesses and CRITICAL alarms
   --selftest             check the Reaper interfaces this script reads still
                          exist and parse; run after every firmware upgrade
   --version              print the version
   --install              download and install into $ADDON_DIR
   --update               download and install a newer version
   --schedule on|off      turn the nightly audit and 10-minute alerts on or off
   --uninstall            remove this copy, its schedule and its alias
   --startup              re-add the cron jobs (run by services-start at boot)
   --help                 show this help
   ... Available module names are ...
EOF
printf '%b\n' "$RESET"
    for m in $MODULES; do
        yellow "... $m"
    done
}

#===================================================================#
# Script specific functions
#===================================================================#

# ----- Baseline access
get_baseline_category() {
    # Output: one type|item|expected|severity row per assertion of category $1.
    sed -n "s/^$1|//p" "$PARSED_BASELINE"
}

validate_baseline() {
    # -------------------------------------------------------------------------
    # Purpose: Parse and validate all of baseline.conf in one pass, before any
    #          module runs, and write the rows get_baseline_category() returns.
    #
    # Assertion form: check=<type>:<body>[:warn|:alert]
    # Omitted severity takes the category's default_criticality.
    #
    # Return status:
    #   0 = baseline is valid
    #   1 = baseline is invalid; each problem has been logged
    # -------------------------------------------------------------------------
    local errors
    local error

    if [ ! -f "$BASELINE_CONF" ] || [ ! -r "$BASELINE_CONF" ]; then
        log_msg "ERROR: Baseline validation failed: baseline file is missing or unreadable: $BASELINE_CONF"
        return 1
    fi

    errors="$(awk -v modules="$MODULES" -v optional_modules="$OPTIONAL_MODULES" \
        -v parsed="$PARSED_BASELINE" '
        function report(message) {
            printf " at line %d%s: %s\n", NR,
                (category == "" ? "" : " in [" category "]"), message
        }

        function is_path(value) { return value ~ /^\// }

        # Split body into item and expected; sets a_item and a_expected.
        function parse_body(body, grammar,    i) {
            a_item = body
            a_expected = ""

            if (grammar == "whole") return 1
            if (grammar == "exclusion") { a_expected = "approved"; return 1 }
            if (grammar == "host") return index(body, ":") == 0

            if (grammar == "rule") {
                if (!match(body, /:[^:]*$/)) return 0
                a_item = substr(body, 1, RSTART - 1)
                a_expected = substr(body, RSTART + 1)
                return a_item != "" && a_expected == "present" && index(a_item, " ") > 0
            }

            i = index(body, ":")
            if (i == 0) return 0
            a_item = substr(body, 1, i - 1)
            a_expected = substr(body, i + 1)
            if (a_item == "") return 0

            if (grammar == "port") return a_expected ~ /^[^:]+:.+$/
            return a_expected != "" || grammar == "allow_empty"
        }

        function value_ok(type, item, expected,    octets, i) {
            if (type == "nvram") return item ~ /^[A-Za-z0-9_.-]+$/
            if (type == "rule") {
                return substr(item, 1, index(item, " ") - 1) ~ /^[A-Za-z0-9_.-]+$/
            }
            if (type == "file_hash") {
                return is_path(item) && length(expected) == 64 &&
                    expected !~ /[^0-9A-Fa-f]/
            }
            if (type == "forbidden_path") {
                return is_path(item) && expected == "present"
            }
            if (type ~ /^forbidden_/) return is_path(item)
            if (type == "allowed_port") {
                return item ~ /^[0-9]+$/ && item + 0 >= 1 && item + 0 <= 65535 &&
                    expected ~ /^(tcp|udp):(lan|external)$/
            }
            if (type == "bridge") {
                return item ~ /^br[0-9]/ && expected == "present"
            }
            if (type == "bridge_membership") {
                return item ~ /^br[0-9]/ &&
                    expected ~ /^[A-Za-z0-9._-]+(,[A-Za-z0-9._-]+)*$/
            }
            if (type == "exec_origin") {
                return item ~ /^\/[A-Za-z0-9._\/-]*[A-Za-z0-9._-]$/ && item !~ /\/\// &&
                    item !~ /\/\.\.?(\/|$)/
            }
            if (type == "firmware") return item ~ /^[A-Za-z0-9._-]+$/
            if (type == "auth_source") {
                if (split(item, octets, ".") != 4) return 0
                for (i = 1; i <= 4; i++) {
                    if (octets[i] !~ /^[0-9]+$/ || octets[i] + 0 > 255) return 0
                }
                return 1
            }
            return 0
        }

        BEGIN {
            split(modules, module_list, " ")
            for (i in module_list) known[module_list[i]] = 1
            split(optional_modules, optional_list, " ")
            for (i in optional_list) optional[optional_list[i]] = 1

            grammar["nvram"] = "allow_empty"
            grammar["rule"] = "rule"
            grammar["file_hash"] = "pair"
            grammar["forbidden_path"] = "pair"
            grammar["forbidden_path_exclude"] = "exclusion"
            grammar["forbidden_file_exclude"] = "exclusion"
            grammar["bridge"] = "pair"
            grammar["bridge_membership"] = "pair"
            grammar["allowed_port"] = "port"
            grammar["auth_source"] = "host"
            grammar["exec_origin"] = "whole"
            grammar["firmware"] = "whole"

            allowed["configuration:nvram"] = 1
            allowed["firewall:rule"] = 1
            allowed["integrity:file_hash"] = 1
            allowed["integrity:forbidden_path"] = 1
            allowed["integrity:forbidden_path_exclude"] = 1
            allowed["integrity:forbidden_file_exclude"] = 1
            allowed["listeners:allowed_port"] = 1
            allowed["segmentation:bridge"] = 1
            allowed["segmentation:bridge_membership"] = 1
            allowed["authentication:auth_source"] = 1
            allowed["processes:exec_origin"] = 1
            allowed["reaper:firmware"] = 1
        }

        {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            sub(/[[:space:]]+$/, "", line)
            if (line == "" || line ~ /^#/) next

            if (line ~ /^\[.*\]$/) {
                category = ""
                header = substr(line, 2, length(line) - 2)
                if (!(header in known) && header != "scope") report("unexpected category [" header "]")
                if (header in seen) report("duplicate category [" header "]")
                seen[header] = 1
                category = header
                next
            }

            if (line ~ /^\[/ || line ~ /\]$/) {
                category = ""
                report("malformed category header")
                next
            }

            if (category == "") {
                report("content outside a category")
                next
            }

            sub(/[[:space:]]+#.*$/, "", line)

            # [scope] only lists checks to leave out of --run-all.
            if (category == "scope") {
                if (line !~ /^skip=/) {
                    report("only skip=<check> lines belong in [scope]")
                    next
                }
                name = substr(line, 6)
                if (!(name in known)) report("unknown check \047" name "\047 in skip=")
                else if (name in skipped) report("duplicate skip=" name)
                else skips++
                skipped[name] = 1
                next
            }

            if (line ~ /^default_criticality=/) {
                value = substr(line, 21)
                if (++default_count[category] > 1) report("duplicate default_criticality")
                if (value == "warn" || value == "alert") {
                    default_value[category] = value
                } else {
                    report("invalid default_criticality")
                }
                next
            }

            if (line !~ /^check=/) {
                report("unrecognized baseline line")
                next
            }

            body = substr(line, 7)
            colon = index(body, ":")
            type = substr(body, 1, colon - 1)
            body = substr(body, colon + 1)
            severity = ""
            if (body ~ /:warn$/ || body ~ /:alert$/) {
                severity = substr(body, match(body, /:[a-z]+$/) + 1)
                body = substr(body, 1, RSTART - 1)
            }

            if (colon == 0 || body == "" || !(type in grammar) ||
                !parse_body(body, grammar[type])) {
                report("invalid assertion grammar")
                next
            }

            if (!((category ":" type) in allowed)) {
                report("assertion type \047" type "\047 is not allowed in this category")
            } else if (!value_ok(type, a_item, a_expected)) {
                report("invalid value for assertion \047" type "\047")
            }

            key = category "|" type "|" a_item "|" a_expected "|" \
                (severity == "" ? default_value[category] : severity)
            if (key in assertion) report("duplicate assertion")
            assertion[key] = 1

            rows++
            row[rows] = category "|" type "|" a_item "|" a_expected "|"
            row_severity[rows] = severity
            row_category[rows] = category
        }

        END {
            for (i = 1; i in module_list; i++) {
                name = module_list[i]
                if (!(name in seen)) {
                    if (!(name in optional) && !(name in skipped))
                        printf ": required category [%s] is missing\n", name
                } else if (default_count[name] != 1 || default_value[name] == "") {
                    printf " in [%s]: invalid or missing default_criticality\n", name
                }
            }

            if (skips > 0 && skips == length(module_list))
                printf " in [scope]: every check is skipped, so nothing would run\n"

            printf "" > parsed
            for (i = 1; i <= rows; i++) {
                severity = row_severity[i]
                if (severity == "") severity = default_value[row_category[i]]
                print row[i] severity > parsed
            }
            close(parsed)
        }
    ' "$BASELINE_CONF")"

    [ -n "$errors" ] || return 0

    while IFS= read -r error; do
        log_msg "ERROR: Baseline validation failed$error"
    done <<EOF
$errors
EOF
    return 1
}

# status: pass | warn | alert (baseline findings) | execution_failure (the
# check could not run) | not_evaluable (expected gap, e.g. boot grace or an
# exited process). not_evaluable is shown in details but not counted in summaries.
log_detail() {
    local category="$1"
    local target="$2"
    local expected="$3"
    local current="$4"
    local reason="$5"
    local status="$6"

    # Values may contain colons (addresses, pid:comm), so fields are |-delimited.
    printf '%s-detail|%s|%s|%s|%s|%s\n' \
        "$category" "$target" "$expected" "$current" "$reason" "$status" \
        >> "$LOG_FILE"
}

log_summary() {
    local summary

    # Summaries come from the detail records, so modules keep no counters.
    summary="$(awk -F'|' -v record="$1-detail" -v category="$1" '
        $1 == record { count[$NF]++ }
        END {
            pass = count["pass"] + 0
            warn = count["warn"] + 0
            alert = count["alert"] + 0
            failed = count["execution_failure"] + 0
            printf "%s-summary:%d:%d:%d:%d:%d\n", category,
                pass + warn + alert + failed, pass, warn, alert, failed
        }
    ' "$LOG_FILE")"
    printf '%s\n' "$summary" >> "$LOG_FILE"
}

display_summary_results() {
    if [ "$MODE" = "interactive" ]; then
        clear
    fi

    format="%-23s | %-8s | %-8s | %-8s | %-10s | %-10s"

    printf "${CYAN_TEXT}$format${RESET}\n" \
        "Category" "Checks" "Passes" "Warns" "Alerts" "Exec-Fail"
    echo "------------------------------------------------------------------------------------------------"

    for category in $REPORT_MODULES; do
        if grep -qx "${category}-skipped" "$LOG_FILE"; then
            printf "${CYAN_TEXT}%-23s${RESET} | ${YELLOW_TEXT}%s${RESET}\n" "[$category]" "skipped ([scope] in baseline.conf)"
            continue
        fi
        line=$(grep -m 1 "^${category}-summary:" "$LOG_FILE")

        if [ -n "$line" ]; then
            IFS=':' read -r _ checked passed warned alerted execution_failed <<EOF
$line
EOF

            [ -n "$execution_failed" ] || execution_failed=0

            printf "${CYAN_TEXT}%-23s${RESET} | %-8s | ${GREEN_TEXT}%-8s${RESET} | ${YELLOW_TEXT}%-8s${RESET} | ${RED_TEXT}%-10s${RESET} | ${RED_TEXT}%-10s${RESET}\n" \
                "[$category]" "$checked" "$passed" "$warned" "$alerted" "$execution_failed"
        fi
    done

    # Reduced coverage is always stated, so a clean report never hides it.
    skipped="$(grep -c -- '-skipped$' "$LOG_FILE")"
    if [ "$skipped" -gt 0 ]; then
        total="$(( $(echo "$REPORT_MODULES" | wc -w) ))"
        printf "\n${YELLOW_TEXT}%d of %d checks ran; [scope] in baseline.conf skips: %s${RESET}\n" \
            "$((total - skipped))" "$total" "$(sed -n 's/-skipped$//p' "$LOG_FILE" | tr '\n' ' ')"
        if grep -qx 'reaper-skipped' "$LOG_FILE"; then
            printf "${YELLOW_TEXT}%s${RESET}\n" "Reaper's own health (watchdog, firewall witnesses, Security Review) is not being checked."
        fi
    fi
}

display_category_details() {
    for category in $REPORT_MODULES; do

        details="$(grep "^${category}-detail|" "$LOG_FILE" | grep -v "|pass$")"

        if [ -n "$details" ]; then
            printf "\n${CYAN_TEXT}[%s]${RESET}\n" "$category"

            format="%-30s | %-12s | %-12s | %-28s | %-18s"

            printf "${CYAN_TEXT}$format${RESET}\n" \
                "Item Checked" "Baseline" "Current" "Reason" "Status"

            echo "--------------------------------------------------------------------------------------------------------------"

            while IFS='|' read -r _ item baseline current reason status; do
                local color

                case "$status" in
                    pass)              color="$GREEN_TEXT" ;;
                    warn)              color="$YELLOW_TEXT" ;;
                    alert|execution_failure)
                        color="$RED_TEXT"
                        ;;
                    *)                 color="$RESET" ;;
                esac

                printf "${color}%-30s | %-12s | %-12s | %-28s | %-18s${RESET}\n" \
                    "$item" "$baseline" "$current" "$reason" "$status"
            done <<EOF
$details
EOF
        fi
    done
}

email_alert() {
    local subject
    local body="${2:-The nightly security audit requires attention. Please review the attached report.}"
    local ret

    subject="${1:-Router Security Audit Report} - $(date '+%Y-%m-%d')"

    # Test runs set this so a finding never sends a real email.
    if [ -n "${SECAUDIT_NO_MAIL:-}" ]; then
        log_msg "Email notification suppressed: SECAUDIT_NO_MAIL is set."
        return 0
    fi

    # Email is an optional notification capability. The audit itself must not
    # depend on the shared email library or AMTM email configuration being
    # installed and configured.
    if [ ! -r "$EMAIL_LIB" ]; then
        log_msg "Email notification unavailable: shared email library not found: $EMAIL_LIB (open the secaudit menu to install it)"
        return 1
    fi

    if ! . "$EMAIL_LIB"; then
        log_msg "Email notification unavailable: failed to load shared email library."
        return 1
    fi

    # _SendEMailNotification_CEM_:
    #   $1 = subject
    #   $2 = body
    #   -Attach = audit run results
    _SendEMailNotification_CEM_ "$subject" "$body" "-Attach=$MAIL_LOG"
    ret=$?

    if [ "$ret" -ne 0 ]; then
        log_msg "WARNING: Failed to send security audit email notification (status $ret)."
        return "$ret"
    fi

    return 0
}

report_setup_failure() {
    log_msg "ERROR: $1"
    AUDIT_EXECUTION_FAILED=1

    # An unattended run that cannot start must not fail silently.
    if [ "$MODE" != "interactive" ]; then
        printf '%s\n' "$1" > "$MAIL_LOG"
        email_alert
    fi
}

#===================================================================#
# Audit modules: one audit_<module>() per entry in MODULES
#===================================================================#

# Audit the sources of successful logins in the active syslog.
#
#   check=auth_source:<IPv4-address>[:<criticality>]
#
# Each successful SSH (password or public key) or WebUI/app (http or https)
# login must come from a declared source. Findings use the most severe
# criticality declared. Having no login events is not a finding. The current
# log and its one rotated copy are read. Unattended runs evaluate only lines not
# reported before; interactive runs evaluate everything and record nothing.

audit_authentication() {
    local category="authentication"
    local log_file="/jffs/syslog.log"
    local log_files seen_file="" record_file=""
    local source_ip severity authorized_sources=" " violation_severity="warn"
    local service account event_text auth_count=0
    local execution_failed=0

    if [ ! -r "$log_file" ]; then
        log_detail "$category" "module" "$log_file" "" \
            "auth_log_unreadable" "execution_failure"
        return 1
    fi

    log_files="$log_file"
    [ -r "$log_file-1" ] && log_files="$log_file-1 $log_file"

    if [ "$MODE" != "interactive" ]; then
        seen_file="$AUTH_SEEN"
        record_file="$AUTH_SEEN.new"
        [ -f "$seen_file" ] || : > "$seen_file"
        : > "$record_file"
    fi

    while IFS='|' read -r _ source_ip _ severity; do
        [ -n "$source_ip" ] || continue
        authorized_sources="$authorized_sources$source_ip "
        [ "$severity" = "alert" ] && violation_severity="alert"
    done <<EOF
$(get_baseline_category "$category")
EOF

    if [ "$authorized_sources" = " " ]; then
        log_detail "$category" "module" "auth_source" "" \
            "no_authorized_sources" "execution_failure"
        return 1
    fi

    # Event rows: service|account|source_ip|event_text
    # log_files is one or two paths without spaces; splitting is intended.
    # shellcheck disable=SC2086
    while IFS='|' read -r service account source_ip event_text; do
        if [ "$service" = "__execution_failure__" ]; then
            log_detail "$category" "event" "successful administrative auth" \
                "${event_text:-<malformed>}" "malformed_auth_event" "execution_failure"
            execution_failed=1
            continue
        fi

        [ -n "$source_ip" ] || continue
        auth_count=$((auth_count + 1))

        case "$authorized_sources" in
            *" $source_ip "*)
                log_detail "$category" "$service:$account:$source_ip" "authorized_source" \
                    "$source_ip" "successful_auth_source_authorized" "pass"
                ;;
            *)
                log_detail "$category" "$service:$account:$source_ip" "authorized_source" \
                    "$source_ip" "successful_auth_source_unauthorized" "$violation_severity"
                ;;
        esac
    done <<EOF
$(awk -v seen="$seen_file" -v record="$record_file" '
    BEGIN {
        if (seen != "")
            while ((getline line < seen) > 0) reported[line] = 1
    }

    # Every matched line is recorded, so the seen list holds only lines still
    # present in the logs and prunes itself as they rotate away.
    function new_event() {
        if (record != "") print $0 > record
        return !($0 in reported)
    }

    /dropbear\[[0-9]+\]: (Pubkey|Password|PAM password) auth succeeded for / {
        if (!new_event()) next
        user = ""
        ip = ""
        quote = sprintf("%c", 39)
        marker = " auth succeeded for " quote
        pos = index($0, marker)
        if (pos > 0) {
            rest = substr($0, pos + length(marker))
            endpos = index(rest, quote)
            if (endpos > 1)
                user = substr(rest, 1, endpos - 1)
        }
        if (match($0, /from [0-9]+(\.[0-9]+){3}:[0-9]+/)) {
            ip = substr($0, RSTART + 5, RLENGTH - 5)
            sub(/:[0-9]+$/, "", ip)
        }
        if (user != "" && ip != "")
            print "dropbear|" user "|" ip "|" $0
        else
            print "__execution_failure__|||" $0
        next
    }

    # httpd logs [LOGIN][http|https][Web|APP] (httpd/web.c).
    /HTTPD: \[LOGIN\]\[https?\]\[(Web|APP)\] successful \(/ {
        if (!new_event()) next
        client = ($0 ~ /\]\[APP\] /) ? "APP" : "WebUI"
        if (match($0, /\([0-9]+(\.[0-9]+){3}\)/))
            print "httpd|" client "|" substr($0, RSTART + 1, RLENGTH - 2) "|" $0
        else
            print "__execution_failure__|||" $0
    }
' $log_files)
EOF

    if [ "$auth_count" -eq 0 ]; then
        log_detail "$category" "events" "successful administrative auth" \
            "<none>" "no_new_successful_auth_events" "pass"
    fi

    [ "$execution_failed" -eq 0 ]
}

# Audit NVRAM values against [configuration].
#
#   check=nvram:<name>:<expected>[:<criticality>]
#
# A variable can exist with an empty value, and nvram get cannot show the
# difference, so one nvram show snapshot decides both existence and value. A
# variable that does not exist cannot be evaluated, so it is an execution failure.

audit_configuration() {
    local category="configuration"
    local item expected severity found observed reason
    local execution_failed=0

    while IFS='|' read -r item expected severity found observed; do
        [ -n "$item" ] || continue

        if [ "$found" != "1" ]; then
            log_detail "$category" "$item" "$expected" "" \
                "nvram_missing" "execution_failure"
            execution_failed=1
        elif [ "$observed" = "$expected" ]; then
            log_detail "$category" "$item" "$expected" "$observed" "" "pass"
        else
            reason="${observed:-empty}_not_expected"
            log_detail "$category" "$item" "$expected" "$observed" "$reason" "$severity"
        fi
    done <<EOF
$({ get_baseline_category "$category"; echo __NVRAM__; nvram show 2>/dev/null; } | awk -F'|' '
    !snapshot {
        if ($0 == "__NVRAM__") {
            snapshot = 1
        } else {
            count++
            name[count] = $2
            row[count] = $2 "|" $3 "|" $4
            wanted[$2] = 1
        }
        next
    }
    {
        i = index($0, "=")
        key = substr($0, 1, i - 1)
        if (i > 1 && (key in wanted)) {
            found[key] = 1
            value[key] = substr($0, i + 1)
        }
    }
    END {
        for (i = 1; i <= count; i++) {
            print row[i] "|" (name[i] in found ? 1 : 0) "|" value[name[i]]
        }
    }
')
EOF

    [ "$execution_failed" -eq 0 ]
}

# Audit firewall rules against [firewall].
#
# Assertion form:
#   check=rule:<chain> <rule-spec>:present[:criticality]
#
# This module evaluates only the firewall assertions declared in
# [firewall] of baseline.conf. It does not implement firewall policy
# semantics, precedence, or reachability.

audit_firewall() {
    local category="firewall"
    local items item expected severity
    local rule_chain rule_spec ret
    local execution_failed=0

    items="$(get_baseline_category "$category")"

    while IFS='|' read -r _ item expected severity; do
        [ -n "$item" ] || continue

        rule_chain="${item%% *}"
        rule_spec="${item#* }"

        # A missing chain means the rule cannot be evaluated, not that it is absent.
        iptables -S "$rule_chain" >/dev/null 2>&1
        ret=$?
        if [ "$ret" -ne 0 ]; then
            log_detail "$category" "$item" "$expected" "unavailable" \
                "chain_inspection_failure: $rule_chain" "execution_failure"
            execution_failed=1
            continue
        fi

        # rule_spec is one rule; word splitting is intended.
        # shellcheck disable=SC2086
        iptables -C "$rule_chain" $rule_spec >/dev/null 2>&1
        ret=$?
        case "$ret" in
            0)
                log_detail "$category" "$item" "$expected" "present" "" "pass"
                ;;
            1)
                log_detail "$category" "$item" "$expected" "absent" \
                    "rule_not_present" "$severity"
                ;;
            *)
                log_detail "$category" "$item" "$expected" "unavailable" \
                    "rule_inspection_failure" "execution_failure"
                execution_failed=1
                ;;
        esac
    done <<EOF
$items
EOF

    [ "$execution_failed" -eq 0 ]
}

# Audit filesystem state against [integrity].
#
#   check=file_hash:<path>:<sha256>[:<criticality>]
#   check=forbidden_path:<directory>:present[:<criticality>]
#   check=forbidden_path_exclude:<directory>[:<criticality>]
#   check=forbidden_file_exclude:<file>[:<criticality>]
#
# forbidden_path allows no executable regular file anywhere below the
# directory. Symlinks are not followed. Exclusions are themselves checked, so
# stale exceptions stay visible.

audit_integrity() {
    local category="integrity"
    local items type path expected severity
    local observed reason ret find_output executable found
    local path_excludes="" file_excludes=""
    local execution_failed=0

    items="$(get_baseline_category "$category")"

    # Exclusions first, so their baseline position does not matter.
    while IFS='|' read -r type path _; do
        case "$type" in
            forbidden_path_exclude) path_excludes="$path_excludes $path" ;;
            forbidden_file_exclude) file_excludes="$file_excludes $path" ;;
        esac
    done <<EOF
$items
EOF

    while IFS='|' read -r type path expected severity; do
        case "$type" in
            file_hash)
                if [ ! -f "$path" ]; then
                    log_detail "$category" "$path" "$expected" "MISSING" \
                        "file_missing" "$severity"
                    continue
                fi

                if ! observed="$(sha256sum "$path" 2>/dev/null)"; then
                    log_detail "$category" "$path" "$expected" "" \
                        "hash_execution_failure" "execution_failure"
                    execution_failed=1
                    continue
                fi

                observed="${observed%% *}"
                if [ "$observed" = "$expected" ]; then
                    log_detail "$category" "$path" "$expected" "$observed" "" "pass"
                else
                    log_detail "$category" "$path" "$expected" "$observed" \
                        "hash_mismatch" "$severity"
                fi
                ;;

            forbidden_path_exclude|forbidden_file_exclude)
                if { [ "$type" = "forbidden_path_exclude" ] && [ -d "$path" ]; } ||
                   { [ "$type" = "forbidden_file_exclude" ] && [ -f "$path" ]; }; then
                    log_detail "$category" "$path" "approved_exclusion" "present" "" "pass"
                elif [ -e "$path" ]; then
                    reason="exclusion_target_not_directory"
                    [ "$type" = "forbidden_file_exclude" ] && reason="exclusion_target_not_file"
                    log_detail "$category" "$path" "approved_exclusion" "wrong_type" \
                        "$reason" "$severity"
                else
                    log_detail "$category" "$path" "approved_exclusion" "missing" \
                        "exclusion_target_missing" "$severity"
                fi
                ;;

            forbidden_path)
                if [ ! -e "$path" ]; then
                    log_detail "$category" "$path" "$expected" "MISSING" "" "pass"
                    continue
                fi

                if [ ! -d "$path" ]; then
                    log_detail "$category" "$path" "$expected" "" \
                        "path_type_execution_failure" "execution_failure"
                    execution_failed=1
                    continue
                fi

                # BusyBox find has no -type, -perm or -prune, so each path goes
                # through ls. A failed -exec does not change find's status, so
                # failure is a marker line. A file that vanished mid-walk is
                # normal in /tmp.
                find_output="$(find "$path" -exec sh -c '
                    ls_output=$(ls -ld "$3" 2>/dev/null) || {
                        [ -e "$3" ] || [ -L "$3" ] || exit 0
                        echo __find_error__
                        exit 0
                    }

                    permissions=${ls_output%% *}
                    [ "${#permissions}" -eq 10 ] || {
                        echo __find_error__
                        exit 0
                    }

                    case "$permissions" in
                        -*) ;;
                        *) exit 0 ;;
                    esac

                    for exclude in $1; do
                        case "$3" in
                            "$exclude"|"$exclude"/*) exit 0 ;;
                        esac
                    done

                    for exclude in $2; do
                        [ "$3" = "$exclude" ] && exit 0
                    done

                    # Execute bits are characters 4, 7 and 10. Setuid and
                    # setgid show as s, and sticky as t, when execute is set.
                    case "$permissions" in
                        ???[xs]*|??????[xs]*|?????????[xt])
                            printf "%s\n" "$3"
                            ;;
                    esac
                ' sh "$path_excludes" "$file_excludes" {} \;)"
                ret=$?

                case "$find_output" in
                    *__find_error__*) ret=1 ;;
                esac

                if [ "$ret" -ne 0 ]; then
                    log_detail "$category" "$path" "$expected" "" \
                        "forbidden_path_execution_failure" "execution_failure"
                    execution_failed=1
                    continue
                fi

                found=0
                while IFS= read -r executable; do
                    [ -n "$executable" ] || continue
                    found=1
                    log_detail "$category" "$path" "$expected" "$executable" \
                        "forbidden_executable" "$severity"
                done <<EOF
$find_output
EOF

                [ "$found" -eq 1 ] ||
                    log_detail "$category" "$path" "$expected" "NONE" "" "pass"
                ;;
        esac
    done <<EOF
$items
EOF

    [ "$execution_failed" -eq 0 ]
}

# Audit IPv4 and IPv6 listeners against [listeners].
#
#   check=allowed_port:<port>:<tcp|udp>:<lan|external>[:<criticality>]
#
# Scope is socket binding, not firewall reachability:
#   lan      = bound only to non-WAN local addresses
#   external = bound to a WAN interface, or wildcard-bound (0.0.0.0 or ::)
#
# The port is per protocol, not per family: tcp/22 covers both IPv4 and IPv6.
# A lan assertion fails if any socket on that port is external. Unlisted
# listeners are alerts, except Avahi's dynamic UDP ports. Loopback is skipped.

# Print loopback, external or lan for an address; fail if it is not local.
# Reads address_map and wan_interfaces from audit_listeners.
listener_scope() {
    local mapped_address mapped_interface interface=""

    case "$1" in
        127.*|::1|::ffff:127.*)
            echo loopback
            return 0
            ;;
        0.0.0.0|\*|::)
            echo external
            return 0
            ;;
    esac

    while IFS='|' read -r mapped_address mapped_interface; do
        if [ "$mapped_address" = "$1" ]; then
            interface="$mapped_interface"
            break
        fi
    done <<EOF
$address_map
EOF

    [ -n "$interface" ] || return 1

    case " $wan_interfaces " in
        *" $interface "*) echo external ;;
        *) echo lan ;;
    esac
}

audit_listeners() {
    local category="listeners"
    local netstat_output ip_output address_map
    local wan_name wan_value wan_interfaces=""
    local protocol address port process scope
    local observed="" allowed=" "
    local expected severity expected_protocol expected_scope expected_state
    local match mismatch unknown
    local execution_failed=0

    if ! netstat_output="$(netstat -lnptu 2>/dev/null)"; then
        log_detail "$category" "runtime_listeners" "available" "unavailable" \
            "listener_enumeration_failed" "execution_failure"
        return 1
    fi

    if ! ip_output="$(ip addr show 2>/dev/null)"; then
        log_detail "$category" "local_addresses" "available" "unavailable" \
            "address_enumeration_failed" "execution_failure"
        return 1
    fi

    for wan_name in wan0_ifname wan1_ifname wan_ifname wan0_gw_ifname wan1_gw_ifname; do
        if ! wan_value="$(nvram get "$wan_name" 2>/dev/null)"; then
            log_detail "$category" "$wan_name" "available" "unavailable" \
                "wan_interface_detection_failed" "execution_failure"
            return 1
        fi
        case "$wan_value" in
            ''|none|disabled) ;;
            *) wan_interfaces="$wan_interfaces $wan_value" ;;
        esac
    done

    address_map="$(printf '%s\n' "$ip_output" | awk '
        /^[0-9]+: / {
            interface = $2
            sub(/@.*/, "", interface)
            sub(/:$/, "", interface)
        }
        /^[[:space:]]+inet6? / {
            address = $2
            sub(/\/.*/, "", address)
            printf "%s|%s\n", address, interface
        }
    ')"

    # Rows: protocol|address|port|scope|process
    while IFS='|' read -r protocol address port process; do
        [ -n "$port" ] || continue

        if ! scope="$(listener_scope "$address")"; then
            scope="scope_unknown"
            execution_failed=1
            log_detail "$category" "$protocol/$port" "scope" "$address" \
                "listener_scope_detection_failed" "execution_failure"
        fi

        [ "$scope" = "loopback" ] && continue
        observed="$observed
$protocol|$address|$port|$scope|$process"
    done <<EOF
$(printf '%s\n' "$netstat_output" | awk '
    # tcp/udp or tcp6/udp6; the port is after the last colon, and an IPv6
    # address may be bracketed. A row that does not parse is kept with an
    # empty address, so it fails scope detection loudly instead of vanishing.
    $1 ~ /^(tcp|udp)6?$/ && $4 ~ /:[0-9]+$/ {
        protocol = $1
        sub(/6$/, "", protocol)
        i = match($4, /:[0-9]+$/)
        address = substr($4, 1, i - 1)
        gsub(/[][]/, "", address)
        if (address !~ /^([0-9.]+|[0-9A-Fa-f:.]+|\*)$/) address = ""
        printf "%s|%s|%s|%s\n", protocol, address, substr($4, i + 1), $NF
    }
' | sort -u)
EOF

    # Baseline to runtime: each assertion gets exactly one result.
    while IFS='|' read -r _ port expected severity; do
        [ -n "$port" ] || continue

        expected_protocol="${expected%%:*}"
        expected_scope="${expected#*:}"
        expected_state="$expected_protocol/$port/$expected_scope"
        allowed="$allowed$expected_protocol/$port "
        match=""
        mismatch=""
        unknown=0

        while IFS='|' read -r protocol address scope_port scope process; do
            [ "$protocol" = "$expected_protocol" ] || continue
            [ "$scope_port" = "$port" ] || continue

            # Every socket on the port counts: an IPv4 LAN socket must not
            # hide an IPv6 wildcard one. A LAN socket on an external
            # assertion is narrower, not a finding.
            case "$scope" in
                "$expected_scope")
                    [ -n "$match" ] || match="present:$address:$port:$process"
                    ;;
                scope_unknown)
                    unknown=1
                    ;;
                external)
                    mismatch="present:$address:external:$process"
                    ;;
            esac
        done <<EOF
$observed
EOF

        if [ -n "$mismatch" ]; then
            log_detail "$category" "$port" "$expected_state" "$mismatch" \
                "unexpected_scope" "$severity"
        elif [ "$unknown" -eq 1 ]; then
            log_detail "$category" "$port" "$expected_state" "scope_unknown" \
                "listener_scope_detection_failed" "execution_failure"
        elif [ -n "$match" ]; then
            log_detail "$category" "$port" "$expected_state" "$match" "" "pass"
        else
            log_detail "$category" "$port" "$expected_state" "not_present" \
                "not_present" "$severity"
        fi
    done <<EOF
$(get_baseline_category "$category")
EOF

    # Runtime to baseline: anything undeclared is an alert.
    while IFS='|' read -r protocol address port scope process; do
        [ -n "$port" ] || continue

        case "$allowed" in
            *" $protocol/$port "*) continue ;;
        esac

        case "$protocol:$process" in
            udp:*/avahi-daemon|udp:*/avahi-daemon:) continue ;;
        esac

        log_detail "$category" "$protocol/$port" "not_authorized" \
            "$protocol/$address:$port/$scope:$process" \
            "unexpected_listener" "alert"
    done <<EOF
$observed
EOF

    [ "$execution_failed" -eq 0 ]
}

# Audit where running user-space processes execute from, against [processes].
#
#   check=exec_origin:<trusted-root>[:<criticality>]
#
# /proc/<pid>/exe is the authority, so a script run by /bin/sh counts as /bin/sh.
# Findings use the most severe criticality declared. Kernel threads are excluded.

# Record a process whose details could not be read. One that has exited, or is
# a zombie, is a normal race rather than an audit failure.
process_unreadable() {
    if [ -d "/proc/$1" ]; then
        case "$(awk '/^State:/ { print $2; exit }' "/proc/$1/status" 2>/dev/null)" in
            ''|Z|X) ;;
            *)
                log_detail "$category" "pid:$1" "executable" "" \
                    "executable_provenance_unreadable" "execution_failure"
                execution_failed=1
                return
                ;;
        esac
    fi

    log_detail "$category" "pid:$1" "executable" "" \
        "process_disappeared_during_audit" "not_evaluable"
}

audit_processes() {
    local category="processes"
    local root severity trusted_roots="" finding_severity="warn"
    local pid_path pid ppid exe comm reason
    local execution_failed=0

    while IFS='|' read -r _ root _ severity; do
        [ -n "$root" ] || continue
        trusted_roots="$trusted_roots $root"
        [ "$severity" = "alert" ] && finding_severity="alert"
    done <<EOF
$(get_baseline_category "$category")
EOF

    if [ -z "$trusted_roots" ]; then
        log_detail "$category" "module" "exec_origin" "" \
            "no_trusted_execution_origins" "execution_failure"
        return 1
    fi

    for pid_path in /proc/[0-9]*; do
        pid="${pid_path##*/}"

        # PID 2 is kthreadd, and every kernel thread is its child.
        [ "$pid" = "2" ] && continue

        ppid="$(awk '/^PPid:/ { print $2; exit }' "$pid_path/status" 2>/dev/null)"
        if [ -z "$ppid" ]; then
            process_unreadable "$pid"
            continue
        fi
        [ "$ppid" = "2" ] && continue

        exe="$(readlink "$pid_path/exe" 2>/dev/null)"
        if [ -z "$exe" ]; then
            process_unreadable "$pid"
            continue
        fi

        comm="$(cat "$pid_path/comm" 2>/dev/null)"

        case "$exe" in
            *" (deleted)")
                reason="executable_deleted"
                ;;
            *)
                reason="executable_origin_untrusted"
                for root in $trusted_roots; do
                    case "$exe" in
                        "$root"/*) reason="" ;;
                    esac
                done
                ;;
        esac

        if [ -z "$reason" ]; then
            log_detail "$category" "pid:$pid:${comm:-unknown}" \
                "trusted_firmware_origin" "$exe" "executable_origin_trusted" "pass"
        else
            log_detail "$category" "pid:$pid:${comm:-unknown}" \
                "trusted_firmware_origin" "$exe" "$reason" "$finding_severity"
        fi
    done

    [ "$execution_failed" -eq 0 ]
}

# Audit bridge topology against [segmentation], using brctl as the only source.
#
#   check=bridge:<bridge>:present[:<criticality>]
#   check=bridge_membership:<bridge>:<member>,<member>...[:<criticality>]
#
# Membership is compared as a sorted set.

# Print a comma, space or newline separated list as sorted unique CSV.
membership_set() {
    printf '%s\n' "$1" | tr ', ' '\n' | sed '/^$/d' | sort -u |
        awk 'NR > 1 { printf "," } { printf "%s", $0 } END { print "" }'
}

audit_segmentation() {
    local category="segmentation"
    local bridges members
    local type bridge expected severity observed
    local reason status

    if ! bridges="$(brctl show 2>/dev/null)"; then
        log_detail "$category" "runtime_bridges" "available" "" \
            "bridge_enumeration_failure" "execution_failure"
        return 1
    fi

    # Rows: bridge [member]. brctl puts the first member on the bridge line and
    # each further member alone on its own line.
    members="$(printf '%s\n' "$bridges" | awk '
        NR == 1 { next }
        NF >= 3 { bridge = $1; print bridge, $4; next }
        NF == 1 { print bridge, $1 }
    ')"

    while IFS='|' read -r type bridge expected severity; do
        [ -n "$type" ] || continue

        if ! printf '%s\n' "$members" | grep -q "^$bridge "; then
            observed="absent"
            reason="bridge_missing"
            status="$severity"
            [ "$type" = "bridge_membership" ] && expected="$(membership_set "$expected")"
        elif [ "$type" = "bridge" ]; then
            observed="present"
            reason=""
            status="pass"
        else
            expected="$(membership_set "$expected")"
            observed="$(membership_set "$(printf '%s\n' "$members" |
                awk -v bridge="$bridge" '$1 == bridge { print $2 }')")"
            reason=""
            status="pass"
            if [ "$observed" != "$expected" ]; then
                reason="membership_mismatch"
                status="$severity"
            fi
        fi

        log_detail "$category" "$bridge" "$expected" "$observed" "$reason" "$status"
    done <<EOF
$(get_baseline_category "$category")
EOF
}

# Audit Reaper's own watchdog, firewall witnesses and Security Review switch.
# The checks are fixed, so [reaper] in baseline.conf is optional and takes no
# assertions; every finding is an alert. Unreviewed Security Review items are
# --notify's job, not this module's.
#
# When an alert fires:
#   watchdog_disabled / watchdog_not_scheduled -> check nvram rwatch_enable, cru l
#   watchdog_reports_failure                   -> logread | grep rwatch
#   firewall_witness_red                       -> cat /tmp/reaper/rwatch_witness
#   security_review_not_armed                  -> accept baseline (Firewall > Status)
#   firmware_changed_run_selftest              -> --selftest, docs §13, then update
#                                                 check=firmware: in baseline.conf

# Print how old an rwatch file may be: three ticks of rwatch_iv minutes,
# clamped to 1..30 with a default of 5, as rc/rwatch.c does.
rwatch_stale_seconds() {
    local interval

    interval="$(nvram get rwatch_iv 2>/dev/null)"
    case "$interval" in
        ''|*[!0-9]*) interval=5 ;;
    esac
    [ "$interval" -ge 1 ] && [ "$interval" -le 30 ] || interval=5
    echo $((interval * 180))
}

# Print the first integer field named $2 in JSON file $1, or nothing.
json_number() {
    tr -d '\n' < "$1" 2>/dev/null | awk -v key="\"$2\":" '{
        i = index($0, key)
        if (i == 0) exit
        rest = substr($0, i + length(key))
        if (match(rest, /^[0-9]+/)) print substr(rest, 1, RLENGTH)
    }'
}

audit_reaper() {
    local category="reaper"
    local uptime now stale state t0 ts red firmware item severity

    # Upgrades reboot, which clears /tmp, so the acknowledged firmware lives in
    # the baseline (check=firmware:<nvram innerver>). After an upgrade: run
    # --selftest, work through docs §13, then update that line.
    firmware="$(nvram get innerver 2>/dev/null)"
    while IFS='|' read -r _ item _ severity; do
        [ -n "$item" ] || continue
        if [ -z "$firmware" ]; then
            log_detail "$category" "firmware" "$item" "" \
                "firmware_version_unreadable" "$severity"
        elif [ "$firmware" != "$item" ]; then
            log_detail "$category" "firmware" "$item" "$firmware" \
                "firmware_changed_run_selftest" "$severity"
        else
            log_detail "$category" "firmware" "$item" "$firmware" "" "pass"
        fi
    done <<EOF
$(get_baseline_category "$category")
EOF

    uptime="$(cut -d. -f1 /proc/uptime)"
    now="$(date +%s)"
    stale="$(rwatch_stale_seconds)"

    if [ "$(nvram get rwatch_enable 2>/dev/null)" != "1" ]; then
        log_detail "$category" "rwatch_enable" "1" "$(nvram get rwatch_enable 2>/dev/null)" \
            "watchdog_disabled" "alert"
        return 0
    fi
    log_detail "$category" "rwatch_enable" "1" "1" "" "pass"

    # cru lines end in #<id>#.
    if cru l 2>/dev/null | grep -q '#rwatch#$'; then
        log_detail "$category" "rwatch_cron" "present" "present" "" "pass"
    else
        log_detail "$category" "rwatch_cron" "present" "absent" \
            "watchdog_not_scheduled" "alert"
    fi

    if [ "$uptime" -lt "$REAPER_GRACE_SECONDS" ]; then
        log_detail "$category" "rwatch_state" "OK" "boot_grace" \
            "too_soon_after_boot" "not_evaluable"
        return 0
    fi

    # rwatch.state is OK, or FAIL <uptime at start> <ticks>.
    state="$(cat "$RWATCH_STATE" 2>/dev/null)"
    case "$state" in
        OK)
            log_detail "$category" "rwatch_state" "OK" "OK" "" "pass"
            ;;
        FAIL*)
            t0="$(echo "$state" | cut -d' ' -f2)"
            case "$t0" in ''|*[!0-9]*) t0="$uptime" ;; esac
            log_detail "$category" "rwatch_state" "OK" \
                "FAIL for $(( (uptime - t0) / 60 )) min" \
                "watchdog_reports_failure" "alert"
            ;;
        *)
            log_detail "$category" "rwatch_state" "OK" "${state:-missing}" \
                "watchdog_state_unreadable" "alert"
            ;;
    esac

    # fwstatus.json is advisory: red witnesses never fail rwatch's tick.
    if [ -x /usr/bin/reaper_fwsim ]; then
        ts="$(json_number "$FWSTATUS_JSON" ts)"
        red="$(json_number "$FWSTATUS_JSON" red)"
        if [ "$(json_number "$FWSTATUS_JSON" ok)" != "1" ] || [ -z "$ts" ] || [ -z "$red" ]; then
            log_detail "$category" "fw_witnesses" "0 red" "unreadable" \
                "fwstatus_unreadable" "alert"
        elif [ $((now - ts)) -gt "$stale" ]; then
            log_detail "$category" "fw_witnesses" "fresh" "$(( (now - ts) / 60 )) min old" \
                "fwstatus_stale" "alert"
        elif [ "$red" -gt 0 ]; then
            log_detail "$category" "fw_witnesses" "0 red" "$red red" \
                "firewall_witness_red" "alert"
        else
            log_detail "$category" "fw_witnesses" "0 red" "0 red" "" "pass"
        fi
    fi

    if [ "$(nvram get rwatch_review 2>/dev/null)" != "1" ]; then
        log_detail "$category" "rwatch_review" "1" "$(nvram get rwatch_review 2>/dev/null)" \
            "security_review_disabled" "alert"
    elif [ "$(json_number "$REVIEW_JSON" armed)" != "1" ]; then
        log_detail "$category" "review_baseline" "accepted" "none" \
            "security_review_not_armed" "alert"
    else
        log_detail "$category" "review_baseline" "accepted" "accepted" "" "pass"
    fi

    return 0
}

# State rule (both --run-all and --notify): write *.new, rename only after the
# email succeeds, so a failed send reports the same items again next run.
# Make this run's recorded state current, after its notification succeeded.
commit_run_state() {
    [ -f "$AUTH_SEEN.new" ] && mv -f "$AUTH_SEEN.new" "$AUTH_SEEN"
    return 0
}

#===================================================================#
# Security Review notifier
#===================================================================#

review_report() {
    # Output: one line per unaccepted change or notice in review.json, or one
    # line saying why the report cannot be trusted. review.json is an internal
    # Reaper format, and its text is untrusted, so it is only ever printed.
    if [ "$(nvram get rwatch_review 2>/dev/null)" != "1" ]; then
        echo "Security Review is switched off (rwatch_review is not 1)"
        return
    fi

    if [ ! -r "$REVIEW_JSON" ]; then
        echo "Security Review report is missing: $REVIEW_JSON"
        return
    fi

    # A parser failure must alert, or it would look like nothing is pending.
    awk -v now="$(date +%s)" -v stale="$(rwatch_stale_seconds)" \
        -v fw_armed="$([ -e "$FW_ARMED" ] && echo 1 || echo 0)" '
        function number(name) {
            return match(json, "\"" name "\":[0-9]+") ?
                substr(json, RSTART + length(name) + 3, RLENGTH - length(name) - 3) + 0 : -1
        }

        # Text of a quoted field, from after its key up to the closing marker.
        function field(text, key, closing,    i) {
            i = index(text, key)
            if (i == 0) return ""
            text = substr(text, i + length(key))
            return substr(text, 1, index(text, closing) - 1)
        }

        { json = json $0 }

        END {
            if (number("ok") != 1 || number("ts") < 0 || index(json, "\"items\":[") == 0) {
                print "Security Review report could not be read"
                exit
            }
            # rwatch skips the review while a rules candidate is armed.
            if (!fw_armed && now - number("ts") > stale) {
                print "Security Review report is stale; rwatch may have stopped"
                exit
            }
            if (number("armed") != 1) {
                print "Security Review has no accepted baseline"
                exit
            }
            if (number("truncated") > 0) {
                print "Security Review report is truncated; see the Firewall page"
            }

            count = split(json, rows, /\{"t":"/)
            for (i = 2; i <= count; i++) {
                state = field(rows[i], "\"st\":\"", "\"")
                if (state == "baseline" || state == "rule") continue
                printf "%s: %s (%s)\n", state,
                    field(rows[i], "\"k\":\"", "\",\"st\":"),
                    field(rows[i], "\"v\":\"", "\"}")
            }

            count = split(json, rows, /\{"svc":"/)
            for (i = 2; i <= count; i++) {
                printf "failed %s logins from %s: %s at %s\n",
                    substr(rows[i], 1, index(rows[i], "\"") - 1),
                    field(rows[i], "\"ip\":\"", "\""),
                    field(rows[i], "\"n\":", ","), field(rows[i], "\"ts\":", "}")
            }

            if (number("ww") > 0) {
                printf "%d world-writable paths under /jffs, first: %s\n",
                    number("ww"), field(json, "\"ww_p\":\"", "\"")
            }
        }
    ' "$REVIEW_JSON" 2>/dev/null || echo "Security Review report could not be read"
}

notify_review() {
    # Email only lines not reported before, so accepting items never alerts and
    # each change alerts once. State stays in /tmp, because a file in /jffs would
    # itself be Security Review drift; after a reboot, open items alert once more.
    local report new_count uptime

    # rwatch needs a few minutes after boot to write its first report.
    uptime="$(cut -d. -f1 /proc/uptime)"
    [ "$uptime" -ge "$REAPER_GRACE_SECONDS" ] || return 0

    report="$(review_report)"

    if [ "$MODE" = "interactive" ]; then
        printf '%s\n' "${report:-Security Review: nothing pending}"
        return 0
    fi

    # The header keeps the file non-empty: grep -f with no patterns selects nothing.
    [ -f "$REVIEW_STATE" ] || echo "# reported" > "$REVIEW_STATE"
    MAIL_LOG="$LOG_DIR/review_mail.log"
    printf '%s\n' "$report" | sed '/^$/d' > "$MAIL_LOG"

    new_count="$(grep -Fxvc -f "$REVIEW_STATE" "$MAIL_LOG")"

    if [ "$new_count" -gt 0 ]; then
        log_msg "Security Review: $new_count new item(s)"
        email_alert "Router Security Review Alert" \
            "Security Review has $new_count new item(s). Review them on the Firewall page, Status tab. The full list is attached." ||
            return 1
    fi

    { echo "# reported"; cat "$MAIL_LOG"; } > "$REVIEW_STATE"
}

#===================================================================#
# Reaper watchdog notifier
#===================================================================#

# Print the newest line rwatch logged as CRITICAL, or nothing.
last_rwatch_critical() {
    local files=""

    [ -r "$SYSLOG_FILE-1" ] && files="$SYSLOG_FILE-1"
    [ -r "$SYSLOG_FILE" ] && files="$files $SYSLOG_FILE"
    [ -n "$files" ] || return 0
    # files is one or two paths without spaces; splitting is intended.
    # shellcheck disable=SC2086
    grep -h 'rwatch: CRITICAL:' $files 2>/dev/null | tail -n 1
}

notify_watch() {
    # Email each change in rwatch's own state, its red firewall witnesses and
    # its CRITICAL alarms once, when it happens, never once per run. State stays
    # in /tmp like review.state; after a reboot, live problems alert once more.
    local uptime state cur prev witness line crit_on events count

    uptime="$(cut -d. -f1 /proc/uptime)"
    [ "$uptime" -ge "$REAPER_GRACE_SECONDS" ] || return 0

    events="$LOG_DIR/watch.events"
    : > "$events"

    # rwatch.state is OK, or FAIL <uptime at start> <ticks>. The start names the
    # episode, so a recovery and a new failure between two runs still alert.
    state="$(cat "$RWATCH_STATE" 2>/dev/null)"
    case "$state" in
        OK)    cur="OK" ;;
        FAIL*) cur="FAIL $(echo "$state" | cut -d' ' -f2)" ;;
        *)     cur="unreadable" ;;
    esac
    prev="$(cat "$WATCH_RWATCH" 2>/dev/null)"
    if [ "$cur" != "${prev:-OK}" ]; then
        case "$cur" in
            OK)    echo "rwatch recovered: the watchdog's checks pass again" ;;
            FAIL*) echo "rwatch failure: the watchdog reports a FAILURE" ;;
            *)     echo "rwatch state unreadable: $RWATCH_STATE is missing or malformed" ;;
        esac >> "$events"
    fi
    printf '%s\n' "$cur" > "$WATCH_RWATCH.new"

    # rwatch logs CRITICAL on every tick while it lasts, and only during a
    # FAIL episode, so alert on the first new line and rearm on recovery.
    line="$(last_rwatch_critical)"
    crit_on="$(cat "$WATCH_CRIT_ON" 2>/dev/null)"
    if [ ! -f "$WATCH_CRIT_LINE" ]; then
        # First run since boot: lines already in /jffs/syslog.log are history.
        crit_on=0
    elif [ "${cur%% *}" != "FAIL" ]; then
        crit_on=0
    elif [ -n "$line" ] && [ "$line" != "$(cat "$WATCH_CRIT_LINE")" ]; then
        [ "$crit_on" = 1 ] ||
            echo "rwatch critical: a Warden block set holds LAN/loopback addresses" >> "$events"
        crit_on=1
    fi
    printf '%s\n' "$line" > "$WATCH_CRIT_LINE.new"
    printf '%s\n' "${crit_on:-0}" > "$WATCH_CRIT_ON.new"

    # rwatch keeps the red-witness list itself and removes it when none are red.
    if [ -x /usr/bin/reaper_fwsim ]; then
        witness="$(cat "$RWATCH_WITNESS" 2>/dev/null)"
        if [ "$witness" != "$(cat "$WATCH_RULES" 2>/dev/null)" ]; then
            if [ -n "$witness" ]; then
                echo "rules red: firewall witnesses to review: $witness"
            else
                echo "rules clear: no firewall witness is red any more"
            fi >> "$events"
        fi
        printf '%s\n' "$witness" > "$WATCH_RULES.new"
    fi

    count="$(grep -c . "$events")"

    if [ "$MODE" = "interactive" ]; then
        rm -f "$WATCH_RWATCH.new" "$WATCH_CRIT_LINE.new" "$WATCH_CRIT_ON.new" "$WATCH_RULES.new"
        if [ "$count" -gt 0 ]; then cat "$events"; else echo "Reaper watchdog: no change since the last run"; fi
        return 0
    fi

    if [ "$count" -gt 0 ]; then
        while IFS= read -r line; do log_msg "Reaper watchdog: $line"; done < "$events"
        # Log text is untrusted, so it is only ever attached.
        MAIL_LOG="$LOG_DIR/watch_mail.log"
        {
            cat "$events"
            echo
            echo "Recent rwatch lines from $SYSLOG_FILE:"
            grep -h 'rwatch:' "$SYSLOG_FILE" 2>/dev/null | tail -n 20
        } > "$MAIL_LOG"
        email_alert "Router Reaper Watchdog Alert" \
            "The Reaper watchdog reports $count change(s). Details are attached." ||
            return 1
    fi

    for line in "$WATCH_RWATCH" "$WATCH_CRIT_LINE" "$WATCH_CRIT_ON" "$WATCH_RULES"; do
        [ -f "$line.new" ] && mv -f "$line.new" "$line"
    done
    return 0
}

#===================================================================#
# Firmware-upgrade self-test
#===================================================================#

# Print one self-test result line and count failures.
selftest_line() {
    # $1 = PASS | WARN | FAIL | SKIP | MANUAL, $2 = text
    case "$1" in
        PASS) green "PASS    $2" ;;
        FAIL) red "FAIL    $2"; SELFTEST_FAILED=$((SELFTEST_FAILED + 1)) ;;
        WARN) yellow "WARN    $2" ;;
        *)    printf '%-7s %s\n' "$1" "$2" ;;
    esac
}

selftest() {
    # Read-only check that every undocumented Reaper interface this script
    # reads still exists and parses (docs §13). It only proves the formats; it
    # cannot prove rwatch's meaning did not change, so MANUAL lines remain.
    # When a new Reaper dependency is added to the script, add it here too.
    local uptime firmware expected state field nv
    SELFTEST_FAILED=0

    uptime="$(cut -d. -f1 /proc/uptime)"
    firmware="$(nvram get innerver 2>/dev/null)"
    cyan "secaudit $SCRIPT_VERSION self-test on ${firmware:-unknown firmware}"

    if validate_baseline; then
        selftest_line PASS "baseline.conf is valid"
        expected="$(get_baseline_category reaper | awk -F'|' '$1 == "firmware" { print $2; exit }')"
        if [ -z "$expected" ]; then
            selftest_line WARN "no check=firmware: in [reaper]; upgrades will not be flagged"
        elif [ "$expected" = "$firmware" ]; then
            selftest_line PASS "baseline firmware matches: $firmware"
        else
            selftest_line WARN "baseline firmware is $expected; this firmware is $firmware"
        fi
    else
        selftest_line FAIL "baseline.conf is invalid (see errors above)"
    fi

    # nvram show tells a missing key from an empty one; nvram get cannot.
    nv="$(nvram show 2>/dev/null)"
    for field in innerver rwatch_enable rwatch_review rwatch_iv; do
        if printf '%s\n' "$nv" | grep -q "^$field="; then
            selftest_line PASS "nvram $field exists"
        else
            selftest_line FAIL "nvram $field is missing"
        fi
    done

    if cru l 2>/dev/null | grep -q '#rwatch#$'; then
        selftest_line PASS "cron job #rwatch# exists"
    else
        selftest_line FAIL "cron job #rwatch# is missing"
    fi

    if [ -x /usr/bin/reaper_fwsim ]; then
        selftest_line PASS "/usr/bin/reaper_fwsim exists"
    else
        selftest_line WARN "/usr/bin/reaper_fwsim is missing; witness checks are skipped"
    fi

    if [ -d "$(dirname "$FW_ARMED")" ]; then
        selftest_line PASS "$(dirname "$FW_ARMED") exists (armed marker location)"
    else
        selftest_line FAIL "$(dirname "$FW_ARMED") is missing (armed marker location)"
    fi

    if [ -r "$SYSLOG_FILE" ]; then
        selftest_line PASS "$SYSLOG_FILE is readable"
    else
        selftest_line FAIL "$SYSLOG_FILE is not readable"
    fi

    if [ -r "$EMAIL_LIB" ]; then
        selftest_line PASS "email library is readable"
    else
        selftest_line WARN "email library is missing; nothing will be emailed (menu option 8 sets it up)"
    fi

    # rwatch writes its files on its first tick after the boot grace.
    if [ "$uptime" -lt "$REAPER_GRACE_SECONDS" ]; then
        selftest_line SKIP "rwatch files: uptime under ${REAPER_GRACE_SECONDS}s; run again later"
    else
        state="$(cat "$RWATCH_STATE" 2>/dev/null)"
        if printf '%s\n' "$state" | grep -qE '^(OK|FAIL [0-9]+ [0-9]+)$'; then
            selftest_line PASS "$RWATCH_STATE format ($state)"
        else
            selftest_line FAIL "$RWATCH_STATE is missing or not OK / FAIL <n> <n>: '$state'"
        fi

        for field in ok ts armed truncated ww; do
            if [ -n "$(json_number "$REVIEW_JSON" "$field")" ]; then
                selftest_line PASS "review.json field $field"
            else
                selftest_line FAIL "review.json field $field is missing or not a number"
            fi
        done
        if grep -q '"items":\[' "$REVIEW_JSON" 2>/dev/null; then
            selftest_line PASS "review.json field items"
        else
            selftest_line FAIL "review.json field items is missing"
        fi

        if [ -x /usr/bin/reaper_fwsim ]; then
            for field in ok ts red; do
                if [ -n "$(json_number "$FWSTATUS_JSON" "$field")" ]; then
                    selftest_line PASS "fwstatus.json field $field"
                else
                    selftest_line FAIL "fwstatus.json field $field is missing or not a number"
                fi
            done
        fi
    fi

    selftest_line MANUAL "rc/rwatch.c: HEALGRACE still ${REAPER_GRACE_SECONDS}s; stale age still 3 x rwatch_iv"
    selftest_line MANUAL "rc/rwatch.c: RV_NV_S still watches the nvram switches left out of [configuration]"
    selftest_line MANUAL "syslog text 'rwatch: CRITICAL:' and the Warden/Dreadwatch alert wording"
    selftest_line MANUAL "refresh the /etc/passwd hash with gen_hashes.sh if --run-all flags it"

    if [ "$SELFTEST_FAILED" -gt 0 ]; then
        red "Self-test: $SELFTEST_FAILED failure(s). secaudit needs an update for this firmware;"
        red "don't rely on its results until then. Check for updates from the menu."
        return 1
    fi
    green "Self-test: no failures."

    # A clean test is what accepting a new firmware needs, so offer it here.
    if [ "$MODE" = "interactive" ] && [ -n "$expected" ] && [ -n "$firmware" ] &&
       [ "$expected" != "$firmware" ]; then
        printf '\n'
        if ask_yes "Accept $firmware as your firmware in baseline.conf?"; then
            set_baseline_firmware "$firmware" || return 1
        else
            yellow "Nightly audits will keep reporting the firmware change until you accept it."
        fi
    fi
    return 0
}

# Replace the check=firmware: value in baseline.conf with $1, in place.
set_baseline_firmware() {
    local tmp="$LOG_DIR/baseline.tmp"
    case "$1" in
        ""|*[!A-Za-z0-9._-]*) red "Unexpected firmware name '$1'; baseline.conf was not changed."; return 1 ;;
    esac
    if ! { sed "s/^\(check=firmware:\)[A-Za-z0-9._-]*/\1$1/" "$BASELINE_CONF" > "$tmp" &&
           [ "$(baseline_firmware_in "$tmp")" = "$1" ] &&
           cat "$tmp" > "$BASELINE_CONF"; }; then
        rm -f "$tmp"
        red "Could not update baseline.conf."
        return 1
    fi
    rm -f "$tmp"
    green "baseline.conf now expects $1. Nightly audits will stop reporting the firmware change."
}

#===================================================================#
# Scope: [scope] skip=<check> lines leave checks out of --run-all
#===================================================================#

# Print the checks [scope] skips, one per line (read straight from baseline.conf).
scope_skips() {
    awk '{
        l = $0
        sub(/^[[:space:]]+/, "", l); sub(/[[:space:]]+#.*$/, "", l); sub(/[[:space:]]+$/, "", l)
        if (l ~ /^\[.*\]$/) { s = (l == "[scope]"); next }
        if (s && l ~ /^skip=/) print substr(l, 6)
    }' "$BASELINE_CONF" 2>/dev/null
}

is_skipped() { scope_skips | grep -qx "$1"; }

# True if baseline.conf has a [<check>] section.
baseline_has_section() {
    grep -qE "^[[:space:]]*\[$1\][[:space:]]*\$" "$BASELINE_CONF" 2>/dev/null
}

run_audit() {
    # $1 = the modules to run; $2 = "named" when one was asked for by name,
    # which runs it even if [scope] skips it.
    local module skipped

    REPORT_MODULES="$1"
    : > "$LOG_FILE"

    if [ "$(( $(echo "$1" | wc -w) ))" -gt 1 ]; then
        log_msg "secaudit running a full audit..."
    else
        log_msg "secaudit running the $1 check..."
    fi

    if ! validate_baseline; then
        report_setup_failure "Baseline validation failed; no audit modules were executed."
        return 1
    fi

    for module in $1; do
        if is_skipped "$module"; then
            if [ "${2:-}" != "named" ]; then
                printf '%s-skipped\n' "$module" >> "$LOG_FILE"
                continue
            fi
            if ! baseline_has_section "$module"; then
                red "$module is skipped in [scope] and baseline.conf has no [$module] section to check against."
                return 1
            fi
            yellow "Note: [scope] skips $module; running it because you asked for it by name."
        fi
        if ! "audit_$module"; then
            AUDIT_EXECUTION_FAILED=1
            log_msg "ERROR: Module '$module' failed to execute successfully"
        fi
        log_summary "$module"
    done

    if [ "$MODE" = "interactive" ]; then
        display_summary_results
        display_category_details

        if [ "$AUDIT_EXECUTION_FAILED" -ne 0 ]; then
            yellow "Audit Complete: Execution errors occurred."
        else
            green "Audit Complete: All requested modules executed successfully."
        fi
    else
        display_summary_results > "$MAIL_LOG"
        display_category_details >> "$MAIL_LOG"

        # Login lines count as reported only once the email went out, so a
        # failed notification reports them again on the next run.
        if [ "$AUDIT_EXECUTION_FAILED" -ne 0 ]; then
            log_msg "Audit Complete: Execution errors occurred."
            email_alert && commit_run_state
        elif grep -qE '\|(warn|alert)$' "$LOG_FILE"; then
            log_msg "Audit Complete: Compliance findings require attention."
            email_alert && commit_run_state
        else
            log_msg "Audit Complete: All requested modules executed successfully."
            commit_run_state
        fi
        skipped="$(sed -n 's/-skipped$//p' "$LOG_FILE" | tr '\n' ' ')"
        [ -z "$skipped" ] || log_msg "Skipped by [scope]: $skipped"
    fi

    [ "$AUDIT_EXECUTION_FAILED" -eq 0 ]
}

#===================================================================#
# Addon management: menu, install, update, schedule, uninstall
#===================================================================#

pause() {
    printf '\nPress Enter to continue... '
    read -r _ || true
}

# Ask a yes/no question; anything but yes is no.
ask_yes() {
    local answer
    printf '%s [y/N] ' "$1"
    read -r answer || return 1
    case "$answer" in
        y|Y|yes|Yes|YES) return 0 ;;
    esac
    return 1
}

# Print the SCRIPT_VERSION of a downloaded copy of this script.
file_version() {
    sed -n 's/^SCRIPT_VERSION="\([0-9][0-9.]*\)"$/\1/p' "$1" | head -n 1
}

# True if dotted version $1 is newer than $2.
version_gt() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        n = split(a, x, "."); m = split(b, y, "."); if (m > n) n = m
        for (i = 1; i <= n; i++) {
            if (x[i] + 0 > y[i] + 0) exit 0
            if (x[i] + 0 < y[i] + 0) exit 1
        }
        exit 1
    }'
}

# The marked lines this addon owns in services-start and profile.add.
hook_line() { printf '%s --startup & # secaudit\n' "$1/audit_security.sh"; }
alias_line() { printf 'alias secaudit="sh %s" # secaudit\n' "$1/audit_security.sh"; }

# Append line $2 to file $1 unless it is already there. A new file starts with $3.
append_line() {
    if [ ! -f "$1" ]; then
        mkdir -p "$(dirname "$1")" && printf '%s\n' "$3" > "$1" || return 1
    fi
    grep -qxF "$2" "$1" && return 0
    [ -z "$(tail -c 1 "$1")" ] || printf '\n' >> "$1"
    printf '%s\n' "$2" >> "$1"
}

# Remove exact line $2 from file $1. Rewrites in place, so permissions stay.
remove_line() {
    local tmp="$LOG_DIR/edit.tmp"
    [ -f "$1" ] && grep -qxF "$2" "$1" || return 0
    grep -vxF "$2" "$1" > "$tmp"
    # grep exits 1 when no line is left; 2 is a real error.
    [ "$?" -le 1 ] || { rm -f "$tmp"; return 1; }
    cat "$tmp" > "$1"
    rm -f "$tmp"
}

# Download ADDON_FILES into directory $1 and check them. Nothing is installed here.
# Every file must match its line in the release's SHA256SUMS.
fetch_files() {
    local dir="$1" name expected actual
    rm -rf "$dir"
    mkdir -p "$dir" || return 1
    for name in $CHECKSUMS $ADDON_FILES; do
        if ! curl -fsSL --retry 2 --connect-timeout 15 -o "$dir/$name" "$REPO_URL/$name"; then
            red "Download failed: $REPO_URL/$name"
            rm -rf "$dir"
            return 1
        fi
        [ "$name" = "$CHECKSUMS" ] && continue
        expected="$(awk -v n="$name" '$2 == n || $2 == "*" n { print $1; exit }' "$dir/$CHECKSUMS")"
        actual="$(sha256sum "$dir/$name" | cut -d ' ' -f 1)"
        if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
            red "The downloaded $name does not match its checksum. Nothing was changed."
            rm -rf "$dir"
            return 1
        fi
        case "$name" in
            *.sh)
                if [ "$(head -n 1 "$dir/$name")" != "#!/bin/sh" ] || ! sh -n "$dir/$name"; then
                    red "The downloaded $name is not a valid script. Nothing was changed."
                    rm -rf "$dir"
                    return 1
                fi
                ;;
        esac
    done
    if [ -z "$(file_version "$dir/audit_security.sh")" ]; then
        red "The downloaded audit_security.sh has no version. Nothing was changed."
        rm -rf "$dir"
        return 1
    fi
}

# Move downloaded files from $1 into $2. mv, not cp over the old file, so a
# running copy of this script keeps reading its own (now unlinked) file.
place_files() {
    local name
    for name in $ADDON_FILES; do
        cp "$1/$name" "$2/.$name.new" && mv -f "$2/.$name.new" "$2/$name" || return 1
    done
    chmod 755 "$2/audit_security.sh" "$2/gen_hashes.sh" && chmod 644 "$2/baseline.conf.example"
}

# The firmware baseline.conf expects (check=firmware:), or nothing.
baseline_firmware() { baseline_firmware_in "$BASELINE_CONF"; }
baseline_firmware_in() {
    sed -n 's/^check=firmware:\([A-Za-z0-9._-]*\).*/\1/p' "$1" 2>/dev/null | head -n 1
}

# ready | placeholders | invalid. placeholders = valid, but REPLACE values
# from baseline.conf.example are still in check= lines.
baseline_state() {
    if ! ( validate_baseline ) >/dev/null 2>&1; then
        echo invalid
    elif grep -q '^check=[^#]*REPLACE' "$BASELINE_CONF"; then
        echo placeholders
    else
        echo ready
    fi
}

# cru l lines that are this copy's own jobs.
own_cron_jobs() {
    local self="$SCRIPT_DIR/$SCRIPT_NAME"
    cru l 2>/dev/null | grep -F -e " $self --run-all #secaudit_run#" -e " $self --notify #secaudit_notify#"
}

# Schedules secaudit did not set up for this copy: a hand-written one, or
# another copy's. services-start lines (comments aside) and cru l lines that
# run audit_security.sh.
foreign_hook_lines() {
    grep 'audit_security\.sh' "$SERVICES_START" 2>/dev/null | grep -v '^[[:space:]]*#' |
        grep -vxF "$(hook_line "$SCRIPT_DIR")"
}
foreign_cron_jobs() {
    local self="$SCRIPT_DIR/$SCRIPT_NAME"
    # One -e per own job: BusyBox grep -F does not split a pattern on newlines.
    cru l 2>/dev/null | grep 'audit_security\.sh' |
        grep -vF -e " $self --run-all #secaudit_run#" -e " $self --notify #secaudit_notify#"
}

# The directory of the copy a foreign schedule runs.
foreign_dir() {
    { foreign_hook_lines; foreign_cron_jobs; } |
        sed -n 's#.*[ "]\(/[^ "]*\)/audit_security\.sh.*#\1#p' | head -n 1
}

# on | manual (this copy, set up by hand) | other (another copy) | partial | off
schedule_state() {
    local hook=0 jobs
    grep -qxF "$(hook_line "$SCRIPT_DIR")" "$SERVICES_START" 2>/dev/null && hook=1
    jobs="$(own_cron_jobs | grep -c '')"
    if [ "$hook" = 1 ] && [ "$jobs" = 2 ]; then
        echo on
    elif [ -n "$(foreign_hook_lines)$(foreign_cron_jobs)" ]; then
        if [ "$(foreign_dir)" = "$SCRIPT_DIR" ]; then echo manual; else echo other; fi
    elif [ "$hook" = 0 ] && [ "$jobs" = 0 ]; then
        echo off
    else
        echo partial
    fi
}

# Set RUN_HOUR and NOTIFY_MINUTES from settings.conf, or the defaults.
# The file is parsed, never sourced.
load_schedule_times() {
    local value
    RUN_HOUR="$DEFAULT_RUN_HOUR"
    NOTIFY_MINUTES="$DEFAULT_NOTIFY_MINUTES"
    [ -r "$SETTINGS_CONF" ] || return 0
    value="$(sed -n 's/^RUN_HOUR=\([0-9][0-9]*\)$/\1/p' "$SETTINGS_CONF" | tail -n 1)"
    if [ -n "$value" ] && [ "$value" -le 23 ] 2>/dev/null; then
        RUN_HOUR="$((value + 0))"
    fi
    value="$(sed -n 's/^NOTIFY_MINUTES=\([0-9][0-9]*\)$/\1/p' "$SETTINGS_CONF" | tail -n 1)"
    case " $NOTIFY_CHOICES " in
        *" $value "*) NOTIFY_MINUTES="$value" ;;
    esac
}

# e.g. "audit 03:00, alerts every 10 min"
schedule_times_text() {
    load_schedule_times
    printf 'audit %02d:00, alerts every %s min' "$RUN_HOUR" "$NOTIFY_MINUTES"
}

add_cron_jobs() {
    local self="$SCRIPT_DIR/$SCRIPT_NAME" notify
    load_schedule_times
    if [ "$NOTIFY_MINUTES" = 60 ]; then notify="0 * * * *"; else notify="*/$NOTIFY_MINUTES * * * *"; fi
    cru a secaudit_run "0 $RUN_HOUR * * * $self --run-all" &&
        cru a secaudit_notify "$notify $self --notify"
}

# Ask for the nightly audit hour and the alert interval, save them, and
# reschedule if this copy's schedule is on.
change_schedule_times() {
    local answer hour minutes tmp="$SETTINGS_CONF.new"
    load_schedule_times
    hour="$RUN_HOUR"
    minutes="$NOTIFY_MINUTES"

    printf '\nNightly full audit: runs at %02d:00.\n' "$hour"
    while :; do
        printf '  New hour (0-23), or Enter to keep %s: ' "$hour"
        read -r answer || return 1
        answer="$(printf '%s' "$answer" | sed 's/^0\([0-9]\)$/\1/')"
        case "$answer" in
            "") break ;;
            [0-9]|1[0-9]|2[0-3]) hour="$answer"; break ;;
        esac
        yellow "  Please type a whole hour from 0 to 23."
    done

    printf '\nReaper change alerts: checked every %s minutes.\n' "$minutes"
    while :; do
        printf '  Check every 5, 10, 15, 30 or 60 minutes? (Enter to keep %s): ' "$minutes"
        read -r answer || return 1
        [ -z "$answer" ] && break
        case " $NOTIFY_CHOICES " in
            *" $answer "*) minutes="$answer"; break ;;
        esac
        yellow "  Please choose 5, 10, 15, 30 or 60."
    done

    if [ "$hour" = "$RUN_HOUR" ] && [ "$minutes" = "$NOTIFY_MINUTES" ]; then
        cyan "Nothing was changed."
        return 0
    fi
    if ! { printf '# Schedule times, written by the secaudit menu. Updates keep this file.\n'
           printf 'RUN_HOUR=%s\nNOTIFY_MINUTES=%s\n' "$hour" "$minutes"; } > "$tmp" ||
       ! mv -f "$tmp" "$SETTINGS_CONF"; then
        rm -f "$tmp"
        red "Could not save $SETTINGS_CONF."
        return 1
    fi
    chmod 644 "$SETTINGS_CONF"
    green "Saved: $(schedule_times_text)."

    case "$(schedule_state)" in
        on)
            if add_cron_jobs; then green "The schedule now uses these times."; else red "Could not update the cron jobs."; return 1; fi
            ;;
        manual)
            yellow "The schedule was set up by hand, so it keeps its own times."
            yellow "These apply once you choose option 6 to let secaudit manage it."
            ;;
        other)
            yellow "The schedule runs $(foreign_dir), which keeps its own times."
            yellow "These apply once you choose option 6 to switch the schedule here."
            ;;
        *)
            cyan "These apply when you turn the schedule on."
            ;;
    esac
}

# Replace a foreign schedule (see foreign_hook_lines) with nothing, after the
# user agrees. services-start is backed up to /tmp and restored if the edit
# leaves it broken. Returns 1 if the user says no or the edit fails.
take_over_schedule() {
    local hooks jobs line id other question backup="$LOG_DIR/services-start.before-takeover"
    hooks="$(foreign_hook_lines)"
    jobs="$(foreign_cron_jobs)"
    other="$(foreign_dir)"

    if [ "$other" = "$SCRIPT_DIR" ] || [ -z "$other" ]; then
        yellow "The schedule was set up by hand:"
        question="Let secaudit manage it? Your lines are replaced by one secaudit line, with the same audits."
    else
        yellow "The schedule runs $other:"
        question="Switch it to $SCRIPT_DIR? $other stays installed but stops running on schedule."
    fi
    [ -z "$hooks" ] || printf '%s\n' "$hooks" | sed 's/^/  services-start:  /'
    [ -z "$jobs" ] || printf '%s\n' "$jobs" | sed 's/^/  cron job:        /'
    if ! ask_yes "$question"; then
        cyan "Nothing was changed."
        return 1
    fi

    if [ -n "$hooks" ]; then
        cp "$SERVICES_START" "$backup" || { red "Could not back up $SERVICES_START."; return 1; }
        while IFS= read -r line; do
            remove_line "$SERVICES_START" "$line" || break
        done <<LINES
$hooks
LINES
        if [ -n "$(foreign_hook_lines)" ] || ! sh -n "$SERVICES_START" 2>/dev/null; then
            cat "$backup" > "$SERVICES_START"
            red "Could not remove those lines safely, so $SERVICES_START was left as it was."
            return 1
        fi
    fi

    while IFS= read -r line; do
        id="$(printf '%s\n' "$line" | sed -n 's/.*#\([^#]*\)#$/\1/p')"
        [ -z "$id" ] || cru d "$id"
    done <<LINES
$jobs
LINES
}

schedule_on() {
    case "$(baseline_state)" in
        invalid)
            red "baseline.conf has errors. Choose 'Edit your baseline' to see and fix them."
            return 1
            ;;
        placeholders)
            red "baseline.conf still has REPLACE values from the example:"
            grep -n '^check=[^#]*REPLACE' "$BASELINE_CONF"
            return 1
            ;;
    esac

    # Two schedules would run every audit twice, so this copy's replaces any other.
    if [ -n "$(foreign_hook_lines)$(foreign_cron_jobs)" ]; then
        take_over_schedule || return 1
    fi

    if [ "$(nvram get jffs2_scripts 2>/dev/null)" != "1" ]; then
        yellow "JFFS custom scripts are off, so the schedule will not come back after a reboot."
        yellow "Turn on Administration > System > 'Enable JFFS custom scripts and configs'."
    fi

    if [ ! -f "$SERVICES_START" ]; then
        append_line "$SERVICES_START" "$(hook_line "$SCRIPT_DIR")" "#!/bin/sh" && chmod 755 "$SERVICES_START"
    else
        append_line "$SERVICES_START" "$(hook_line "$SCRIPT_DIR")" "#!/bin/sh"
    fi || { red "Could not update $SERVICES_START."; return 1; }

    if ! add_cron_jobs; then
        red "Could not add the cron jobs."
        return 1
    fi
    load_schedule_times
    green "$(printf 'Schedule is on: a full audit every night at %02d:00, and Reaper change alerts every %s minutes.' "$RUN_HOUR" "$NOTIFY_MINUTES")"
    yellow "Reaper's Security Review will list the change to $SERVICES_START. Review and accept it."
}

schedule_off() {
    # Jobs share their names with any other copy's, so delete only this copy's.
    local jobs
    jobs="$(own_cron_jobs)"
    case "$jobs" in *"#secaudit_run#"*) cru d secaudit_run ;; esac
    case "$jobs" in *"#secaudit_notify#"*) cru d secaudit_notify ;; esac
    if ! remove_line "$SERVICES_START" "$(hook_line "$SCRIPT_DIR")"; then
        red "Could not update $SERVICES_START."
        return 1
    fi
    green "Schedule is off."
}

edit_baseline() {
    local editor="${EDITOR:-}"
    if [ -z "$editor" ]; then
        if which nano >/dev/null 2>&1; then editor="nano"; else editor="vi"; fi
    fi
    if [ ! -f "$BASELINE_CONF" ]; then
        cp "$SCRIPT_DIR/baseline.conf.example" "$BASELINE_CONF" || return 1
        chmod 600 "$BASELINE_CONF"
    fi

    "$editor" "$BASELINE_CONF"

    cyan "Checking baseline.conf..."
    if ! validate_baseline; then
        red "Fix the errors above, then choose 'Edit your baseline' again."
        return 1
    fi
    if grep -q '^check=[^#]*REPLACE' "$BASELINE_CONF"; then
        yellow "baseline.conf is valid, but these lines still have REPLACE values:"
        grep -n '^check=[^#]*REPLACE' "$BASELINE_CONF"
        return 1
    fi
    green "baseline.conf is valid."
}

# ready | no_amtm | no_library
email_state() {
    if [ ! -f "$AMTM_EMAIL_CONF" ] || [ ! -f "$(dirname "$AMTM_EMAIL_CONF")/emailpw.enc" ]; then
        echo no_amtm
    elif [ ! -r "$EMAIL_LIB" ]; then
        echo no_library
    else
        echo ready
    fi
}

# Ask a yes/no question whose default is yes.
ask_yes_default() {
    local answer
    printf '%s [Y/n] ' "$1"
    read -r answer || return 1
    case "$answer" in
        ""|y|Y|yes|Yes|YES) return 0 ;;
    esac
    return 1
}

# Download the email library to $1 and check it looks like the library.
fetch_email_lib() {
    rm -f "$1"
    if ! curl -fsSL --retry 2 --connect-timeout 15 -o "$1" "$EMAIL_LIB_URL"; then
        red "Download failed: $EMAIL_LIB_URL"
        rm -f "$1"
        return 1
    fi
    if [ "$(head -n 1 "$1")" != "#!/bin/sh" ] || ! sh -n "$1" ||
       [ -z "$(email_lib_version "$1")" ]; then
        red "The downloaded email library does not look right. Nothing was changed."
        rm -f "$1"
        return 1
    fi
}

email_lib_version() {
    sed -n 's/^CEM_LIB_VERSION="\{0,1\}v\{0,1\}\([0-9][0-9.]*\).*/\1/p' "$1" 2>/dev/null | head -n 1
}

# Move a checked download $1 into place, as the shared library.
place_email_lib() {
    mkdir -p "$EMAIL_LIB_DIR" && chmod 755 "$EMAIL_LIB_DIR" &&
        cp "$1" "$EMAIL_LIB.new" && chmod 755 "$EMAIL_LIB.new" && mv -f "$EMAIL_LIB.new" "$EMAIL_LIB"
}

# Offer to install the library when amtm email is set up but it is missing.
offer_email_lib() {
    local tmp="$LOG_DIR/email_lib.download"
    case "$(email_state)" in
        no_amtm)
            yellow "Email isn't set up in amtm yet. To get emailed results, type amtm, choose em,"
            yellow "fill in your mail account and send its test email. Then come back to option 8."
            return 1
            ;;
        ready) return 0 ;;
    esac
    yellow "Email needs Martinski W.'s shared email library, which many Merlin addons use."
    if ! ask_yes_default "Download it now from github.com/Martinski4GitHub?"; then
        cyan "Not installed. Results will show here only until it is."
        return 1
    fi
    fetch_email_lib "$tmp" || return 1
    if ! place_email_lib "$tmp"; then
        rm -f "$tmp" "$EMAIL_LIB.new"
        red "Could not write $EMAIL_LIB."
        return 1
    fi
    rm -f "$tmp"
    green "Email library $(email_lib_version "$EMAIL_LIB") installed."
}

# Offer a newer email library, if there is one. Used by "Check for updates".
update_email_lib() {
    local tmp="$LOG_DIR/email_lib.download" have latest
    [ -r "$EMAIL_LIB" ] || return 0
    cyan "Checking for email library updates..."
    fetch_email_lib "$tmp" || return 1
    have="$(email_lib_version "$EMAIL_LIB")"
    latest="$(email_lib_version "$tmp")"
    if ! version_gt "$latest" "${have:-0}"; then
        green "The email library ${have:+$have }is up to date."
        rm -f "$tmp"
        return 0
    fi
    if ask_yes_default "Email library $latest is available (you have ${have:-an unknown version}). Update it?"; then
        if place_email_lib "$tmp"; then green "Email library updated to $latest."; else red "Could not write $EMAIL_LIB."; fi
    fi
    rm -f "$tmp"
}

# Menu: set email up if needed, then send a test email.
send_test_email() {
    offer_email_lib || return 1
    MAIL_LOG="$LOG_DIR/test_mail.log"
    printf 'This is a test email from secaudit %s on %s.\nIf you received it, SecAudit can email you its results.\n' \
        "$SCRIPT_VERSION" "$(nvram get lan_hostname 2>/dev/null)" > "$MAIL_LOG"
    cyan "Sending a test email..."
    if email_alert "SecAudit test email" "A test email, sent from the SecAudit menu."; then
        green "Sent. Check your inbox (and spam folder)."
    else
        red "The test email failed. Check amtm's own test email (amtm, then em) first."
        return 1
    fi
}

addon_install() {
    local dl="$LOG_DIR/download" version
    cyan "Installing secaudit into $ADDON_DIR"
    fetch_files "$dl" || return 1
    if ! mkdir -p "$ADDON_DIR" || ! place_files "$dl" "$ADDON_DIR"; then
        red "Could not write to $ADDON_DIR."
        rm -rf "$dl"
        return 1
    fi
    version="$(file_version "$dl/audit_security.sh")"
    rm -rf "$dl"

    if [ -f "$ADDON_DIR/baseline.conf" ]; then
        green "Kept your existing baseline.conf."
    else
        cp "$ADDON_DIR/baseline.conf.example" "$ADDON_DIR/baseline.conf" &&
            chmod 600 "$ADDON_DIR/baseline.conf"
    fi
    append_line "$PROFILE_ADD" "$(alias_line "$ADDON_DIR")" "# profile.add" ||
        yellow "Could not add the 'secaudit' command to $PROFILE_ADD."

    green "secaudit $version is installed."
    cat <<NEXT

Next steps, all from the menu:
  1. Edit your baseline: describe how your router should be set up.
  2. Run a full audit until it reports nothing you did not expect.
  3. Turn on the schedule.

Open the menu any time by typing:  secaudit
(in a new SSH session; until then: sh $ADDON_DIR/audit_security.sh)

NEXT
    case "$(email_state)" in
        no_library) offer_email_lib; printf '\n' ;;
        no_amtm)    yellow "For emailed results, set up email in amtm (amtm, then em), then use menu option 8."
                    printf '\n' ;;
    esac
    if ask_yes "Open the menu now?"; then
        exec sh "$ADDON_DIR/audit_security.sh"
    fi
}

# "Check for updates": SecAudit itself, then the email library.
addon_update() {
    local status=0
    addon_update_secaudit || status=1
    update_email_lib || status=1
    return "$status"
}

# Sets ADDON_UPDATED=1 when this copy was replaced.
addon_update_secaudit() {
    local dl="$LOG_DIR/download" latest
    ADDON_UPDATED=0
    cyan "Checking for updates..."
    fetch_files "$dl" || return 1
    latest="$(file_version "$dl/audit_security.sh")"
    if ! version_gt "$latest" "$SCRIPT_VERSION"; then
        green "secaudit $SCRIPT_VERSION is up to date."
        rm -rf "$dl"
        return 0
    fi
    yellow "secaudit $latest is available. You have $SCRIPT_VERSION."
    if ! ask_yes "Update now? Your baseline.conf is not changed."; then
        rm -rf "$dl"
        return 0
    fi
    if ! place_files "$dl" "$SCRIPT_DIR"; then
        red "The update failed while copying files. Run the update again."
        rm -rf "$dl"
        return 1
    fi
    rm -rf "$dl"
    ADDON_UPDATED=1
    green "Updated to secaudit $latest."
    yellow "New options may be in baseline.conf.example; compare it with your baseline.conf."
}

# Sets ADDON_REMOVED=1 when this copy was removed.
addon_uninstall() {
    local name
    ADDON_REMOVED=0
    yellow "This removes secaudit from $SCRIPT_DIR, with its schedule and 'secaudit' command."
    if ! ask_yes "Uninstall secaudit?"; then
        cyan "Nothing was changed."
        return 0
    fi
    schedule_off || return 1
    remove_line "$PROFILE_ADD" "$(alias_line "$SCRIPT_DIR")" ||
        yellow "Could not remove the 'secaudit' command from $PROFILE_ADD."
    for name in $ADDON_FILES; do
        rm -f "$SCRIPT_DIR/$name"
    done
    if [ -f "$BASELINE_CONF" ]; then
        if ask_yes "Also delete your baseline.conf? Keep it if you may reinstall."; then
            rm -f "$BASELINE_CONF" "$SETTINGS_CONF"
        else
            green "Kept $BASELINE_CONF and your schedule times."
        fi
    else
        rm -f "$SETTINGS_CONF"
    fi
    if [ ! -f "$BASELINE_CONF" ] && ! rmdir "$SCRIPT_DIR" 2>/dev/null; then
        yellow "Left files secaudit did not install in $SCRIPT_DIR."
    fi
    rm -rf "$LOG_DIR"
    ADDON_REMOVED=1
    green "secaudit is uninstalled."
}

# Run this script again with $@, in its own process, so each run starts clean.
run_child() {
    sh "$SCRIPT_DIR/$SCRIPT_NAME" "$@"
    pause
}

module_title() {
    case "$1" in
        authentication) echo "who logged in to the router, and from where" ;;
        configuration)  echo "router settings you chose (Wi-Fi, DNS, SSH, services)" ;;
        firewall)       echo "firewall rules Reaper's witnesses do not cover" ;;
        integrity)      echo "unexpected or changed system files" ;;
        listeners)      echo "network ports the router answers on" ;;
        processes)      echo "programs running from unexpected places" ;;
        segmentation)   echo "networks (bridges) and what is connected to them" ;;
        reaper)         echo "Reaper's own watchdog, firewall and Security Review" ;;
        *)              echo "" ;;
    esac
}

# Add or remove "skip=$2" in [scope] ($1 = add | remove), then validate; a
# change that leaves the baseline invalid is undone.
set_scope_skip() {
    local tmp="$LOG_DIR/baseline.tmp" backup="$LOG_DIR/baseline.before-scope"
    cp "$BASELINE_CONF" "$backup" || return 1
    if [ "$1" = "remove" ]; then
        awk -v m="$2" '{
            l = $0
            sub(/^[[:space:]]+/, "", l); sub(/[[:space:]]+#.*$/, "", l); sub(/[[:space:]]+$/, "", l)
            if (l ~ /^\[.*\]$/) s = (l == "[scope]")
            if (s && l == "skip=" m) next
            print
        }' "$BASELINE_CONF" > "$tmp"
    elif grep -qE '^[[:space:]]*\[scope\][[:space:]]*$' "$BASELINE_CONF"; then
        awk -v m="$2" '{ print }
            !done && $0 ~ /^[[:space:]]*\[scope\][[:space:]]*$/ { print "skip=" m; done = 1 }' \
            "$BASELINE_CONF" > "$tmp"
    else
        { cat "$BASELINE_CONF"
          printf '\n[scope]\n# Checks left out of every full audit. Delete a line to run that check again.\n'
          printf 'skip=%s\n' "$2"; } > "$tmp"
    fi || { rm -f "$tmp"; return 1; }
    cat "$tmp" > "$BASELINE_CONF"
    rm -f "$tmp"
    if ! ( validate_baseline ) > "$LOG_DIR/scope.errors" 2>&1; then
        cat "$backup" > "$BASELINE_CONF"
        red "That change would leave baseline.conf invalid, so it was undone:"
        cat "$LOG_DIR/scope.errors"
        return 1
    fi
}

# Copy section [$1] from baseline.conf.example to the end of baseline.conf and
# drop its skip= line, so the check runs. Undone if the result is invalid.
copy_example_section() {
    local example="$SCRIPT_DIR/baseline.conf.example" section tmp="$LOG_DIR/baseline.tmp"
    local backup="$LOG_DIR/baseline.before-copy"
    section="$(awk -v h="[$1]" '{
        l = $0; sub(/^[[:space:]]+/, "", l); sub(/[[:space:]]+$/, "", l)
        if (l ~ /^\[.*\]$/) on = (l == h)
        if (on) print
    }' "$example" 2>/dev/null)"
    if [ -z "$section" ]; then
        red "baseline.conf.example has no [$1] section to copy."
        return 1
    fi
    cp "$BASELINE_CONF" "$backup" || return 1
    if ! { cat "$BASELINE_CONF"; printf '\n%s\n' "$section"; } > "$tmp" ||
       ! cat "$tmp" > "$BASELINE_CONF"; then
        rm -f "$tmp"; cat "$backup" > "$BASELINE_CONF"
        red "Could not update baseline.conf."
        return 1
    fi
    rm -f "$tmp"
    set_scope_skip remove "$1" || { cat "$backup" > "$BASELINE_CONF"; return 1; }
    green "Copied the example [$1] section into your baseline. $1 is on."
    if printf '%s\n' "$section" | grep -q '^check=[^#]*REPLACE'; then
        yellow "It has REPLACE values to change for your router: choose 5, 'Edit your baseline'."
    else
        yellow "Check it matches your router with 5, 'Edit your baseline', before trusting its results."
    fi
}

# Menu: switch checks on or off in [scope].
choose_scope() {
    local i module choice state
    while :; do
        printf '\nChecks in a full audit (on = runs, off = left out by [scope] in baseline.conf):\n\n'
        i=0
        for module in $MODULES; do
            i=$((i + 1))
            if is_skipped "$module"; then state="${MENU_WARN}off${RESET}"; else state="${MENU_GOOD}on ${RESET}"; fi
            printf "  ${MENU_TITLE}%d${RESET}  %b  %-15s %s\n" "$i" "$state" "$module" "$(module_title "$module")"
        done
        printf '\nType a number to switch it on or off (Enter to go back): '
        read -r choice || return 0
        [ -z "$choice" ] && return 0
        i=0
        for module in $MODULES; do
            i=$((i + 1))
            [ "$choice" = "$i" ] || continue
            if is_skipped "$module"; then
                if ! baseline_has_section "$module"; then
                    yellow "Your baseline has no [$module] section yet, so there's nothing to check against."
                    if ask_yes "Copy the example [$module] section into your baseline and switch $module on?"; then
                        copy_example_section "$module"
                    else
                        cyan "$module stays off."
                    fi
                elif set_scope_skip remove "$module"; then
                    green "$module is on: it runs in every full audit."
                fi
            else
                if set_scope_skip add "$module"; then
                    yellow "$module is off: full audits leave it out, and their report says so."
                    [ "$module" = "reaper" ] && yellow "Reaper's own health will no longer be checked."
                fi
            fi
        done
    done
}

choose_module() {
    local i=0 module choice
    printf '\n'
    for module in $MODULES; do
        i=$((i + 1))
        printf '  %d  %-15s %s\n' "$i" "$module" "$(module_title "$module")"
    done
    printf '\nCheck number (Enter to go back): '
    read -r choice || return 0
    i=0
    for module in $MODULES; do
        i=$((i + 1))
        if [ "$choice" = "$i" ]; then
            run_child --module "$module"
            return 0
        fi
    done
}

# Print one menu status line: $1 label, $2 colour, $3 value.
menu_status() {
    printf "  ${MENU_LABEL}%-14s${RESET}$2%s${RESET}\n" "$1" "$3"
}

# Print one menu option: $1 key, $2 text.
menu_option() {
    printf "  ${MENU_TITLE}%-2s${RESET} %s\n" "$1" "$2"
}

menu_rule() {
    printf "${MENU_RULE}%s${RESET}\n" "  ==========================================================="
}

addon_menu() {
    local choice baseline baseline_c schedule schedule_c state action email email_c skips total
    while :; do
        clear
        case "$(baseline_state)" in
            ready)
                if [ "$(baseline_firmware)" != "$(nvram get innerver 2>/dev/null)" ] &&
                   [ -n "$(baseline_firmware)" ]; then
                    baseline="ready, but the firmware changed: run the self-test (4)"
                    baseline_c="$MENU_WARN"
                else
                    baseline="ready"; baseline_c="$MENU_GOOD"
                fi
                ;;
            placeholders) baseline="still has REPLACE values"; baseline_c="$MENU_WARN" ;;
            *)            baseline="has errors"; baseline_c="$MENU_BAD" ;;
        esac
        state="$(schedule_state)"
        case "$state" in
            on)     schedule="on ($(schedule_times_text))"; schedule_c="$MENU_GOOD"
                    action="Turn the schedule off" ;;
            off)    schedule="off"; schedule_c="$MENU_WARN"; action="Turn the schedule on" ;;
            manual) schedule="on (set up by hand)"; schedule_c="$MENU_WARN"
                    action="Let secaudit manage the schedule" ;;
            other)  schedule="on, runs $(foreign_dir)"; schedule_c="$MENU_WARN"
                    action="Switch the schedule to $SCRIPT_DIR" ;;
            *)      schedule="partly on (turn it on again to repair)"; schedule_c="$MENU_BAD"
                    action="Turn the schedule on" ;;
        esac
        case "$(email_state)" in
            ready)      email="set up"; email_c="$MENU_GOOD" ;;
            no_library) email="library missing (option 8 sets it up)"; email_c="$MENU_BAD" ;;
            *)          email="not set up in amtm (results show here only)"; email_c="$MENU_WARN" ;;
        esac

        menu_rule
        printf "  ${MENU_TITLE}%s${RESET}\n" "secaudit $SCRIPT_VERSION - security audit for Reaper firmware"
        menu_rule
        menu_status "Installed in:" "$MENU_LABEL" "$SCRIPT_DIR"
        menu_status "Baseline:" "$baseline_c" "$baseline"
        skips="$(scope_skips | grep -c .)"
        total="$(( $(echo "$MODULES" | wc -w) ))"
        if [ "$skips" = 0 ]; then
            menu_status "Checks:" "$MENU_GOOD" "all $total"
        else
            menu_status "Checks:" "$MENU_WARN" "$((total - skips)) of $total (off: $(scope_skips | tr '\n' ' '))"
        fi
        menu_status "Schedule:" "$schedule_c" "$schedule"
        menu_status "Email:" "$email_c" "$email"
        menu_rule
        printf '\n'
        menu_option 1 "Run a full audit now"
        menu_option 2 "Run one check"
        menu_option 3 "Choose which checks run"
        menu_option 4 "Self-test (run after every firmware upgrade)"
        menu_option 5 "Edit your baseline (how your router should be set up)"
        menu_option 6 "$action"
        menu_option 7 "Change the schedule times"
        menu_option 8 "Send a test email (sets up email if needed)"
        menu_option 9 "Check for updates"
        menu_option 10 "Uninstall"
        menu_option e "Exit"
        printf '\n'
        printf 'Choose an option: '
        read -r choice || exit 0

        case "$choice" in
            1) run_child --run-all ;;
            2) choose_module ;;
            3) choose_scope ;;
            4) run_child --selftest ;;
            5) edit_baseline; pause ;;
            6)
                if [ "$state" = "on" ]; then schedule_off; else schedule_on; fi
                pause
                ;;
            7) change_schedule_times; pause ;;
            8) send_test_email; pause ;;
            9)
                addon_update
                pause
                [ "$ADDON_UPDATED" = 1 ] && exec sh "$SCRIPT_DIR/$SCRIPT_NAME"
                ;;
            10)
                addon_uninstall
                [ "$ADDON_REMOVED" = 1 ] && exit 0
                pause
                ;;
            e|E|q|Q) exit 0 ;;
        esac
    done
}

# Management commands change the router, so they need someone at the terminal.
require_attended() {
    if [ "$MODE" != "interactive" ]; then
        log_msg "ERROR: $1 is interactive mode only."
        exit 1
    fi
}

#===================================================================#
# Script mainline processing
#===================================================================#
umask 077
mkdir -p "$LOG_DIR" || exit 1

if [ $# -gt 2 ]; then
    red "[ERROR] Too many arguments!"
    show_help
    exit 1
fi

# SECAUDIT_ATTENDED is for test runs: dropbear here gives no output with ssh -tt.
if [ -n "${SECAUDIT_ATTENDED:-}" ] || tty >/dev/null 2>&1; then MODE="interactive"; else MODE="unattended"; fi
if [ "$MODE" = "interactive" ]; then
    # Management commands keep earlier output (e.g. --install) on screen.
    case "$1" in
        ""|--install|--update|--uninstall|--schedule|--startup|--version|--help) ;;
        *) clear ;;
    esac
else
    # The report is emailed, so it carries no terminal escape codes.
    RED_TEXT='' GREEN_TEXT='' YELLOW_TEXT='' CYAN_TEXT='' RESET=''
fi

if [ "$#" = 0 ] && [ "$MODE" = "unattended" ]; then
    log_msg "CRITICAL: No arguments passed to unattended mode. Execution halted."
    exit 1
fi

case "$1" in
    "")          addon_menu ;;
    --help)      show_help; exit 0 ;;
    --install|--update|--uninstall)
        require_attended "$1"
        if [ "$#" -ne 1 ]; then
            red "[ERROR] $1 does not accept additional arguments."
            show_help
            exit 1
        fi
        case "$1" in
            --install)   addon_install ;;
            --update)    addon_update ;;
            --uninstall) addon_uninstall ;;
        esac
        ;;
    --schedule)
        require_attended "$1"
        case "$2" in
            on)  schedule_on ;;
            off) schedule_off ;;
            *)
                red "[ERROR] --schedule needs 'on' or 'off'."
                show_help
                exit 1
                ;;
        esac
        ;;
    --startup)
        if add_cron_jobs; then
            log_msg "Scheduled secaudit cron jobs from $SCRIPT_DIR"
        else
            log_msg "ERROR: could not add secaudit cron jobs"
            exit 1
        fi
        ;;
    --run-all)
        if [ "$#" -ne 1 ]; then
            red "[ERROR] --run-all does not accept additional arguments."
            show_help
            exit 1
        fi

        run_audit "$MODULES"
        ;;
    --version)
        echo "secaudit $SCRIPT_VERSION"
        exit 0
        ;;
    --selftest)
        if [ "$#" -ne 1 ]; then
            red "[ERROR] --selftest does not accept additional arguments."
            show_help
            exit 1
        fi
        selftest
        ;;
    --notify)
        if [ "$#" -ne 1 ]; then
            red "[ERROR] --notify does not accept additional arguments."
            show_help
            exit 1
        fi

        # Both always run; either failing fails the run, so cron logs show it.
        status=0
        notify_review || status=1
        notify_watch || status=1
        exit "$status"
        ;;
    --module)
        if [ "$MODE" != "interactive" ]; then
            log_msg "ERROR: Single-module execution is interactive mode only."
            exit 1
        fi

        if [ "$#" -ne 2 ]; then
            red "[ERROR] --module requires a module name."
            show_help
            exit 1
        fi

        case " $MODULES " in
            *" $2 "*) ;;
            *)
                red "[ERROR] Unknown module: $2"
                show_help
                exit 1
                ;;
        esac

        run_audit "$2" named
        ;;
    *)
        red "[ERROR] invalid parameter passed"
        show_help
        exit 1
        ;;
esac
