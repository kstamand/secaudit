# SecAudit Architecture

**Target:** Reaper firmware only (RT-BE88U, Reaper noMCP)

## 1. Purpose

SecAudit is a local, read-only security audit for a Reaper router. It does two jobs:

- **Live checks:** it compares running router state with `baseline.conf`, covering what Reaper does not.
- **Alerts:** it emails new items from Reaper's Security Review, which has no alerting of its own.

It never changes router state and never remediates. A finding is a difference from the baseline, not evidence of a firmware defect. SecAudit is independent of Reaper and does not speak for it.

## 2. What Reaper covers, and what SecAudit covers

| Area | Covered by |
|---|---|
| /jffs scripts and configs, SSH keys, cron | Security Review, alerted by `--notify` |
| Exposure and protection settings in nvram (`RV_NV_S` in rc/rwatch.c, including `rwarden_dns`) | Security Review, alerted by `--notify` |
| Failed-login bursts | Security Review, alerted by `--notify` |
| Watchdog health (`rwatch.state`, CRITICAL syslog lines) | `rwatch`; checked by `audit_reaper`, alerted by `--notify` |
| INPUT/FORWARD hooks (F8i/F8f) and guest/VLAN zone isolation → br0 (F2.*) | Firewall witnesses (`reaper_fwsim`); checked by `audit_reaper`, alerted by `--notify` |
| Firewall policy and chain drift | Reaper; SecAudit checks only the rules declared in the baseline |
| Other security nvram settings (my service and hardening choices) | `audit_configuration` |
| OUTPUT hook `REAPER_HOOK_O` (no witness covers OUTPUT) | `audit_firewall` |
| Successful logins from unknown sources | `audit_authentication` |
| Executables dropped in `/tmp` and `/var` | `audit_integrity` |
| `/etc/passwd` changes (outside /jffs) | `audit_integrity` |
| Listening ports | `audit_listeners` |
| Where processes execute from | `audit_processes` |
| Bridge membership | `audit_segmentation` |

**Rule of thumb:** if Reaper already watches something, SecAudit checks Reaper's health in `audit_reaper` and does not re-add the item to `baseline.conf`.

## 3. Layout

```text
/jffs/addons/secaudit/
├── audit_security.sh
├── baseline.conf          # created from the example at install; never overwritten
├── baseline.conf.example  # generic starting baseline; refreshed by updates
├── gen_hashes.sh          # maintenance utility, not used by the audit
└── settings.conf          # schedule times; written by the menu, never by updates
```

These four are `ADDON_FILES` minus `baseline.conf`; `--install` and `--update` download exactly those. Repository only: `smoke_test.sh`, `addon_test.sh`, `make_release.sh`, `README.md`, `CHANGELOG.md`, `LICENSE` and `docs/`.

Outside the addon directory SecAudit owns one line each, marked `# secaudit`: the `--startup` hook in `/jffs/scripts/services-start` and a `secaudit` alias in `/jffs/configs/profile.add`.

`audit_security.sh` holds everything: baseline parsing, reporting, one `audit_<module>()` function per module, the notifier, and the mainline. Paths come from the script's own location, so a test install under `/jffs/addons/test/secaudit/` is independent of production.

Run output goes to `/tmp/secaudit<install path>/`, not `/jffs`, because a file in `/jffs` would be Security Review drift.

| File | Contents |
|---|---|
| `secaudit.log` | Detail and summary records for the last run |
| `secaudit_mail.log` | Report attached to audit email |
| `baseline.parsed` | Normalized baseline rows |
| `review.state` | Lines the notifier has already reported |
| `review_mail.log` | Report attached to notifier email |
| `auth.seen` | Login lines already reported by `audit_authentication` |
| `watch.rwatch` | Last reported `rwatch.state` (`OK`, `FAIL <start>` or `unreadable`) |
| `watch.rules` | Last reported red firewall witness list |
| `watch.crit_line`, `watch.crit_on` | Last `rwatch` CRITICAL line seen, and whether this FAIL episode has alerted |
| `watch.events` | Watchdog changes found by this run |
| `watch_mail.log` | Report attached to watchdog email |

State files are written as `<name>.new` and renamed only after the email is sent (or, attended, discarded), so a failed send reports the same items again next run.

## 4. Commands

| Command | Behavior |
|---|---|
| `--run-all` | Validate the baseline, run every module in `MODULES` except those `[scope]` skips, report. Unattended runs email on findings or failures. |
| `--module <name>` | Attended only. Validate the baseline, run one module, report. Runs a module `[scope]` skips, with a note, unless its section is missing. |
| `--selftest` | Check that every undocumented Reaper interface SecAudit reads still exists and parses, and print the manual checks that remain. Exits 1 on any FAIL. Run after every firmware upgrade (section 13). Read-only, except that an attended run with no FAILs and a firmware different from `check=firmware:` asks to accept it; on yes, `set_baseline_firmware` rewrites only that value in `baseline.conf`. |
| `--version` | Print the version (`SCRIPT_VERSION`). |
| `--notify` | Report new Security Review items and watchdog changes (`rwatch` state, CRITICAL alarms, red firewall witnesses). Unattended runs email; attended runs print the current list and change nothing. |
| *(none)* | Attended: open the menu (section 4a). Unattended: error. |
| `--install` | Attended only. Download `ADDON_FILES` from `REPO_URL` into `ADDON_DIR`, create `baseline.conf` from the example if absent, add the `secaudit` alias. Does not turn on the schedule. |
| `--update` | Attended only. Download into `/tmp`, and if the version is newer and the user agrees, replace this copy's files. `baseline.conf` is never touched. |
| `--schedule on\|off` | Attended only. Add or remove the `services-start` hook and both cron jobs for this copy. |
| `--startup` | Re-add both cron jobs. Run by the `services-start` hook at boot. |
| `--uninstall` | Attended only. Schedule off, remove the alias and `ADDON_FILES`, ask before deleting `baseline.conf`, delete the `/tmp` run directory. |
| `--help` | Print usage. |

A run is attended if stdin is a tty. Test-only variables:

| Variable | Effect |
|---|---|
| `SECAUDIT_ATTENDED` | Force attended mode. Needed because `ssh -tt` gives no output on this router. |
| `SECAUDIT_NO_MAIL` | Suppress email. |
| `SECAUDIT_LOG_DIR` | Override the run directory. |
| `SECAUDIT_REVIEW_JSON` | Override the Security Review report path. |
| `SECAUDIT_RWATCH_STATE` | Override the `rwatch.state` path. |
| `SECAUDIT_FWSTATUS_JSON` | Override the `fwstatus.json` path. |
| `SECAUDIT_RWATCH_WITNESS` | Override the red-witness list path. |
| `SECAUDIT_SYSLOG` | Override the syslog read for `rwatch` CRITICAL lines. |
| `SECAUDIT_ADDON_DIR` | Override where `--install` installs (`/jffs/addons/secaudit`). |
| `SECAUDIT_REPO_URL` | Override the download base URL; `file://` works for tests. |
| `SECAUDIT_SERVICES_START` | Override the `services-start` path. |
| `SECAUDIT_PROFILE_ADD` | Override the `profile.add` path. |

## 4a. Addon management

Management code lives in its own section of `audit_security.sh`, before the mainline. Audits never call it.

- **Menu:** shows version, location, baseline state (`ready`, `placeholders`, `invalid`), how many checks run (`all 8`, or `6 of 8 (off: ...)`), schedule state (`on`, `off`, `partial`) and whether email is set up, then offers: 1 run a full audit, 2 run one check, 3 choose which checks run, 4 self-test, 5 edit baseline, 6 schedule on/off, 7 schedule times, 8 send a test email, 9 check for updates, 10 uninstall. Audits and the self-test run as a child process (`sh audit_security.sh --run-all`), so each starts with clean counters.
- **Downloads** (`fetch_files`): `curl -L` `SHA256SUMS` and each of `ADDON_FILES` from `REPO_URL`, the latest GitHub release (`.../releases/latest/download`), into `$LOG_DIR/download`. Each file's `sha256sum` must match its line in `SHA256SUMS`; a `.sh` must also start with `#!/bin/sh` and pass `sh -n`, and `audit_security.sh` must carry a `SCRIPT_VERSION`. Any failure discards everything and changes nothing.
- **What checksums prove:** a file is the one published in the release, not truncated, corrupted or swapped in transit. They come from the same release, so they do not protect against someone who controls the GitHub account; signing with `openssl` (present on the router) would, and is a possible later step.
- **Releases** (`make_release.sh`, on the development machine): refuses unless on a clean `main`, with a dated `CHANGELOG.md` entry for `SCRIPT_VERSION` and no existing tag; shellchecks the scripts; builds `dist/v<version>/` with `ADDON_FILES` and `SHA256SUMS`, plus the release notes from `CHANGELOG.md`; and prints the `git tag` and `gh release create` commands. It publishes nothing itself.
- **Replacing files** (`place_files`): copy to `.<name>.new` beside the target, then `mv`. The running script keeps reading its old, unlinked file, so updating from the menu is safe; the menu then `exec`s the new copy.
- **Firmware changed:** when the baseline is `ready` but `check=firmware:` differs from `nvram get innerver`, the menu shows "ready, but the firmware changed: run the self-test (4)", and the self-test offers to accept it (section 4). Reaper releases often (eight RT-BE88U releases from 28 Oct to 4 Nov 2026), so this has to take one keypress.
- **Edit baseline:** `$EDITOR`, else `nano`, else `vi`; then `validate_baseline`, and list any `check=` lines still holding `REPLACE`.
- **Owned lines:** `hook_line` and `alias_line` build the exact marked lines; `append_line` adds one only if absent, and `remove_line` deletes only that exact line, rewriting the file in place so its permissions stay.
- **This copy's jobs only:** every copy names its jobs `secaudit_run` and `secaudit_notify`, so a test copy and production would collide by name. `own_cron_jobs` matches a job by its full command path; schedule off and uninstall delete a job only if it is this copy's.
- **Foreign schedules:** `foreign_hook_lines` (uncommented `services-start` lines that run `audit_security.sh`, other than this copy's hook) and `foreign_cron_jobs` (`cru l` lines that run it, other than this copy's jobs). `schedule_state` reports `on`, `manual` (foreign, for this copy's path), `other` (foreign, for another copy; `foreign_dir` names it), `partial` or `off`; the menu labels option 6 to match ("Turn the schedule off", "Let secaudit manage the schedule", "Switch the schedule to <this copy's folder>", "Turn the schedule on").
- **Schedule on** refuses if the baseline is not `ready`, and warns if `jffs2_scripts` is not `1`. If a foreign schedule exists, `take_over_schedule` lists it and asks. On yes it backs `services-start` up to `$LOG_DIR`, removes each foreign line with `remove_line`, and checks the result with `sh -n`; if a line could not be removed or the file no longer parses (for example, the line sat inside an `if` block), it restores the backup and stops. Only then does it `cru d` the foreign jobs by their ids and add this copy's schedule.
- **Choose which checks run** (option 3, `choose_scope`): lists `MODULES` with on/off and `module_title`; a number toggles one. `set_scope_skip` adds `skip=<module>` just under the `[scope]` header (creating the section at the end of the file if absent) or deletes that exact line, then validates and restores the previous file if the result is invalid (for example, skipping the last check). Switching on a module whose section is missing asks first; on yes, `copy_example_section` appends that section from `baseline.conf.example` (header to the next header) and removes the `skip=` line, restoring the previous file if the result is invalid, then points the user to "Edit your baseline", naming any `REPLACE` values.
- **Schedule times:** `settings.conf` holds `RUN_HOUR` (0-23) and `NOTIFY_MINUTES` (one of `NOTIFY_CHOICES`: 5, 10, 15, 30, 60). `load_schedule_times` parses it with `sed` (never sources it) and falls back to `DEFAULT_RUN_HOUR` 3 and `DEFAULT_NOTIFY_MINUTES` 10 for a missing file or invalid value. `add_cron_jobs` builds `0 <hour> * * *` and `*/<n> * * * *` (`0 * * * *` for 60), so `--startup` at boot uses the saved times. Menu option 7, `change_schedule_times`, asks for both (Enter keeps a value, a bad answer is asked again), writes the file via `.new` and `mv`, and re-adds the jobs at once if the schedule is `on`. A `manual` or `other` schedule keeps its own times until option 6 takes it over. Uninstall keeps `settings.conf` with `baseline.conf`, or deletes both.
- `REPO_URL` must point at a public repository for other routers to download from.

## 5. Audit flow

```text
baseline.conf -> validate_baseline -> baseline.parsed
                                           |
                     [scope] skip=?  ------+---- yes -> <module>-skipped record
                                           | no
                     get_baseline_category | one call per module
                                           v
                     audit_<module>() -> log_detail -> secaudit.log
                                           |
                     log_summary, after each module returns
                                           v
                     report on screen, or by email
```

`validate_baseline` is one awk pass over the whole file. Modules never parse baseline lines; they read `type|item|expected|severity` rows from `get_baseline_category`, with omitted severity already resolved.

`--run-all` passes over modules `[scope]` skips (section 6, Scope); `--module` runs one even if skipped. A run announces itself as "secaudit running a full audit..." or "secaudit running the <module> check...".

An invalid baseline stops the run before any module executes. In an unattended run that also sends an email, so a failed run is never silent.

## 6. Baseline

```text
[<module>]
default_criticality=<warn|alert>
check=<type>:<body>[:warn|:alert]
```

Every module in `MODULES` must have a section, unless `[scope]` skips it (see Scope, below), with exactly one `default_criticality`, which applies to its whole section. The exception is `[reaper]` (listed in `OPTIONAL_MODULES`): its checks are fixed, so the section may be omitted and takes no assertions. Severity on a check overrides it. Comments are full lines, or ` # text` after a value.

| Module | Assertion | Meaning |
|---|---|---|
| authentication | `auth_source:<IPv4>` | Authorized source for successful logins |
| configuration | `nvram:<name>:<expected>` | nvram value; expected may be empty |
| firewall | `rule:<chain> <rule-spec>:present` | Rule exists, by `iptables -C` |
| integrity | `file_hash:<path>:<sha256>` | File matches the hash |
| integrity | `forbidden_path:<dir>:present` | No executable regular files below the directory |
| integrity | `forbidden_path_exclude:<dir>` | Exempt a subtree |
| integrity | `forbidden_file_exclude:<file>` | Exempt one file |
| listeners | `allowed_port:<port>:<tcp\|udp>:<lan\|external>` | Declared listener and scope |
| processes | `exec_origin:<root>` | Trusted executable root |
| segmentation | `bridge:<bridge>:present` | Bridge exists |
| segmentation | `bridge_membership:<bridge>:<members>` | Exact member set |
| reaper | `firmware:<innerver>` | Firmware the baseline was verified on; other checks are fixed (section 8) |

### Scope

```text
[scope]
skip=<module>
```

`[scope]` is optional and takes only `skip=` lines, one per module to leave out of `--run-all`. Validation rejects an unknown or duplicate name, any other line, and skipping every module. A skipped module's section may be omitted; if present it is still validated. `scope_skips` reads the names straight from `baseline.conf`.

In a run, a skipped module writes a `<module>-skipped` record instead of running, and its summary row reads "skipped ([scope] in baseline.conf)". Below the table the report states "N of M checks ran; [scope] in baseline.conf skips: ...", plus a line when `reaper` is skipped, so a clean report never hides reduced coverage; unattended runs also log the skipped list. `[scope]` does not affect `--notify`, `--selftest` or the firmware check.

The baseline is data. It is never evaluated as shell code, except that a `rule` spec is deliberately word-split into `iptables` arguments.

## 7. Results

Each record ends in one status:

| Status | Meaning | Counts as a check |
|---|---|---|
| `pass` | Matches the baseline | Yes |
| `warn`, `alert` | Differs from the baseline | Yes |
| `execution_failure` | Could not be evaluated | Yes |
| `not_evaluable` | A normal race, such as a process exiting | No |

Findings and execution failures are separate. A finding does not make the script fail, and a failure is never reported as a finding. Exit status is 0 unless an execution failure occurred.

Summaries are derived from the detail records, so modules keep no counters:

```text
total = pass + warn + alert + execution_failure
```

Detail records are `|`-delimited, because values can contain colons. Summary records are `<module>-summary:total:pass:warn:alert:failed`. A module `[scope]` skips writes only `<module>-skipped`, which is not a summary and counts no checks; the report shows it as a skipped row and states how many modules ran.

## 8. Modules

**authentication** reads `/jffs/syslog.log` for successful dropbear pubkey and WebUI logins, and checks each source. Each event is one check. Findings use the most severe criticality declared. Having no events is not a finding. Rotated logs are not read.

**configuration** takes one `nvram show` snapshot, which decides both existence and value, because `nvram get` cannot tell an empty value from a missing variable. A missing variable is an execution failure.

**firewall** runs `iptables -C` for each declared rule. A rule that is absent is a finding. A missing chain or an `iptables` error is an execution failure. iptables here is v1.4.15, with no `-w` option and no xtables lock. It does not evaluate Reaper policy, which Reaper owns.

**integrity** hashes declared files, and walks each forbidden path for executable regular files, including setuid, setgid and sticky files that are also executable. Symlinks are not followed. BusyBox `find` has no `-type`, `-perm` or `-prune`, so each path goes through `ls`. A failed `-exec` does not change `find`'s status, so failures are marker lines. Rootfs is a read-only squashfs, so firmware binaries are not hashed. Exclusions are themselves checked, so stale ones stay visible.

**listeners** classifies IPv4 listeners by binding, not firewall reachability. `external` means bound to a WAN interface or a wildcard, so a port firewalled from WAN can still be `external`. Undeclared listeners are alerts, except Avahi's dynamic UDP ports. Loopback and IPv6 are not audited.

**processes** uses `/proc/<pid>/exe` as the authority, so a script run by `/bin/sh` counts as `/bin/sh`. Kernel threads are excluded. A deleted executable is a finding, and trusted roots match whole path components. Exited and zombie processes are `not_evaluable`. `/opt` is not trusted unless the baseline says so.

**segmentation** compares declared bridges and members with `brctl show`, the only source. Membership is compared as a sorted set. Firewall flow policy is not part of it.

**reaper** compares `nvram get innerver` with the baseline's `firmware` assertion, if one is declared. Upgrades reboot and clear `/tmp`, so the acknowledged version has to live in the baseline; a mismatch (`firmware_changed_run_selftest`) stays until the line is updated. Its other checks are fixed, so the category is optional. It requires `rwatch_enable=1` and the `#rwatch#` cron job, then reads `rwatch.state` (`OK`, or `FAIL <uptime> <ticks>`). For the first 900 seconds after boot (`HEALGRACE` in rc/rwatch.c) the state is `not_evaluable`. When `reaper_fwsim` exists, it reads `fwstatus.json` and alerts if it is unreadable, stale or has red witnesses. Last, it requires `rwatch_review=1` and an accepted (armed) Security Review baseline.

## 9. Security Review notifier

`--notify` reads `/tmp/reaper/review.json`, which `rwatch` rewrites every 5 minutes. This is an internal Reaper format, not a documented interface, so check it before changing firmware.

- It emails only lines not reported before, so each change alerts once and accepting items never alerts.
- A file that changes again while pending alerts again.
- Failed-login notices and world-writable paths are reported the same way.
- It also alerts when Review is switched off, has no accepted baseline, or its report is missing, stale (older than 30 minutes), truncated or unreadable.
- A parser failure counts as unreadable, so a fault can never look like nothing pending.
- It stays silent for the first 15 minutes after boot, while `rwatch` writes its first report.
- State is in `/tmp`, so after a reboot, open items alert once more.
- If email fails, state is not updated, so the next run tries again.

`rwatch` pauses Review while a firewall change is armed, so an armed window over 30 minutes raises one stale alert.

The report text is untrusted, because a cron line or filename can contain anything. It is only printed, never evaluated.

`--notify` also emails watchdog changes, each once when it happens: `rwatch.state` failing, recovering or becoming unreadable; the first new `rwatch` CRITICAL syslog line in a FAIL episode; and changes to the red firewall witness list (`rwatch_witness`). Like Review, it is silent during the boot grace, keeps state in `/tmp`, and commits state only after the email is sent.

## 10. Email

Email uses Martinski W.'s shared library, `/jffs/addons/shared-libs/CustomEMailFunctions.lib.sh` (GPL-3.0, shared by many Merlin addons), which sends through amtm's email settings (`/jffs/addons/amtm/mail/email.conf` and `emailpw.enc`, set up with amtm's `em`). SecAudit holds no credentials or transport logic. Reports carry no terminal escape codes. An email failure is logged and never changes audit results. Attended runs do not send email, except the menu's test email.

`email_state` reports `no_amtm` (amtm's two files are missing), `no_library` or `ready`, and the menu's Email line shows it. The library is downloaded only by someone at the terminal who agrees: `offer_email_lib` at `--install` and from menu option 8 (default yes), and `update_email_lib` in "Check for updates". Both fetch `EMAIL_LIB_URL` (Martinski4GitHub/CustomMiscUtils, `master`) into `$LOG_DIR` with certificate checking on, require `#!/bin/sh`, `sh -n` and a `CEM_LIB_VERSION`, compare versions with `version_gt` (never sourcing the download to do it), and move the file into place. Unattended runs never download it: a missing library is logged with a pointer to the menu. Unlike SecAudit's own files, the library cannot be checked against `SHA256SUMS`; that is listed in the FAQ's known limits. Overrides for tests: `SECAUDIT_EMAIL_LIB_DIR`, `SECAUDIT_EMAIL_LIB_URL`, `SECAUDIT_AMTM_EMAIL_CONF`.

## 11. Coding rules

- BusyBox ash only, and only applets the router's BusyBox has (`busybox --list` on the router). No `stat`, `id`, `timeout` or `mktemp`.
- Establish behavior on the router rather than assuming it. BusyBox differs from GNU in ways that matter here: `split` treats a string separator as a regex, and `grep -f` with an empty pattern file selects nothing.
- Quote expansions unless splitting is intended. Use `printf` rather than `echo` for structured output.
- Never treat a tool failure as a clean result. If a check cannot be evaluated, say so.
- Keep the simplest thing that works. Justify added complexity.

## 12. Testing

`shellcheck -s dash` runs on every `.sh` file; the only exceptions are `SC1090`, `SC2059` and `SC3043` (`local`, which BusyBox ash supports) in `audit_security.sh`.

Both test scripts run on the router from `/tmp`. Neither sends email or changes the installed copy, `/jffs/scripts`, cron or the baseline. Copy them, with the files they test, into a folder in `/tmp` and run them there. From a computer, replace `admin@192.168.50.1` with your router's login and address:

```sh
ssh admin@192.168.50.1 'mkdir -p /tmp/sa_test'
scp -O audit_security.sh gen_hashes.sh baseline.conf.example smoke_test.sh addon_test.sh admin@192.168.50.1:/tmp/sa_test/
scp -O /path/to/your/baseline.conf admin@192.168.50.1:/tmp/sa_test/
ssh -n admin@192.168.50.1 'sh /tmp/sa_test/smoke_test.sh /tmp/sa_test; sh /tmp/sa_test/addon_test.sh /tmp/sa_test; rm -rf /tmp/sa_test'
```

To test an installed copy's own files instead, run `sh smoke_test.sh /jffs/addons/secaudit` from `/tmp`; it only reads that folder. Run them with stdin closed (`ssh -n`, or `< /dev/null`), so an unexpected question fails rather than waits.

`smoke_test.sh` runs against a disposable `/tmp` copy, with email off. It works with any valid baseline: each deliberate mismatch is made generically with awk (only a documentation address may log in, no port is allowed, programs may only run from `/smoke`, bridge `br99` is expected, every fingerprint is zeroed, the first nvram value is altered, the firmware is `smoke_firmware`). It covers a known-good run (a module `[scope]` skips counts as reported), result accounting, one deliberate mismatch per baseline module, a clean `--selftest`, invalid-baseline handling, the Security Review notifier, and, once uptime passes the 900-second boot grace, a failing watchdog in `audit_reaper` and the watchdog notifier's failure and recovery alerts. A module with no section is skipped, and `authentication` is skipped when the router log has no admin logins to test with. Firewall witnesses and CRITICAL syslog alerts are not tested, because they need a live red witness or Warden event.

`addon_test.sh` tests addon management in `/tmp` only, never against the real `services-start`, `profile.add` or cron. It points the `SECAUDIT_ADDON_DIR`, `SECAUDIT_REPO_URL=file://...`, `SECAUDIT_SERVICES_START` and `SECAUDIT_PROFILE_ADD` overrides at `/tmp`, and puts a stub `cru` first on `PATH`. It needs a `baseline.conf` that validates with no `REPLACE` values. It covers install, reinstall (baseline kept), schedule refusal (REPLACE values), take-over of a hand-written schedule (declined, accepted, and undone when removing the line would break `services-start`), another copy's same-named jobs (menu label, left alone by schedule off, moved on yes), schedule on (idempotent), `--startup`, the menu, schedule times (default times, saved and applied at once, shown in the menu, bad answers re-asked, 60 minutes, Enter keeps both, used by `--startup`, a damaged `settings.conf` falls back to defaults), firmware change (menu flag, self-test offer declined and accepted, only the firmware line changed), scope (skipped modules listed and not run, coverage line, `reaper` note, `--module` on a skipped module with and without its section, an omitted section valid only when skipped, unknown/duplicate/other lines and skip-all invalid, the menu switching a module off and on again with the file unchanged, and switching on a module with no section: declined leaves it off, accepted copies the example section verbatim and leaves the baseline valid), the start line ("secaudit running a full audit" / "the <module> check"), email (status without amtm, library missing, set up; test email without amtm points to amtm; declining leaves it out; Enter installs it and sends a test email; a bad download rejected; update offers a newer library; an up-to-date library reported; unattended runs never download it; install offers it), update (up to date, newer, rejected download, checksum mismatch, missing `SHA256SUMS`, `settings.conf` kept), uninstall (owned lines removed, nothing else changed) and the attended-only rule.

Test only in `/tmp`, or in a separate test install such as `/jffs/addons/test/secaudit/`. Executable files in `/tmp` are reported by `forbidden_path`, which is correct.

## 13. Before updating Reaper

After the upgrade, `--run-all` reports `firmware_changed_run_selftest` until you finish this list:

- Run `--selftest` and fix every FAIL. It automates the file, field, nvram and cron checks below; the MANUAL lines it prints are the rest.
- Update `check=firmware:` in `[reaper]` to the new `nvram get innerver`. An attended `--selftest` with no FAILs offers to do this; users only need that step.
- Run `--notify` and `--run-all`, and check for new findings.
- Confirm `review.json` still has the fields in section 9.
- Confirm the other undocumented Reaper interfaces SecAudit reads are unchanged:
  - `/tmp/reaper/rwatch.state` format: `OK` or `FAIL <uptime at start> <ticks>`.
  - `/tmp/reaper/fwstatus.json` fields `ok`, `ts` and `red`, and `/usr/bin/reaper_fwsim`.
  - `/tmp/reaper/rwatch_witness` (red-witness list, absent when none) and witness IDs F8i, F8f and F2.*.
  - `/tmp/reaper_fw/armed` (firewall change pending; pauses Review).
  - The syslog text `rwatch: CRITICAL:`.
  - nvram `rwatch_enable`, `rwatch_review` and `rwatch_iv`, and the `#rwatch#` cron ID.
  - `HEALGRACE` (900 s, `REAPER_GRACE_SECONDS`) and the stale age of 3 × `rwatch_iv` minutes, both in rc/rwatch.c.
  - Which nvram switches `RV_NV_S` watches; if one is dropped, add it back to `[configuration]`.
- Confirm `/tmp/rwarden` (an `[integrity]` exclusion) survives the Warden to Dreadwatch rename in 3.6.3, and update the "Warden block set" wording of the CRITICAL alert in `notify_watch`.
- Refresh the `/etc/passwd` hash if it changes, using `gen_hashes.sh`.

### Self-test results

`--selftest` (`selftest()` in `audit_security.sh`) is read-only and prints one line per check:

| Result | Meaning |
|---|---|
| `PASS` | The file, field, nvram key or cron job exists and parses as expected. |
| `FAIL` | Something SecAudit depends on is missing or changed format. Its results cannot be trusted until the script is fixed. Exit status is 1. |
| `WARN` | Works, but with reduced coverage (for example, no `reaper_fwsim`, no email library, or the baseline firmware differs from the running one). |
| `SKIP` | Within the 900-second boot grace; `rwatch` has not written its files yet. Run it again later. |
| `MANUAL` | Cannot be checked by a script (meanings in rc/rwatch.c, log wording). Check by hand. |

It proves formats, not meaning: a field can keep its name and change what it means, which is why the MANUAL lines remain.

**Keep it in step with the script.** Every Reaper path, nvram key, JSON field or cron ID the script reads must have a check in `selftest()` and a bullet in the list above. When you add a dependency, add both; when you remove one, remove both.
