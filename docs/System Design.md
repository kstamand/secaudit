# SecAudit Overview

## Purpose

SecAudit is a read-only security posture audit for routers running Reaper firmware. It compares the router's current running state against operator-defined expectations in a configurable baseline.

The audit can be run interactively from a router command-line session or as a scheduled job (for example, nightly). Running `audit_security.sh` with no arguments at a terminal opens a menu that installs, schedules, updates and uninstalls it, edits the baseline and runs audits. Interactive runs display summary and detailed results in the CLI. Scheduled runs can send finding results by email.

## Scope and Intended Audience

SecAudit is intended for router operators who are comfortable working at the command line and want visibility into what an audit checks and how findings are determined. It is better suited to users who want to understand and configure their router's security posture than to users looking for an add-on that automatically manages security for them.

SecAudit applies only to Reaper firmware.

## Requirements

### Core requirements

- Reaper firmware.
- JFFS and custom scripts enabled.
- The native Reaper BusyBox environment.

### Scheduled operation and email reporting

- If SecAudit is configured to run on a scheduled basis, AMTM email must be configured, tested, and verified as working (`amtm`, then `em`).
- Email is sent with Martinski W.'s shared email library. SecAudit offers to download it, at install or from the menu, when someone is at the terminal; scheduled runs never download it. The menu's "Send a test email" confirms the whole path.
- A scheduled run sends an email report only when exceptions are detected. No email is sent when the audit finds no exceptions.

Interactive CLI runs display their results in the terminal. Email is not used during interactive runs, except the menu's test email.

### Security Review and watchdog alerts

`audit_security.sh --notify` emails new items from Reaper's Security Review, which has no alerting of its own. It also emails changes in the `rwatch` watchdog's state, its CRITICAL alarms and its red firewall witnesses. Run it from cron every 10 minutes or so. It needs Security Review switched on, with a baseline accepted on the Firewall page, Status tab.

### Firmware upgrades

SecAudit reads Reaper files and nvram keys that are not a documented interface, so an upgrade can break it silently. To prevent that, the baseline records the firmware it was verified on (`check=firmware:` in `[reaper]`). A different firmware is a finding until the operator runs `audit_security.sh --selftest`, fixes any failure, and updates that line.

## Operating Principles

- **Read-only audits:** Audits and alerts do not modify the router's state. Only the management commands (install, schedule, update, uninstall) write anything, and only SecAudit's own files and the lines it marks `# secaudit` in `services-start` and `profile.add`.
- **No remediation:** SecAudit reports findings; it does not attempt to fix them.
- **Evidence-based:** Findings are based on observed router state and configured baselines.
- **Runs locally:** The audit runs entirely on the target router.
- **Limited dependencies:** Runtime dependencies are limited to the native Reaper and BusyBox environment.
- **Defined categories and grammar:** Audit modules use predefined categories and baseline grammar.
- **Operator-defined expectations:** The router operator defines the expected state through the available categories and baseline declarations.
- **Findings are not firmware verdicts:** An audit finding is not, by itself, evidence of a firmware defect.

## Configuration Model

- **Baselines - `baseline.conf`:** Defines the expected state using SecAudit's supported baseline grammar. The distributed file is a sample and includes explanatory comments and example declarations.
- **Scope - `[scope]` in `baseline.conf`:** Optional `skip=<module>` lines leave modules out of full audits, so operators need not build sections they do not want. Every report states which modules were skipped. The menu's "Choose which checks run" maintains it.
- **Audit modules:** Examine the current router state and report findings against the applicable baselines.
- **Controller - `audit_security.sh`:** Coordinates execution, validates configuration, provides shared services to modules, handles errors, consolidates results, and produces the final report.

Changes to predefined categories or baseline grammar may require corresponding changes to SecAudit's implementation. Users maintaining a customized fork are responsible for keeping those changes compatible.

## Audit Modules

The modules examine the following areas against configured expectations:

| Module         | What it examines                                                              |
|----------------|-------------------------------------------------------------------------------|
| Authentication | Login-related activity recorded in system logs, including sources.            |
| Configuration  | Current NVRAM settings.                                                       |
| Firewall       | Defined firewall rules.                                                       |
| Integrity      | Hashes of baseline files, and executables in forbidden paths.                 |
| Listeners      | Open and communicating network ports.                                         |
| Processes      | Executable file locations against approved locations defined in the baseline. |
| Segmentation   | Currently running network bridges.                                            |

The descriptions above summarize the stated module responsibilities; consult the release's implementation and documentation for exact coverage.

## Architecture Overview

The following diagram summarizes the logical flow:

```text
baseline.conf -> baseline validation -> modules -> final report
```

`audit_security.sh` validates the baseline, runs each module, and reports the results. `--notify` separately reports new Security Review items.

## Directory Structure

Runtime deployment: `/jffs/addons/secaudit/`

```text
/jffs/addons/secaudit/
├── audit_security.sh
├── baseline.conf              # created from baseline.conf.example at install; never overwritten
├── baseline.conf.example      # refreshed by updates, for comparing new options
├── gen_hashes.sh              # maintenance utility; not invoked by the audit
└── settings.conf              # schedule times set from the menu; kept by updates
```

The script resolves its paths from its own location, so a copy under `/jffs/addons/test/secaudit/` is independent of production. Run output (`secaudit.log`, `secaudit_mail.log`) is written to `/tmp`, in one directory per install, not to `/jffs`.

`smoke_test.sh` and `addon_test.sh` are repository-only test tools, and `make_release.sh` is the maintainer's release tool; none is installed on the router.

---

## Limitations and Operator Responsibilities

SecAudit evaluates observed router state against configured expectations. Users are responsible for ensuring that their baselines accurately reflect their firmware version, enabled features, installed add-ons, and intended configuration. An incorrect or incomplete baseline may produce misleading findings or fail to identify an unexpected condition.

SecAudit is an auditing tool, not a security enforcement or remediation system. It does not correct findings, guarantee that all security issues will be detected, or replace appropriate router administration and security practices.

The supplied `baseline.conf.example` is a sample, not a universal set of correct expectations. Reaper firewall chains and rules, user customizations, Guest Network Pro, add-ons, and other configuration choices may require baseline changes.

Operators should review the findings in context and verify unexpected results against the router's actual configuration and intended behavior. A clean report should not be interpreted as a guarantee that the router is secure.

## Persistence requirements

The menu's "Turn the schedule on" (or `--schedule on`) adds two cron jobs, a nightly `--run-all` (`secaudit_run`, 03:00 by default) and `--notify` (`secaudit_notify`, every 10 minutes by default), and one marked line to `/jffs/scripts/services-start` that re-adds them after a reboot:

```sh
/jffs/addons/secaudit/audit_security.sh --startup & # secaudit
```

The menu's "Change the schedule times" sets the audit hour (0-23) and the alert interval (5, 10, 15, 30 or 60 minutes). They are saved in `settings.conf`, applied at once if the schedule is on, and used by `--startup` at boot.

It refuses while the baseline is invalid or still holds `REPLACE` values. If `services-start` or cron already runs `audit_security.sh` another way (set up by hand, or by another copy), it shows those lines and jobs and, if the operator agrees, removes them and installs its own schedule, so audits never run twice and nothing has to be edited by hand. Reaper's Security Review reports the `services-start` change; the operator reviews and accepts it.
