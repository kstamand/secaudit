# Changelog

Versions match `SCRIPT_VERSION` in `audit_security.sh`.

## 1.0.0 (unreleased)

- Reaper-only audit of nvram hardening, login sources, listeners, process
  origins, bridges, file integrity and the OUTPUT firewall hook.
- `[reaper]` module: checks the rwatch watchdog, firewall witnesses and Security
  Review, which Reaper itself covers, instead of re-checking what they watch.
- `--notify`: emails each new Security Review item and watchdog change once.
- `--selftest` and `check=firmware:` in `[reaper]`: flag firmware upgrades and
  verify the undocumented Reaper files and settings SecAudit relies on.
- `--version`; generic `baseline.conf.example`; GPL-3.0-or-later `LICENSE`.
- Menu (run with no arguments): run audits, self-test, edit the baseline, turn
  the schedule on or off, check for updates, uninstall.
- `--install`, `--update`, `--schedule on|off`, `--startup`, `--uninstall`,
  `--help`. The schedule is one marked line in `services-start`. An existing
  schedule (hand-written, or another copy's) is shown and, if the user agrees,
  replaced, so nothing has to be edited by hand.
- After a firmware upgrade, the menu flags it and a clean self-test offers to
  accept the new firmware in `baseline.conf`: one keypress instead of an edit.
- Install and update download from the latest GitHub release and check every
  file against its `SHA256SUMS`; `make_release.sh` builds the release files.
- `[scope]` in `baseline.conf`: `skip=<check>` lines leave checks out of full
  audits (a skipped check's section may be omitted); reports say what was
  skipped. Menu option 3, "Choose which checks run", switches checks on and off,
  and offers to copy a missing section from `baseline.conf.example`.
  The menu is renumbered: self-test 4, baseline 5, schedule 6, times 7,
  updates 8, uninstall 9.
- A run starts with "secaudit running a full audit..." (or "the <check>
  check...") instead of listing every module.
- Email setup: SecAudit offers to download Martinski W.'s shared email library
  (at install, from the new menu option 8 "Send a test email", and in "Check
  for updates"), only with the user's say-so and never in scheduled runs. The
  menu's Email line says whether amtm or the library is missing. Updates and
  uninstall move to options 9 and 10.
- Menu "Change the schedule times": the nightly audit hour and the alert
  interval, saved in `settings.conf` and kept by updates.
