# Changelog

Versions match `SCRIPT_VERSION` in `audit_security.sh`.

## 0.1.0 (2026-11-05)

First public release, a proof-of-concept. Feedback welcome in SecAudit's
SNBForums thread.

**Audits** (nightly, or on demand)

- Compares the router with your `baseline.conf`: router settings (nvram), where
  admin logins come from, listening ports, where running programs come from,
  bridges and their members, the `/etc/passwd` fingerprint, programs in `/tmp`
  and `/var`, and the OUTPUT firewall hook.
- Checks that Reaper's own watchdog (`rwatch`), firewall witnesses and Security
  Review are working, rather than re-checking what they watch.
- `[scope]` in the baseline switches checks off; reports always say which
  checks were skipped.

**Alerts**

- Every 10 minutes, emails each new Security Review item and each watchdog
  change (state, CRITICAL alarms, red firewall witnesses) once.

**Menu** (run `secaudit` with no arguments)

- Run a full audit or one check; choose which checks run; self-test; edit the
  baseline; turn the schedule on or off and change its times; send a test
  email; check for updates; uninstall.
- An existing hand-written schedule, or another copy's, is shown and replaced
  only if you agree.

**Firmware upgrades**

- `check=firmware:` flags an upgrade. The self-test verifies the undocumented
  Reaper files SecAudit reads, and if it's clean, offers to accept the new
  firmware with one keypress.

**Install and updates**

- Downloads from the latest GitHub release and checks every file against its
  `SHA256SUMS`. Nothing is downloaded unless you're at the terminal and agree.
- Offers to install Martinski W.'s shared email library; email settings come
  from amtm (`amtm`, then `em`).
