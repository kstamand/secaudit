# SecAudit

> [!WARNING]
> **NOT YET RELEASED FOR PUBLIC USE.** SecAudit is an early proof-of-concept
> and is on hold. Please don't install it yet: there is no support thread, and
> it may change or be withdrawn without notice. This notice will be removed
> when it is ready.

**A nightly security check-up for routers running Reaper firmware.**

Reaper already watches a lot of your router's security for you. SecAudit adds
two things:

- **It checks the things Reaper doesn't.** You describe how your router
  *should* be set up (who may log in, which ports should be open, which networks
  exist, and so on). Every night SecAudit compares the router with that
  description and emails you if anything is different.
- **It emails you when Reaper spots something.** Reaper's Security Review and
  its watchdog record changes but don't send alerts. SecAudit checks them every
  10 minutes and emails you about anything new, once.

SecAudit only looks. It never changes your router's settings and never tries to
"fix" anything. What to do about a finding is always your decision.

Tested on an RT-BE88U running Reaper 3.7.1 beta (noMCP). It should work on other
Reaper routers, but your description will need your router's own details.

---

## Is SecAudit for you?

SecAudit is for people who want to **know what their router is doing** and are
willing to look into it when something changes. It is not set-and-forget
protection.

**It's a good fit if you:**

- are comfortable logging in to your router over SSH;
- can spend about 30 minutes describing your router: which ports should be open,
  which networks exist, where you log in from;
- will look into a finding and decide whether it's expected, rather than just
  accepting it.

**It's probably not for you if you:**

- want something that protects the router without your involvement;
- would rather not judge whether an open port or a new network is normal;
- only want to use the router's web pages.

What SecAudit is **not**:

- **Not a firewall or blocker.** It doesn't stop anything; it tells you when
  something changed.
- **Not proof that your router is secure.** A clean report means "matches your
  description", nothing more.
- **Not protection against someone who already controls your router.** It runs
  on the router itself, so it catches mistakes and unexpected changes, not a
  determined attacker.

If that sounds right, read on.

---

## SecAudit and Reaper

SecAudit is an **independent community addon**. It isn't part of Reaper, and it
isn't endorsed or supported by Reaper or its developer. **Please report SecAudit
problems in SecAudit's SNBForums thread, not Reaper's.**

SecAudit builds on Reaper's own work: its Security Review, its `rwatch`
watchdog and its firewall witnesses. Credit for those goes to Reaper; see the
[Reaper releases](https://github.com/TheUnboundDeveloper/AM-Reaper/releases).

- **It adds no work for Reaper.** SecAudit only reads files Reaper already
  writes. It never runs Reaper's tools and adds no load.
- **Reaper owes it nothing.** Those files aren't a documented interface and may
  change in any Reaper release. SecAudit expects that: its self-test and its
  firmware check detect a change, so Reaper has no compatibility to keep.
- **No duplication.** If Reaper adds a feature SecAudit provides, such as its
  own email alerts, SecAudit will retire its version.

---

## Before you start

You need:

1. **A router running Reaper firmware.**
2. **Custom scripts turned on.** In the router's web page, go to
   *Administration → System* and set **Enable JFFS custom scripts and configs**
   to *Yes*.
3. **SSH turned on**, so you can type commands on the router. Same page:
   set **Enable SSH** to *LAN only*. Then, from your computer:
   - Mac: open *Terminal* and type `ssh admin@192.168.50.1`
   - Windows: open *PowerShell* and type `ssh admin@192.168.50.1`

   Use your own router's login name and address if they're different.
4. **Reaper's Security Review turned on**, with a baseline accepted
   (*Firewall* page, *Status* tab), and Reaper's watchdog (`rwatch`) on.
5. **Optional, for email: email set up in amtm.** Type `amtm`, choose `em`
   (email settings), fill in your mail account, and send amtm's test email.
   Without it, SecAudit still works, but you only see results when you open
   the menu.

   SecAudit sends mail with Martinski W.'s shared email library, which many
   Merlin addons use. If it isn't on your router yet, SecAudit offers to
   download it when you install, or from menu option 8.

---

## Install

Log in to your router over SSH, then copy and paste this one line:

```sh
curl -fsSL https://github.com/kstamand/secaudit/releases/latest/download/audit_security.sh -o /tmp/audit_security.sh && sh /tmp/audit_security.sh --install
```

It installs SecAudit into `/jffs/addons/secaudit/` and asks whether to open the
menu. Say **y**.

Installs and updates come from SecAudit's latest GitHub release. Every file is
checked against the release's list of SHA-256 checksums, and if any file doesn't
match, nothing is installed.

From now on, open the menu any time by typing:

```sh
secaudit
```

(This works from your *next* SSH login. Until then use
`sh /jffs/addons/secaudit/audit_security.sh`.)

---

## The menu

```text
  ===========================================================
  secaudit 0.1.0 - security audit for Reaper firmware
  ===========================================================
  Installed in: /jffs/addons/secaudit
  Baseline:     ready
  Checks:       all 8
  Schedule:     on (audit 03:00, alerts every 10 min)
  Email:        set up
  ===========================================================

  1  Run a full audit now
  2  Run one check
  3  Choose which checks run
  4  Self-test (run after every firmware upgrade)
  5  Edit your baseline (how your router should be set up)
  6  Turn the schedule off
  7  Change the schedule times
  8  Send a test email (sets up email if needed)
  9  Check for updates
  10 Uninstall
  e  Exit
```

The box at the top tells you, at a glance, whether everything is ready:
green means fine, sand means something to do, rose means something is wrong.
Type a number and press Enter.

---

## Set up your baseline (one time, about 30 minutes)

Your **baseline** is SecAudit's description of how your router should be set up.
SecAudit starts you off with an example. You make it match *your* router.
Take your time here: a good baseline means no false alarms later.

**Don't need every check?** Choose **3, "Choose which checks run"** first and
switch off the ones you don't want. You then don't have to fill in their
sections. (More under *Choose which checks run*, below.)

1. **Choose 5, "Edit your baseline".** The file opens in a simple editor
   (`nano`). Lines starting with `#` are explanations; read them as you go.
2. **Change every value marked `REPLACE`.** For example, the firmware line wants
   your exact firmware version. To find it, type `nvram get innerver` at the
   router prompt.
3. **Save and exit** with *Ctrl+O*, *Enter*, *Ctrl+X*. SecAudit checks the file
   right away and tells you the line number of anything it doesn't understand.
4. **Set the password-file fingerprint.** At the router prompt, run:

   ```sh
   sh /jffs/addons/secaudit/gen_hashes.sh /jffs/addons/secaudit/baseline.conf
   ```

   Copy the `check=file_hash:...` line it prints into your baseline, replacing
   the line of zeros.
5. **Run one check at a time** (menu option 2). For each finding, work out what
   it is before you accept it. If it's something you set up on purpose, add it
   to your baseline. If you don't recognise it, find out what it is first.
6. **Run the self-test** (option 4). It should show no **FAIL** lines.
7. **Run a full audit** (option 1). When it shows nothing unexpected, you're
   done.

---

## Choose which checks run

Choose **3, "Choose which checks run"**. It lists the eight checks, each **on**
or **off**, with a line on what it looks at. Type a check's number to switch it.

- A check that's **off** is left out of every full audit, including the nightly
  one. Its section of your baseline can be left out.
- **Every report says which checks were skipped**, for example
  *6 of 8 checks ran*, so a clean report never hides that something wasn't
  checked.
- Switching on a check your baseline has no section for offers to copy that
  section from the example. Then change it to match your router with option 5.
- You can still run a switched-off check yourself with option 2.
- The alerts about Reaper changes and the self-test aren't affected.
- Switching off **reaper** stops SecAudit checking Reaper's own watchdog,
  firewall witnesses and Security Review. The reports say so.

Your choices are saved as `skip=` lines in the `[scope]` section of your
baseline, so they travel with it.

---

## Turn on the schedule

Choose **6, "Turn the schedule on"**. SecAudit will then:

- run a full audit every night at 3:00, and email you only if something is wrong;
- check Reaper's Security Review and watchdog every 10 minutes, and email you
  about each new change once.

The schedule survives reboots.

**To change the times,** choose **7, "Change the schedule times"**. It asks for
the hour of the nightly audit (0 to 23) and how often to check for Reaper
changes (every 5, 10, 15, 30 or 60 minutes). Press Enter to keep a value. The
new times apply right away, and updates keep them.

**Expect one note from Reaper:** turning the schedule on adds one line to
`/jffs/scripts/services-start`, and Reaper's Security Review will list that
change. That's expected. Review it and accept it.

SecAudit won't turn the schedule on while your baseline still has errors or
`REPLACE` values, so it can't start emailing you false alarms.

---

## Reading the results

A full audit shows a table with one row per check area:

| Column | Meaning |
|---|---|
| **Checks** | How many things were checked |
| **Passes** | Matched your baseline |
| **Warns** | Different from your baseline; worth a look |
| **Alerts** | Different from your baseline, and you marked it as important |
| **Exec-Fail** | SecAudit couldn't run that check (see *Troubleshooting*) |

Below the table, each finding is listed with what was expected and what was
found.

**A finding isn't necessarily a problem.** It means "this is different from what
you told me to expect". It could be a setting you changed on purpose, a new
device, or something that needs your attention. You decide which.

---

## After a firmware upgrade

SecAudit reads some of Reaper's internal files. A new Reaper version can change
those, so after every upgrade the menu shows
*Baseline: ready, but the firmware changed*, and each nightly audit reminds you
until you do this:

1. Open the menu and choose **4, Self-test**. The results mean:
   - **PASS**: fine.
   - **WARN**: works, with a note. After an upgrade you'll see one saying the
     baseline expects the old firmware; that's expected.
   - **SKIP**: couldn't be checked yet, usually because the router started less
     than 15 minutes ago. Run the self-test again later.
   - **MANUAL**: something SecAudit can't check by itself. Most are for
     advanced users. One matters to everyone: if a nightly audit flags
     `/etc/passwd`, repeat step 4 of *Set up your baseline*.
   - **FAIL**: SecAudit needs an update for this firmware. Choose **9, Check for
     updates**. If there's no update yet, don't rely on SecAudit's results until
     there is.
2. When the self-test has no FAIL lines, it asks
   *Accept <new firmware> as your firmware in baseline.conf?* Say **y**. That's
   all; the reminders stop.

Reaper updates often, sometimes several times a week. Each time, it's those two
steps: option 4, then **y**.

---

## Update

Choose **9, Check for updates**. If there's a newer version, SecAudit asks
before installing it. Your baseline is never changed. A new version may add
options to `baseline.conf.example`; the changelog says when.

The same option checks the shared email library and offers a newer version if
there is one.

## Uninstall

Choose **10, Uninstall**. It stops the schedule, removes the `secaudit` command
and SecAudit's files, and asks whether to keep your baseline and schedule times
(keep them if you might reinstall).

---

## Troubleshooting

More questions and answers, including the common objections, are in
[`docs/FAQ.md`](docs/FAQ.md).

**The menu says "Schedule: on (set up by hand)" or "on, runs <folder>"**
SecAudit was scheduled before, by hand or by another copy of SecAudit. Choose
option 6: it shows what it found and asks whether to replace it with its own
schedule. Say **y**: it removes the old lines and jobs, so audits don't run
twice.

**"JFFS custom scripts are off"**
See step 2 of *Before you start*. Without it, the schedule stops after a reboot.

**The menu says "Email: not set up in amtm"**
Set up email in amtm first: type `amtm`, choose `em`, and send amtm's test
email. SecAudit uses amtm's email settings, and keeps no passwords of its own.

**The menu says "Email: library missing"**
Choose **8, Send a test email**. SecAudit offers to download the shared email
library, then sends a test email. Scheduled runs never download it by
themselves, so until then nothing is emailed.

**The menu says "Email: set up", but no email arrives**
Send a test email (option 8). If that fails too, check that amtm's own test
email works (`amtm`, then `em`). SecAudit only emails when
something needs attention, so a quiet inbox after a clean night is normal.

**A check shows Exec-Fail**
SecAudit couldn't read something it needs. Run the self-test (option 4); it
usually points to the cause.

**`secaudit: not found`**
Log out and back in. The command becomes available from your next login.

---

## For advanced users

Everything in the menu also works as a command. Most need you at the
terminal; `--run-all`, `--notify` and `--startup` also run from cron.

| Command | What it does |
|---|---|
| *(none)* | Open the menu |
| `--run-all` | Run every check that's switched on |
| `--module <name>` | Run one check (even one switched off) |
| `--notify` | Email new Security Review items and watchdog changes |
| `--selftest` | Check that the Reaper files SecAudit reads still work |
| `--schedule on` / `off` | Turn the schedule on or off |
| `--install`, `--update`, `--uninstall` | Install, update or remove |
| `--startup` | Re-add the cron jobs (run by `services-start` at boot) |
| `--version`, `--help` | Version, and the full command list |

Files:

- `/jffs/addons/secaudit/`: the script, your `baseline.conf`, the example
  baseline, `gen_hashes.sh`, and `settings.conf` once you change the schedule
  times.
- `/tmp/secaudit*`: results of the last run. Kept in memory, so they're gone
  after a reboot and never show up in Reaper's Security Review.

How it works, the baseline grammar and the firmware-upgrade checklist are in
`docs/Architecture and Design.md`. `docs/System Design.md` covers what SecAudit
is for, `docs/FAQ.md` answers common questions, and `CHANGELOG.md` has the
release history.

## Files in this repository

| File | What it's for | On your router? |
|---|---|---|
| `audit_security.sh` | SecAudit itself, including the menu | Yes, installed |
| `baseline.conf.example` | The starting baseline, with notes | Yes, installed |
| `gen_hashes.sh` | Sets the `/etc/passwd` fingerprint in your baseline | Yes, installed |
| `smoke_test.sh` | Optional check that the audits work with your baseline | No |
| `addon_test.sh` | Optional check of install, schedule, update and uninstall | No |
| `make_release.sh` | Builds a release; for the maintainer only | No |
| `README.md`, `CHANGELOG.md`, `LICENSE`, `docs/` | Documentation | No |

The install and updates download only the three files marked "installed", and
check each against the release's SHA-256 list.

The two test scripts are optional. They run from `/tmp`, use a throwaway copy of
SecAudit, and never change your setup: no email is sent, and nothing in
`/jffs/scripts`, cron or your baseline is touched. How to run them is in
`docs/Architecture and Design.md`, section 12.

## License

Copyright (C) 2026 kstamand

GNU General Public License v3.0 or (at your option) any later version
(SPDX: `GPL-3.0-or-later`). See `LICENSE`.
