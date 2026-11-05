# SecAudit Q&A

Answers to the questions people ask most about SecAudit: what it's for, the
hardest objections, and how it works day to day.

## The 30-second pitch

SecAudit emails you when Reaper's Security Review or watchdog sees a change, and
checks every night that your router still matches how you said it should be set
up.

- **What it adds:** alerts (Reaper records but doesn't notify), plus checks Reaper
  doesn't make: admin login sources, listening ports, programs running from
  `/tmp`, network bridges, the `/etc/passwd` fingerprint, the OUTPUT firewall
  hook. Switch off any you don't need.
- **Who it's for:** people comfortable with SSH who will spend about 30 minutes on
  a baseline and look into findings.
- **What it is not:** a firewall, set-and-forget protection, proof the router is
  secure, or protection against someone who already has root.
- **What it never does:** change router settings or "fix" anything. Audits are
  read-only.
- **Status:** independent community addon, not part of or endorsed by Reaper.
  Problems go in the SecAudit thread, not Reaper's.

## Hard challenges

Five objections security-minded Reaper users raise, each with the answer and
what backs it up.

| Challenge | Answer | Backed by |
| --- | --- | --- |
| "Reaper already has Security Review, rwatch and firewall witnesses. Why add this?" | Reaper records changes but sends no alerts; `--notify` is the alerting. The nightly audit covers what Reaper doesn't watch. If Reaper adds alerting, SecAudit retires its version. | Coverage table in the design doc; retirement pledge in the README |
| "Reaper ships several releases a week. Won't this nag me constantly?" | After an upgrade the menu flags it. Run the self-test (option 4); if it's clean, press **y** to accept the new firmware. One keypress per release. | 8 RT-BE88U releases from 28 Oct to 4 Nov 2026; firmware accept built in |
| "You want root, and you update yourself from GitHub." | Installs and updates come only from tagged GitHub releases. Every file must match the release's SHA-256 list, or nothing is installed. Code is GPL and readable. | `fetch_files`, `make_release.sh` |
| "Non-technical users can't judge a finding." | Agreed, so the README says up front who it's for and who it isn't for. It's a tool for people who want to know, not a safety net. | README "Is SecAudit for you?" |
| "If I'm compromised, an attacker just edits your script." | True for anyone with root. SecAudit's files live in `/jffs`, which Reaper's Security Review watches, so edits to them show up there. It catches drift and mistakes, not a determined attacker. | README "What SecAudit is not" |

## Questions users ask

| Question | Answer |
| --- | --- |
| Does it work on my BE96U / GT-BE98 / other model? | Tested only on RT-BE88U with Reaper 3.7.1. It should run on any Reaper router, but bridges, interfaces and ports differ by model, so expect findings until your baseline matches your router. Reports from other models are welcome. |
| How do I get email? | Set up email in amtm (`amtm`, then `em`) and send its test mail. SecAudit then offers to download Martinski W.'s shared email library (many Merlin addons use it), at install or from menu option 8, which also sends a test email. The menu shows "Email: set up" when both are in place. |
| Will SecAudit download things behind my back? | No. It downloads only when you're at the terminal and say yes: installs, updates, and the email library. Scheduled runs never download anything. |
| Will it slow my router or wear out the flash? | No. One quick check every 10 minutes and one audit a night. Results go to `/tmp` (RAM). Nothing is written to flash during normal runs. |
| Will it change my settings? | Never. Audits only read. Install, schedule and uninstall write only SecAudit's own files and two marked lines in `services-start` and `profile.add`. |
| Why does Reaper's Security Review list a change after I install it? | Turning on the schedule adds one line to `services-start`, and changing the times or the baseline writes files in the addon folder. All expected: review and accept them. |
| Is it in amtm? Is there a web page? | Not yet. It's a command-line proof-of-concept with a menu (`secaudit`). |
| What does it do that Reaper's Status page or `netstat` doesn't? | It compares what's there against what you said should be there, every night, and emails you when that changes. You don't have to remember to look. |
| I already scheduled it by hand. Do I have to undo that? | No. Menu option 6 shows what it found and offers to replace it with its own schedule. |
| Can I turn off checks I don't need? | Yes. Option 3, "Choose which checks run", switches each check on or off. Your choices are saved as `skip=` lines in the `[scope]` section of your baseline, so they travel with it. |
| Do I have to fill in a section for a check I've switched off? | No. A switched-off check's section can be left out of your baseline. Fewer checks means a quicker setup. |
| Won't switching checks off hide problems? | Not silently. Every report lists each skipped check and says, for example, "6 of 8 checks ran". The menu shows "Checks: 6 of 8". Switching off the reaper check adds a warning that Reaper's own health isn't being checked. |
| How do I switch a check back on if I deleted its section? | Option 3 offers to copy that section from `baseline.conf.example`. Then change it to match your router with option 5, "Edit your baseline". |
| Can I still run a switched-off check now and then? | Yes. Option 2 runs any check by name, with a note that it's switched off. |
| Does switching checks off affect the alerts or the self-test? | No. The 10-minute Reaper alerts, the self-test and the firmware check always run. |
| Can I change when it runs? | Yes. Option 7 sets the nightly audit hour and how often to check for Reaper changes (5 to 60 minutes). |
| Is this an official Reaper addon? | No. It's independent and not endorsed by Reaper or its developer. Please report problems in the SecAudit thread. |
| What if the self-test shows FAIL? | Reaper changed something SecAudit reads. Check for updates (option 9). Until there's a fix, don't rely on its results. |
| How do I remove it? | Menu option 10. It removes the schedule, the `secaudit` command and its files, and asks whether to keep your baseline. |

## Known limits

- **Checksums aren't signatures.** They prove a file matches the release, not who
  published it. Signing is a possible next step (`openssl` is on the router).
- **The first download isn't checked.** The one-line install fetches
  `audit_security.sh` itself before any checksum check; everything it then
  installs is checked.
- **The email library isn't ours.** It's Martinski W.'s, downloaded over HTTPS
  from his official repository. It can't be checked against SecAudit's
  checksums.
- **Undocumented Reaper files.** SecAudit reads Reaper internals that can change
  in any release. The self-test catches it, but a fix may lag a Reaper release.
- **One model tested.** RT-BE88U only, so far.
- **Single maintainer.** Support and fixes depend on one person's time.
- **No web UI, no amtm entry.** Command line and menu only.
