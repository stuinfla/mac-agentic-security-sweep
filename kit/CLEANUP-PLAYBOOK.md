# Mac Claude Security Sweep v2: cleanup playbook

Cleanup happens **only after the full scan and report are finished**, and **only for items you approve one at a time**. Every change is reversible where macOS allows it, and every change is logged.

## Rules Claude follows during cleanup

1. **Scan first, clean second.** No change is made until every scan phase is done and the report is delivered.
2. **Confirmed compromise? Secure your accounts before cleaning.** If any High indicator is **Confirmed** as malicious:
   - Save the evidence first (checklist Section 14, step 3).
   - Change passwords **from your phone** and sign out of all sessions.
   - **Don't run any more `sudo` scripts from the kit folder.** They run with full admin rights, and on a compromised Mac they could have been tampered with.
   - For a real infection, the safest end state is usually to back up your documents (not apps or settings) and **erase and reinstall macOS** (checklist Section 14, step 9). Claude tells you plainly when that's the better call.
3. **One item at a time, with a proposal first.** For each item Claude shows:
   - **What it is**, with the evidence and confidence label.
   - **What the action does**, as the exact command or the clicks in System Settings.
   - **What could break**, such as an app you use stopping working.
   - **How to undo it.**

   Then it waits for an explicit "yes" for that item. "Yes to all" isn't accepted for High-risk items.
4. **Prefer the gentlest effective action**, in this order:
   1. Turn it off in System Settings or the browser (fully reversible).
   2. Use the vendor's own uninstaller.
   3. Quarantine it with `quarantine.sh`: the item is moved, not deleted, and an undo line is recorded.
   4. Never `rm`. Deleting quarantined items later is your decision, made after a week or two of everything working.
5. **Paths are always in single quotes**, and Claude shows you the exact line before anything runs, e.g. `bash quarantine.sh '/Applications/Some App.app'`. Filenames can contain characters the shell would otherwise act on.
6. **Claude doesn't use `sudo`.** For system-level items, Claude gives you the exact `sudo bash quarantine.sh '<path>'` line to run in a second Terminal window.
7. **Verify after every action.** Claude re-checks that the item is gone or stopped (and not running) before moving to the next.
8. **Log everything** in `results/<mac>-<date>/CLEANUP-LOG.md`: time, item, action, evidence, verification result and undo command.
9. **Never touched:** anything Apple-signed or under `/System`, System Integrity Protection, Gatekeeper, XProtect, FileVault (except turning protections *on*), and items you said are yours.

## What `quarantine.sh` will and won't move

It only accepts items in these places:
- launch agents and daemons (`~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`) and `/Library/PrivilegedHelperTools`,
- apps in `/Applications` or `~/Applications`,
- `/Users/Shared` and temporary folders,
- browser native messaging host `.json` files,
- Claude Code skills and plugins (`~/.claude/skills`, `~/.claude/plugins`).

It refuses everything else, and refuses genuine Apple-signed apps and programs. (A fake `com.apple.*` plist outside `/System` is *not* refused just because of its name.) If it refuses something, Claude uses System Settings or the vendor's uninstaller instead, or tells you it's a job for a professional. It never works around the refusal.

- Your own items: undo with `bash quarantine/UNDO.sh`.
- System items (moved with `sudo`): they are kept in a root-only folder outside the kit, `/Library/Application Support/Mac Claude Security Sweep/`, so a program running as you cannot tamper with them. Undo with `sudo bash "/Library/Application Support/Mac Claude Security Sweep/UNDO-system.sh"`.
- A note on `sudo`: the kit's own folder is writable by you, and by any program running as you. If you think your Mac may already be compromised, don't run the kit's cleanup with `sudo`. Use System Settings or the vendor's uninstaller, or ask a professional.

## Playbooks by finding type

| Finding | Gentlest fix | Stronger fix | Undo |
|---|---|---|---|
| **Login item / background item you don't want** | System Settings → General → Login Items (Login Items & Extensions on macOS 15+) → switch it off | Uninstall the app that owns it | Switch it back on |
| **User launch agent** (`~/Library/LaunchAgents/*.plist`) | Switch off in Login Items | `bash quarantine.sh --launchd '<path to .plist>'` | `bash quarantine/UNDO.sh` |
| **System launch agent/daemon** (`/Library/Launch*`) | Switch off in Login Items | `sudo bash quarantine.sh --launchd '<path to .plist>'`, then quarantine its helper in `/Library/PrivilegedHelperTools/` the same way (without `--launchd`) | `sudo bash "/Library/Application Support/Mac Claude Security Sweep/UNDO-system.sh"` |
| **Unwanted or suspicious app** | Quit it; use its own uninstaller if it has one | `bash quarantine.sh '/Applications/<App>.app'`. A login item built into the app may keep running until you restart; the post-restart check covers it. | `bash quarantine/UNDO.sh` |
| **Browser extension** | Turn it off at `chrome://extensions` (or Safari → Settings → Extensions) | Click **Remove** there. Then check `chrome://policy`, the search engine and the startup pages. | Reinstall from the official store |
| **Native messaging host** (browser ↔ app bridge) | Uninstall the app that owns it | `bash quarantine.sh '<path to host .json>'` | `bash quarantine/UNDO.sh` |
| **Privacy permission** (Screen Recording, Accessibility, Full Disk Access, Input Monitoring, Camera/Mic) | System Settings → Privacy & Security → that category → switch off or **−** remove | — | Grant it again |
| **Configuration profile / MDM** on a personal Mac | macOS 13: System Settings → Privacy & Security → Profiles. Later: System Settings → General → Device Management. Select it → **−** | If it can't be removed, it's managed; ask whoever owns the Mac | Reinstall the profile |
| **Added root certificate** | Keychain Access (on macOS 15+ it's hidden: open it with Spotlight, ⌘Space) → the certificate → Get Info → Trust → **Never Trust** | Export it to the kit's `quarantine/` folder, then delete it in Keychain Access | Re-import it / set the trust back |
| **Unknown proxy / DNS / VPN** | System Settings → Network → your connection → Details → Proxies / DNS → remove | Remove the VPN configuration under VPN | Re-enter the settings |
| **Hosts-file entry** | Claude shows you the exact line, then runs the three commands under *Hosts file and cron jobs* below. They remove only a line that matches exactly and keep the old file as `/etc/hosts.bak`. | — | `sudo cp /etc/hosts.bak /etc/hosts` |
| **Cron job** | Claude shows you the exact line, then runs the commands under *Hosts file and cron jobs* below. They save your scheduled jobs to a backup first. | — | `crontab results/crontab.backup` |
| **Suspicious line in a shell startup file** (`.zshrc` etc.) | Back up the file into `results/`, then comment out the line with `#` | — | Restore from the backup |
| **Unknown SSH key in `authorized_keys`** | Back up the file into `results/`, then remove that one line | Turn off Remote Login (System Settings → General → Sharing) | Restore the backup / switch it back on |
| **Remote Login / Screen Sharing / Remote Management you didn't turn on** | System Settings → General → Sharing → switch off | — | Switch back on |
| **Authorization plugin** (`/Library/Security/SecurityAgentPlugins`) | **Uninstall the app that installed it** | **Don't move it by hand.** macOS's login database can still reference it, and you could be locked out of logging in. If there's no uninstaller, get professional help. | — |
| **System or network extension** | Uninstall its app, or (macOS 15+) System Settings → General → Login Items & Extensions → Extensions | — (never disable SIP to remove one) | Reinstall the app |
| **Global npm / pip / Homebrew package** | `npm uninstall -g '<pkg>'` / `pip3 uninstall '<pkg>'` / `brew uninstall '<pkg>'` | Also remove any MCP server or hook that used it | Reinstall the package |
| **MCP server, hook or skill you don't trust** | Back up the config file into `results/`, then remove that one entry | Quarantine the skill or plugin folder | Restore the backup / `bash quarantine/UNDO.sh` |
| **Exposed API key or token** | **Revoke and re-issue it at the provider** (from your phone or another device if compromise is suspected) | Then remove it from the file | — (revoking is the fix) |

### Protections to switch on (hardening gaps)

| Gap | Fix | Undo |
|---|---|---|
| **FileVault off** | System Settings → Privacy & Security → FileVault → Turn On. Save the recovery key somewhere safe that **isn't this Mac** (on paper, or in a password manager on your phone). Encryption runs in the background. | Turn Off (not recommended) |
| **Firewall off** | System Settings → Network → Firewall → on | Switch off |
| **macOS out of date or updates off** | System Settings → General → Software Update: install pending updates. Click the ⓘ next to Automatic Updates and turn everything on, especially security responses and system files. If your Mac can't run a supported macOS version, it no longer gets security fixes; limit what you do on it, or plan to replace it. | Switch settings back |
| **Automatic login on** | System Settings → Users & Groups → "Automatically log in as" → Off | Switch back on |
| **No backups** | Plug in an external drive and choose it in System Settings → General → Time Machine | Remove the destination |

## After cleanup

1. Claude re-runs the relevant checks and confirms each item is gone or stopped. Results are logged.
2. **Restart once**, then run the post-cleanup check (`AUDIT-BRIEF.md`). Persistent malware often reinstalls itself. If anything returns, treat it as a confirmed compromise.
3. Keep the `quarantine/` folder for 1–2 weeks. If everything works, delete it yourself in Finder.
4. Optional: set up ongoing protection (below).

## Ongoing protection (optional, with your OK)

Both tools are free and open source, from Objective-See (objective-see.org).

| Tool | What it alerts on | Install |
|---|---|---|
| **LuLu** | Any app trying to connect out to the internet for the first time | Official download at https://objective-see.org/products/lulu.html, or `brew install --cask lulu` |
| **BlockBlock** | Anything installing itself to start automatically (the main way Mac malware persists) | https://objective-see.org/products/blockblock.html, or `brew install --cask blockblock` |

**Install notes:**
- macOS asks you to approve each tool's system extension in System Settings → Privacy & Security. That's expected; click Allow.
- For LuLu, also approve its network filter.
- BlockBlock may also need Full Disk Access (System Settings → Privacy & Security → Full Disk Access) to watch everything.
- Expect a burst of LuLu prompts in the first day as your normal apps connect. Allow the ones you recognize.

Claude can walk you through this, but installing is your call and your click.

## Hosts file and cron jobs (commands Claude runs only after you approve)

Hosts file. Replace `<exact line>` with the line Claude showed you:

```
sudo cp /etc/hosts /etc/hosts.bak
grep -vxF '<exact line>' /etc/hosts.bak | sudo tee /etc/hosts >/dev/null
diff /etc/hosts.bak /etc/hosts
```

Cron job. Replace `<exact line>` the same way:

```
crontab -l > results/crontab.backup
grep -vxF '<exact line>' results/crontab.backup | crontab -
```
