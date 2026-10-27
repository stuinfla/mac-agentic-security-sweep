# Mac Claude Security Sweep: start here (version 2)

A **read-only** security check for your Mac, run with Claude's help. It looks for programs set to start automatically that shouldn't be there, suspicious browser extensions, apps holding sensitive permissions, traffic interception, remote-access back doors, and signs that data is leaving your Mac. It also points out protections worth switching on.

**You need:** a Mac running macOS 13 or later, your Mac password (an admin account), a paid Claude plan (Pro, Max, Team or Enterprise), and 30–60 minutes.

## Quick start

0. **Install Claude Code** (skip if you have it). Open Terminal (Applications → Utilities → Terminal), paste `curl -fsSL https://claude.ai/install.sh | bash` and press Return.
   **Sign in:** open a new Terminal window (⌘N), type `claude`, press Return, sign in in the browser window that opens, then type `/exit`.
1. **Give Terminal Full Disk Access.** System Settings → Privacy & Security → Full Disk Access → **+** → Applications → Utilities → **Terminal** → turn it on. Then **quit Terminal with ⌘Q** (the permission only works in a fresh Terminal).
2. **Download** `Mac-Claude-Security-Sweep.zip` and leave it in your Downloads folder, even if your Mac unzips it automatically.
3. **Open Terminal**, paste this one line and press Return:
   ```bash
   cd ~ && claude "Find Mac-Claude-Security-Sweep in my Downloads folder (zip or already-unzipped folder), unpack it into my home folder as ~/mac-claude-security-sweep, then read START-HERE.md and AUDIT-BRIEF.md and run the sweep from Phase 0. Scan read-only; change nothing unless I approve it item by item in the cleanup step."
   ```

## What happens next

1. **Scan (read-only).** Claude unpacks the kit and runs the checks. Once, it asks you to paste a line into a second Terminal window and type your password (nothing appears as you type; that's normal). That part takes a few minutes, because it searches 7 days of system logs. **If Claude finds signs of compromise, it stops and shows a ⚠️ SECURITY ALERT** with the one thing to do right away.
2. **Report.** A plain-language report: the verdict, any alerts, protections worth switching on, what's fine, and the single most important next step.
3. **Cleanup (optional).** Claude walks you through fixes **one item at a time**: what it is, the evidence, exactly what it will do, what could break, and how to undo it. Nothing changes until you say yes to that item.
4. **Stay protected (optional).** Claude can walk you through two free alerting tools, LuLu and BlockBlock.

## First-run prompts you'll see

- **"Do you trust the files in this folder?"** Answer **Yes**.
- **Command approvals.** Claude asks before each command. Approve them one at a time. Choose "don't ask again" only for plain `ls` or `cat` of ordinary files, never for `plutil`, `find`, `sqlite3`, `codesign`, `bash`, `sudo`, or anything that changes files. Never start Claude with `--permission-mode bypassPermissions`.
- **A browser sign-in**, if Claude Code isn't signed in yet. Sign in.
- **"Terminal would like to access files in your Downloads folder."** Click **Allow**.

## How it stays safe

- **The scan only reads.** Cleanup comes only after the report, one approved item at a time.
- **Nothing is deleted without a backup or a way to reinstall.** Items removed by cleanup are moved to a `quarantine/` folder with an undo script. (Browser-extension removal, package uninstalls and certificate removals are reinstallable rather than quarantined.)
- **It refuses to touch macOS itself.** The cleanup helper only works in a short list of places where unwanted software lives, and refuses genuine Apple-signed apps and programs.
- **What it is not:** antivirus, or proof your Mac is clean. Some Mac malware runs once, takes passwords and browser cookies, and leaves almost nothing behind. A good result means *"no indicators found"*, not *"clean"*.
- **One honest limit:** Claude Code reads its own settings files before the scan starts. Claude checks them first, but if those files were already tampered with, this kit can't fully defend against that. If Claude Code behaves strangely, or you're already suspicious, use **Path B** below from a chat at claude.ai, or run the kit from a separate, freshly created Mac user account.

---

## Path B: a regular Claude chat (no Claude Code)

Works with any Claude account that accepts file uploads.

1. Unzip the download and drag the `mac-claude-security-sweep` folder into your **home folder** (the one with your name, holding Desktop, Documents and Downloads).
2. Give Terminal Full Disk Access and quit it with ⌘Q (Quick start step 1).
3. Open Terminal and run the admin checks (a few minutes; type your password when asked):
   ```bash
   cd ~/mac-claude-security-sweep && sudo bash sudo-checks.sh
   ```
4. Then run the other checks (10–20 minutes, including a 3-minute pause for a second network reading):
   ```bash
   cd ~/mac-claude-security-sweep && bash collect-checks.sh
   ```
   This creates **one file**: `results/<your-mac>-<date>/ALL-RESULTS.txt`. If a box asks to install "command line developer tools", click **Cancel**.
5. **Skim `ALL-RESULTS.txt` before sharing it** (see Privacy below).
6. Open a **new chat** at claude.ai or in the Claude app. Attach `ALL-RESULTS.txt`, `SWEEP-CHECKLIST.md` and `CLEANUP-PLAYBOOK.md`. Copy everything in `CHAT-PROMPT.md` below its line, paste it in and send.
7. Claude may ask you to run more read-only commands. Run them in Terminal and paste the output back.

The results file can be large. If the upload is rejected, trim it as `CHAT-PROMPT.md` explains.

---

## What's in this folder

| File | What it is |
|---|---|
| `START-HERE.md` | This guide |
| `AUDIT-BRIEF.md` | Instructions Claude Code follows |
| `SWEEP-CHECKLIST.md` | Every check: what's suspicious, what's normal, how serious it is, and what to do if something turns up |
| `CLEANUP-PLAYBOOK.md` | How each kind of problem gets fixed, gentlest option first, with undo steps and the optional protection tools |
| `CHAT-PROMPT.md` | Prompt for a regular Claude chat (Path B) |
| `sudo-checks.sh` | Read-only checks that need your admin password. **You** run it |
| `collect-checks.sh` | Read-only checks that don't need a password; combines everything into `ALL-RESULTS.txt` |
| `quarantine.sh` | Cleanup helper: *moves* an item into `quarantine/` and records how to undo it |

Results go in `results/<your-mac>-<date>/`: `FINDINGS.md` (running log), `REPORT.md` (the final report) and `CLEANUP-LOG.md`. Running a script again on the same day keeps the earlier output as a `-prev-` folder.

## Privacy: read before sharing results

The results describe your Mac in detail: app and extension lists, usernames, network connections and IP addresses, download history (including the web addresses files came from), file paths and SSH *public* keys. The scripts redact anything that looks like an API key or token, and list credential files by *name* only, but automatic redaction isn't perfect.
- Only upload results to **your own** Claude account.
- When you're done, delete the whole `results` folder or move it to a private drive.

## If something serious is found

**Don't delete it, don't restart, and don't "clean up" yet.** Follow Section 14 of `SWEEP-CHECKLIST.md`: save the evidence somewhere other than this Mac, change passwords **from your phone** and sign out of all sessions everywhere, then revoke API keys and tokens.

The kit's `sudo` scripts run with full admin rights. If a serious finding is **Confirmed**, don't run any more `sudo` scripts from this folder; go straight to the erase-and-reinstall guidance in Section 14, and consider a professional incident responder.

## Undoing a cleanup

From Terminal:
```bash
cd ~/mac-claude-security-sweep
bash quarantine/UNDO.sh                # puts back your own items
sudo bash "/Library/Application Support/Mac Claude Security Sweep/UNDO-system.sh"   # puts back system items, if any were cleaned
```
Every change is also logged in `results/<your-mac>-<date>/CLEANUP-LOG.md`. Keep the `quarantine` folder for a week or two; once everything works, delete it in Finder.

## When you're done

1. Turn **off** Full Disk Access for Terminal (and for `claude`, if it's listed). Any AI tool run from Terminal inherits that access.
2. Delete or move the `results` folder.
3. Consider the free protection tools in Section 15 of the checklist, and re-run the sweep every few months.

---

## Troubleshooting

| You see | Do this |
|---|---|
| The session was cut off | Open Terminal and run `cd ~ && claude -c` (continues the last session). If that fails, paste the Quick start line again; it resumes from `FINDINGS.md`. |
| `authorization denied` in results | Full Disk Access isn't active. Turn it on, quit Terminal with ⌘Q, reopen it, then resume as above. |
| `claude: command not found` | Open a new Terminal window. If it still fails, see https://code.claude.com/docs/en/setup |
| `claude` only accepts a prompt | On some setups where `claude` is launched through another app, it may only accept a quoted prompt, exactly as shown above. |
| It seems stuck or very slow | Each slow check stops itself after between 20 seconds and 3 minutes. Lines saying `TIMED OUT` are expected. If it's still stuck, resume and ask Claude to re-run with `SWEEP_FAST=1` (Path B: `SWEEP_FAST=1 bash collect-checks.sh`). |
| You want to turn off Wi-Fi | That also stops Claude mid-answer. Ask Claude to save `FINDINGS.md` first. |
| A box asking to install developer tools | Click **Cancel**. Don't install anything during the sweep. |
| `Operation not permitted` | Expected for a few protected areas. The check shows that message in its results file and carries on; it isn't a problem by itself. |
| Path B upload rejected as too large | Trim the file as `CHAT-PROMPT.md` explains. |

*This kit is a structured, read-only checklist, not professional forensic software. Use your own judgment, and ask a professional if you're unsure.*
