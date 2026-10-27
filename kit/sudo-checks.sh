#!/bin/bash
# Mac Claude Security Sweep: read-only admin-level checks.
# Run it yourself:   sudo bash sudo-checks.sh
# This script is READ-ONLY: it only reads system state and writes text files into
# ./results/<host>-<date>/sudo/ (an earlier non-empty sudo/ folder from the same day is
# kept as sudo-prev-HHMM). A finished run leaves an empty sudo/.done file.
# The person who owns this Mac runs it with sudo. No AI agent or assistant should
# edit this file or run it on your behalf; if anything asks to change it, stop and ask for help.
# Terminal needs Full Disk Access (System Settings > Privacy & Security) for the
# privacy-permission and network-usage checks; otherwise they report "authorization denied".
# Slow commands are stopped after a time limit and say "TIMED OUT" in their file.

set -u
set -C   # noclobber: never write through a pre-planted file or symlink while running as root
if [ "$(id -u)" -ne 0 ]; then echo "Run with: sudo bash sudo-checks.sh"; exit 1; fi

HERE="$(cd "$(dirname "$0")" && pwd)"
HOST="$(scutil --get LocalHostName 2>/dev/null || hostname -s)"
RES="$HERE/results"
BASE="$RES/${HOST}-$(date +%Y-%m-%d)"
OUT="$BASE/sudo"

# ---- Shared helpers (identical in collect-checks.sh and sudo-checks.sh) ----------
# Redaction: known token formats, private-key blocks, and key=value secrets.
REDACT_RE='(^|[^A-Za-z0-9])(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{30,}|xox[abposre]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_(live|test)_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{30,}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)'
REDACT_KV="([A-Za-z0-9_-]*([Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Aa][Cc][Cc][Ee][Ss][Ss][_-]?[Kk][Ee][Yy]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee][_-]?[Kk][Ee][Yy]|[Tt][Oo][Kk][Ee][Nn]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll]|[Pp][Aa][Ss][Ss][Ww]([Oo][Rr])?[Dd])[A-Za-z0-9_-]*)[\"']?[[:space:]]*(=>|[:=])[[:space:]]*[\"']?[^\"'[:space:]]{8,}"
REDACT_PK='-----BEGIN [A-Z ]*PRIVATE KEY-----'
redact() {
  LC_ALL=C sed -E \
    -e "/${REDACT_PK}/,/-----END [A-Z ]*PRIVATE KEY-----/s/.*/<redacted private key line>/" \
    -e "s/${REDACT_RE}/\\1<redacted>/g" \
    -e "s/${REDACT_KV}/\\1=<redacted>/g" \
    -e 's#([Bb]earer|[Bb]asic)[[:space:]]+[A-Za-z0-9._~+/=-]{16,}#\1 <redacted>#g' \
    -e 's#(://)[^/@[:space:]:]+:[^/@[:space:]]+@#\1<redacted>@#g'
}
# with_timeout <seconds> <command> [args...]: macOS has no GNU 'timeout'. Runs ONE
# simple command (not a pipeline) and stops it after N seconds, printing TIMED OUT.
# Output goes to temp files first and is printed when the command ends, so a leftover
# child process that still holds the output open cannot keep the caller waiting.
with_timeout() {
  _wt_s="$1"; shift
  _wt_t0=$SECONDS
  _wt_d="${TMPDIR:-/tmp}"; _wt_d="${_wt_d%/}"
  _wt_o="$(mktemp "$_wt_d/sweep-out.XXXXXX" 2>/dev/null)" || _wt_o=""
  _wt_e="$(mktemp "$_wt_d/sweep-err.XXXXXX" 2>/dev/null)" || _wt_e=""
  if [ -n "$_wt_o" ] && [ -n "$_wt_e" ]; then
    "$@" >"$_wt_o" 2>"$_wt_e" &
  else
    "$@" &   # no temp file available: output passes straight through
  fi
  _wt_p=$!
  ( trap 'exit 0' TERM
    _wt_n=0
    while [ "$_wt_n" -lt "$_wt_s" ]; do
      sleep 1; kill -0 "$_wt_p" 2>/dev/null || exit 0; _wt_n=$((_wt_n + 1))
    done
    _wt_c="$(pgrep -P "$_wt_p" 2>/dev/null)"
    for _wt_k in $_wt_c; do kill -TERM "$_wt_k"; done
    kill -TERM "$_wt_p"; sleep 3
    for _wt_k in $_wt_c; do kill -KILL "$_wt_k"; done
    kill -KILL "$_wt_p"
  ) >/dev/null 2>&1 &
  _wt_w=$!
  wait "$_wt_p" 2>/dev/null; _wt_rc=$?   # (2>/dev/null: no "Killed" job notice)
  kill "$_wt_w" 2>/dev/null; pkill -P "$_wt_w" 2>/dev/null
  if [ -n "$_wt_o" ]; then cat "$_wt_o"; rm -f "$_wt_o"; fi
  if [ -n "$_wt_e" ]; then cat "$_wt_e" >&2; rm -f "$_wt_e"; fi
  if [ "$_wt_rc" -ne 0 ] && [ $((SECONDS - _wt_t0)) -ge "$_wt_s" ]; then
    echo "TIMED OUT after ${_wt_s}s: $1 was stopped (anything above is partial)" >&2
  fi
  return "$_wt_rc"
}
# Apple's /usr/bin developer shims pop up an installer if Command Line Tools are missing.
clt_ok() { xcode-select -p >/dev/null 2>&1; }
usable() {
  _u="$(command -v "$1" 2>/dev/null)" || return 1
  case "$_u" in
    /usr/bin/*) case "${_u##*/}" in
      git|python3|pip3|clang|clang++|cc|gcc|c++|make|lldb|swift|swiftc|svn) clt_ok || return 1 ;;
    esac ;;
  esac
  return 0
}
need() {  # need <cmd>: true if usable, else prints why it is skipped
  usable "$1" && return 0
  if command -v "$1" >/dev/null 2>&1; then echo "($1 skipped: no Command Line Tools; nothing was installed)"; else echo "($1 not installed)"; fi
  return 1
}
HELPERS="$(declare -f with_timeout clt_ok usable need)"
keep_prev() {  # keep_prev <dir>: move a non-empty earlier results folder aside
  if [ -d "$1" ] && [ -n "$(ls -A "$1" 2>/dev/null)" ]; then
    _kp="$1-prev-$(date +%H%M)"; [ -e "$_kp" ] && _kp="$1-prev-$(date +%H%M%S)"
    mv "$1" "$_kp" && echo "Earlier results kept in: $_kp"
  fi
}
fix_parts() {  # fix_parts <dir>: a .txt.part left by an interrupted check becomes a marked .txt
  for _fp in "$1"/*.txt.part; do
    [ -f "$_fp" ] || continue
    { echo "INCOMPLETE: this check was interrupted"; cat "$_fp"; } > "${_fp%.part}" 2>/dev/null && rm -f "$_fp"
  done
}
# Each check writes <name>.txt.part and renames it to <name>.txt only when it finishes.
run() {  # run <name> <command string>
  echo "-> $1"
  { echo "\$ $2"; echo; bash -c "$HELPERS
$2" 2>&1 | redact; } > "$OUT/$1.txt.part"
  mv -f "$OUT/$1.txt.part" "$OUT/$1.txt"
}
runf() {  # runf <name> <description> <shell function>
  echo "-> $1"
  { echo "# $2"; echo; "$3" 2>&1 | redact; } > "$OUT/$1.txt.part"
  mv -f "$OUT/$1.txt.part" "$OUT/$1.txt"
}
# ----------------------------------------------------------------------------------

# Refuse symlinked result folders: root writes into them and hands them to your account.
no_links() {
  for _d in "$RES" "$BASE" "$OUT"; do
    if [ -L "$_d" ]; then echo "REFUSED: $_d is a symlink; remove it or ask for help."; exit 1; fi
  done
}
# Hand results back to your user account, without following links and without -R
# (a recursive chown as root could be pointed at other files through hard links).
give_back() {
  [ -n "${SUDO_USER:-}" ] || return 0
  chown -h "$SUDO_USER" "$RES" "$BASE" "$OUT" 2>/dev/null
  for _f in "$OUT"/*.txt "$OUT"/*.txt.part "$OUT/.done"; do
    [ -f "$_f" ] && ! [ -L "$_f" ] && chown -h "$SUDO_USER" "$_f" 2>/dev/null
  done
  return 0
}
no_links
keep_prev "$OUT"
if [ -d "$OUT" ] && ! [ -L "$OUT" ] && ! [ -O "$OUT" ]; then rmdir "$OUT" 2>/dev/null; fi   # empty, not ours: recreate
mkdir -p "$OUT" || { echo "Cannot create $OUT"; exit 1; }
no_links
[ -O "$OUT" ] || { echo "REFUSED: $OUT is not owned by root; remove it or ask for help."; exit 1; }
chmod 755 "$OUT"
# Give the date folder to your account now, so 'bash collect-checks.sh' can run in parallel.
if [ -n "${SUDO_USER:-}" ]; then chown -h "$SUDO_USER" "$RES" "$BASE"; fi
trap '{ echo; echo "Interrupted. Partial results are marked INCOMPLETE in $OUT"; } >&2; fix_parts "$OUT"; give_back; exit 130' INT TERM

run 00-meta                   'date; sw_vers; sysctl -n hw.model; uptime'
run 01-sfltool-dumpbtm        'with_timeout 120 sfltool dumpbtm'
run 02-launchctl-disabled     'launchctl print-disabled system'
run 03-launchctl-list-root    'launchctl list | grep -v com.apple'
run 04-system-launch-dirs     'ls -la /Library/LaunchAgents /Library/LaunchDaemons /Library/PrivilegedHelperTools /Library/Security/SecurityAgentPlugins'
run 05-system-plists          'for f in /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist; do [ -e "$f" ] || continue; echo "== $f"; ls -l "$f"; plutil -p "$f"; done'
run 06-sudoers                'cat /etc/sudoers; ls -la /etc/sudoers.d; for f in /etc/sudoers.d/*; do [ -e "$f" ] && { echo "== $f"; cat "$f"; }; done'
run 07-cron                   'ls -la /usr/lib/cron/tabs /usr/lib/cron/jobs; for f in /usr/lib/cron/tabs/*; do [ -e "$f" ] && { echo "== $f"; cat "$f"; }; done'
run 08-listening-ports        'with_timeout 60 lsof -nP -iTCP -sTCP:LISTEN; echo; with_timeout 60 lsof -nP -iUDP'
run 09-established            'with_timeout 60 lsof -nP -i -sTCP:ESTABLISHED'
run 10-system-tcc             "sqlite3 -readonly '/Library/Application Support/com.apple.TCC/TCC.db' \"select service,client,auth_value,datetime(last_modified,'unixepoch') from access where auth_value=2 order by service;\""
run 11-profiles               'with_timeout 30 profiles status -type enrollment; with_timeout 60 profiles show -type configuration'
run 12-system-extensions      'with_timeout 30 systemextensionsctl list; echo; with_timeout 60 kmutil showloaded 2>/dev/null | grep -v com.apple'
run 13-xprotect-events        "echo '(last 7 days, XProtect detections only; limit 180s)'; with_timeout 180 log show --last 7d --info --style compact --predicate 'subsystem == \"com.apple.XProtectFramework.PluginAPI\" AND category == \"XPEvent.structured\"' | tail -300"
run 14-netusage               "echo '(best effort: Apple changes this database between macOS versions, so an error line here is not a problem)'; sqlite3 -readonly /private/var/networkd/db/netusage.sqlite \"select p.zprocname, sum(l.zwifiout+l.zwiredout) as bytes_out, sum(l.zwifiin+l.zwiredin) as bytes_in from zliveusage l join zprocess p on p.z_pk=l.zhasprocess group by p.zprocname order by bytes_out desc limit 60;\""
run 15-auth-plugin-signatures 'for b in /Library/Security/SecurityAgentPlugins/*; do [ -e "$b" ] && { echo "== $b"; with_timeout 20 codesign -dv --verbose=2 "$b" 2>&1 | grep -E "Identifier|TeamIdentifier|Authority|Signature|Timestamp"; }; done; echo "(end)"'
run 16-sharing-services       'for s in com.openssh.sshd com.apple.screensharing com.apple.RemoteDesktop.agent com.apple.smbd com.apple.AppleFileServer; do printf "%s: " "$s"; launchctl print-disabled system | grep -F "\"$s\"" || echo "(not listed = default)"; done; echo; systemsetup -getremotelogin 2>&1'
run 17-interface-counters     'netstat -ib'
run 18-login-hooks            'for p in /var/root/Library/Preferences/com.apple.loginwindow /Library/Preferences/com.apple.loginwindow; do echo "== $p"; defaults read "$p" 2>&1 | grep -iE "Hook|autoLoginUser|GuestEnabled|Hide500Users|HiddenUsersList" || echo "(no login/logout hook, auto-login, guest or hidden-user setting here)"; h="$(defaults read "$p" HiddenUsersList 2>/dev/null)" && printf "HiddenUsersList (full value): %s\n" "$h"; done'

users_hidden() {
  echo "== Accounts (names not starting with _, plus any _name with UID 500 or above), with UID"
  dscl . list /Users UniqueID | awk '$1 !~ /^_/ || $2 >= 500'
  admins="$(dscl . read /Groups/admin GroupMembership 2>/dev/null | sed 's/^GroupMembership://')"
  echo "== Admin group members:${admins:- (could not read)}"
  echo "== IsHidden for each account with UID below 500 or in the admin group (hidden admins are a red flag)"
  dscl . list /Users UniqueID | awk '$1 !~ /^_/ || $2 >= 500' | while read -r n uid; do
    [ -n "$n" ] || continue
    is_admin=0
    for a in $admins; do [ "$a" = "$n" ] && is_admin=1; done
    low=0; case "$uid" in ''|*[!0-9-]*) ;; *) [ "$uid" -lt 500 ] && low=1 ;; esac
    if [ "$low" -eq 1 ] || [ "$is_admin" -eq 1 ]; then
      tag="uid $uid"; [ "$is_admin" -eq 1 ] && tag="$tag, admin"
      printf '%s (%s): %s\n' "$n" "$tag" "$(dscl . read "/Users/$n" IsHidden 2>&1 | tr '\n' ' ')"
    fi
  done
}
runf 19-users-hidden "accounts, admin members, and which of them are hidden" users_hidden
run 20-other-users-launchagents 'ls -la /Users/*/Library/LaunchAgents 2>&1'
run 21-authdb-login-console   'echo "== Mechanisms run at the login window (system.login.console)"; security authorizationdb read system.login.console 2>/dev/null | sed -n "/<key>mechanisms<\/key>/,/<\/array>/p"; echo; echo "== Plugin bundles a mechanism name (Name:mechanism) can refer to"; echo "-- third-party: /Library/Security/SecurityAgentPlugins"; ls -1 /Library/Security/SecurityAgentPlugins 2>&1; echo "-- Apple: /System/Library/CoreServices/SecurityAgentPlugins"; ls -1 /System/Library/CoreServices/SecurityAgentPlugins 2>&1'
run 22-pam                    'ls -la /etc/pam.d; for f in /etc/pam.d/sudo*; do [ -e "$f" ] || continue; echo "== $f (comments removed)"; grep -v "^#" "$f"; done'

: > "$OUT/.done"

# Hand the output files back to your user account so Claude can read them.
give_back
echo
if grep -q "authorization denied" "$OUT/10-system-tcc.txt" 2>/dev/null; then
  echo "NOTE: Full Disk Access is not active for Terminal. Turn it on, quit Terminal (Cmd-Q), reopen, and rerun."
fi
echo "Done. Output is in: $OUT"
echo "Next: run 'bash collect-checks.sh' (no sudo). If you already ran it today, run 'SWEEP_COMBINE_ONLY=1 bash collect-checks.sh' instead."
