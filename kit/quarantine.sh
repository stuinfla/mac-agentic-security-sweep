#!/bin/bash
# Mac Claude Security Sweep v2: reversible cleanup helper.
# Moves ONE item into the kit's quarantine/ folder instead of deleting it, and
# records the exact undo command first. Nothing is ever deleted.
#
#   bash quarantine.sh <path>                 # user-owned item (e.g. ~/Library/LaunchAgents/x.plist)
#   sudo bash quarantine.sh <path>            # system item (e.g. /Library/LaunchDaemons/x.plist)
#   bash quarantine.sh --launchd <plist>      # stop a launch agent/daemon first, then quarantine its plist
#
# Only these areas can be cleaned (anything else is refused; ask for help instead):
#   ~/Library/LaunchAgents, /Library/LaunchAgents, /Library/LaunchDaemons,
#   /Library/PrivilegedHelperTools, /Applications/*.app, ~/Applications/*.app,
#   /Users/Shared, /tmp (/private/tmp), NativeMessagingHosts/*.json (yours or /Library),
#   ~/Library/Application Support/*/NativeMessagingHosts, ~/.claude/skills, ~/.claude/plugins
# Genuine Apple-signed programs and apps are never touched.
#
# Where things go and how to undo:
#   run without sudo -> quarantine/<stamp>/...   undo: bash quarantine/UNDO.sh
#   run with sudo    -> /Library/Application Support/Mac Claude Security Sweep/quarantine/<stamp>/...
#                       undo: sudo bash "/Library/Application Support/Mac Claude Security Sweep/UNDO-system.sh"
#   (System items are kept in a root-only folder outside the kit, so a program running as
#    you cannot swap the undo file or the quarantined items for something else.)
# Undo is safe to re-run: anything already back in place is skipped.

set -u
die() { echo "REFUSED: $*" >&2; exit 1; }

# pdir <dir>: physical (symlink-free) absolute path of a directory, newline-safe.
pdir() { _p="$(cd -P -- "$1" 2>/dev/null && pwd -P && echo x)" || return 1; _p="${_p%x}"; printf '%s' "${_p%?}"; }
# ldir <dir>: logical absolute path (as typed, symlinks kept), newline-safe.
ldir() { _p="$(cd -- "$1" 2>/dev/null && pwd -L && echo x)" || return 1; _p="${_p%x}"; printf '%s' "${_p%?}"; }

HERE="$(pdir "$(dirname "$0")")" || die "cannot locate the kit folder"
QROOT="$HERE/quarantine"
STAMP="$(date +%Y%m%d-%H%M%S)"
MYUID="$(id -u)"
IS_ROOT=0; [ "$MYUID" -eq 0 ] && IS_ROOT=1

LAUNCHD=0
if [ "${1:-}" = "--launchd" ]; then LAUNCHD=1; shift; fi
[ $# -eq 1 ] || die "usage: bash quarantine.sh [--launchd] <path>"

# The user's real home, even under sudo.
UHOME="$HOME"
if [ "$IS_ROOT" -eq 1 ] && [ -n "${SUDO_USER:-}" ] && command -v dscl >/dev/null 2>&1; then
  _h="$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | sed -n 's/^NFSHomeDirectory: //p' | head -n 1)"
  [ -n "$_h" ] && [ -d "$_h" ] && UHOME="$_h"
fi
UHOME_P="$(pdir "$UHOME")" || UHOME_P="$UHOME"

TARGET="$1"
[ -n "$TARGET" ] || die "empty path"
[ -e "$TARGET" ] || [ -L "$TARGET" ] || die "not found: $TARGET"

# Split into parent + name with parameter expansion only (keeps odd characters,
# including newlines). The final name is never followed if it is a symlink.
T="$TARGET"
while [ "${#T}" -gt 1 ] && [ "${T%/}" != "$T" ]; do T="${T%/}"; done
case "$T" in
  */*) PARENT="${T%/*}"; NAME="${T##*/}"; [ -n "$PARENT" ] || PARENT="/" ;;
  *)   PARENT="."; NAME="$T" ;;
esac
case "$NAME" in ''|.|..) die "give the full path of one specific item, not a folder shortcut" ;; esac
PDIR="$(pdir "$PARENT")" || die "cannot resolve the folder containing: $TARGET"
LDIR="$(ldir "$PARENT")" || LDIR="$PDIR"
if [ "$PDIR" = "/" ]; then ABS="/$NAME"; else ABS="$PDIR/$NAME"; fi
if [ "$LDIR" = "/" ]; then ABS_L="/$NAME"; else ABS_L="$LDIR/$NAME"; fi
[ -e "$ABS" ] || [ -L "$ABS" ] || die "could not resolve the path safely: $TARGET"

# ---- Safety rail 1: never the kit itself (or a folder that contains it), never whole folders.
case "$ABS" in "$HERE"|"$HERE"/*) die "that is inside the sweep kit itself." ;; esac
case "$HERE/" in "$ABS"/*) die "that folder contains the sweep kit itself." ;; esac
case "$ABS" in
  /|/Applications|/Library|/Users|/Users/Shared|/tmp|/private|/private/tmp|"$UHOME_P"|"$UHOME_P/Library"|"$UHOME_P/Applications"|/Library/LaunchDaemons|/Library/LaunchAgents|/Library/PrivilegedHelperTools|"$UHOME_P/Library/LaunchAgents"|"$UHOME_P/.claude"|"$UHOME_P/.claude/skills"|"$UHOME_P/.claude/plugins")
    die "refusing to quarantine a whole top-level folder: $ABS" ;;
esac

# ---- Safety rail 2: ALLOW-LIST. ABS has a symlink-free parent, so it cannot escape.
ALLOWED=0
case "$ABS" in
  "$UHOME_P"/Library/LaunchAgents/*) ALLOWED=1 ;;
  /Library/LaunchAgents/*|/Library/LaunchDaemons/*|/Library/PrivilegedHelperTools/*) ALLOWED=1 ;;
  /Applications/*.app|"$UHOME_P"/Applications/*.app) ALLOWED=1 ;;
  /Users/Shared/*|/private/tmp/*|/tmp/*) ALLOWED=1 ;;
  "$UHOME_P"/.claude/skills/*|"$UHOME_P"/.claude/plugins/*) ALLOWED=1 ;;
  "$UHOME_P/Library/Application Support/"*/NativeMessagingHosts/*) ALLOWED=1 ;;
  "$UHOME_P"/*/NativeMessagingHosts/*.json|/Library/*/NativeMessagingHosts/*.json) ALLOWED=1 ;;
esac
[ "$ALLOWED" -eq 1 ] || die "$ABS is outside the areas this kit may clean; ask for help instead."
# Allowed .app areas: only the bundle itself, never a file inside an app bundle.
case "$ABS" in /Applications/*.app/*|"$UHOME_P"/Applications/*.app/*) die "$ABS is inside an app bundle; quarantine the whole .app instead." ;; esac

# ---- Safety rail 3: genuine Apple-signed code is never touched. Names are NOT
# trusted (a fake com.apple.* plist is a classic lure); the signature is.
if { [ -d "$ABS" ] && case "$ABS" in *.app) true ;; *) false ;; esac; } || { [ -f "$ABS" ] && [ -x "$ABS" ]; }; then
  if command -v codesign >/dev/null 2>&1; then
    _sig="$(codesign -dv --verbose=2 "$ABS" 2>&1)"
    if printf '%s\n' "$_sig" | grep -q '^Authority=Software Signing$'; then
      if codesign --verify -R="anchor apple" "$ABS" >/dev/null 2>&1; then
        die "$ABS is Apple-signed; not touched."
      fi
      echo "WARNING: $ABS claims an Apple signature but FAILS Apple verification. Treat it as suspicious." >&2
    elif printf '%s\n' "$_sig" | grep -q '^Authority=Apple Mac OS Application Signing$'; then
      echo "NOTE: $ABS is a Mac App Store app (signed through the App Store). It is only moved because you asked; it can be put back with the undo command." >&2
    fi
  fi
fi

# ---- Permission check BEFORE anything is stopped or moved.
if [ "$IS_ROOT" -eq 0 ]; then
  [ -w "$PDIR" ] || die "no permission to move $ABS: re-run with sudo"
  # Sticky folders (/tmp, /Users/Shared): only the owner may move an item.
  if [ -k "$PDIR" ] && ! [ -O "$ABS" ] && ! [ -O "$PDIR" ]; then die "no permission to move $ABS (owned by someone else): re-run with sudo"; fi
  # Moving a folder to a new parent also needs write access to the folder itself.
  if [ -d "$ABS" ] && ! [ -L "$ABS" ] && ! [ -w "$ABS" ]; then die "no permission to move $ABS: re-run with sudo"; fi
fi

# ---- Where it goes, and which undo file records it.
if [ "$IS_ROOT" -eq 1 ]; then
  # System items live in a root-only folder OUTSIDE the user-writable kit folder, and
  # are restored by a root-owned undo file there. Nothing here is ever chowned to the user.
  SYSROOT="${SWEEP_SYSROOT:-/Library/Application Support/Mac Claude Security Sweep}"
  [ -L "$SYSROOT" ] && die "$SYSROOT is a symlink; refusing"
  if [ ! -d "$SYSROOT" ]; then (umask 077 && mkdir -p "$SYSROOT") || die "cannot create $SYSROOT"; fi
  [ -O "$SYSROOT" ] || die "$SYSROOT is not owned by root; refusing"
  chmod 700 "$SYSROOT" 2>/dev/null
  QSYS="$SYSROOT/quarantine"
  [ -L "$QSYS" ] && die "$QSYS is a symlink; refusing"
  if [ ! -d "$QSYS" ]; then (umask 077 && mkdir "$QSYS") || die "cannot create $QSYS"; fi
  [ -O "$QSYS" ] || die "$QSYS is not owned by root; refusing"
  chmod 700 "$QSYS" 2>/dev/null
  DEST="$QSYS/$STAMP$ABS"
  UNDO="$SYSROOT/UNDO-system.sh"       # root-only folder, root-owned
  UNDO_CMD="sudo bash $(printf '%q' "$UNDO")"
else
  if [ ! -d "$QROOT" ]; then mkdir -p "$QROOT" || die "cannot create $QROOT"; fi
  [ -L "$QROOT" ] && die "$QROOT is a symlink; refusing"
  DEST="$QROOT/$STAMP$ABS"
  UNDO="$QROOT/UNDO.sh"
  UNDO_CMD="bash $(printf '%q' "$UNDO")"
fi
if [ -e "$DEST" ] || [ -L "$DEST" ]; then die "quarantine slot already used: $DEST (wait a second and retry)"; fi
[ -L "$UNDO" ] && die "$UNDO is a symlink; refusing"
mkdir -p "${DEST%/*}" || die "cannot create quarantine folder; nothing was changed"

# ---- launchd: decide whether to stop the job (only if THIS file is what is loaded).
DO_BOOTOUT=0; DOMAIN=""; LABEL=""
if [ "$LAUNCHD" -eq 1 ]; then
  case "$ABS" in *.plist) ;; *) die "--launchd expects a .plist file" ;; esac
  if [ -L "$ABS" ] || [ ! -f "$ABS" ]; then die "--launchd expects a regular .plist file"; fi
  LABEL="$(plutil -extract Label raw "$ABS" 2>/dev/null)" || die "could not read Label from $ABS"
  [ -n "$LABEL" ] || die "empty Label in $ABS"
  case "$LABEL" in */*|*"
"*) die "unusual Label in $ABS; ask for help instead" ;; esac
  case "$ABS" in
    /Library/LaunchDaemons/*) DOMAIN="system" ;;
    /Library/LaunchAgents/*|"$UHOME_P"/Library/LaunchAgents/*) DOMAIN="gui/${SUDO_UID:-$MYUID}" ;;
    *) die "--launchd only handles plists in a LaunchAgents/LaunchDaemons folder" ;;
  esac
  if [ "$DOMAIN" = "system" ] && [ "$IS_ROOT" -eq 0 ]; then die "system daemon: re-run with sudo"; fi
  if INFO="$(launchctl print "$DOMAIN/$LABEL" 2>/dev/null)"; then
    LPATH="$(printf '%s\n' "$INFO" | sed -n 's/^[[:space:]]*path = //p' | head -n 1)"
    if [ "$LPATH" = "$ABS" ] || [ "$LPATH" = "$ABS_L" ]; then
      DO_BOOTOUT=1
    elif [ -z "$LPATH" ]; then
      case "$LABEL" in
        com.apple.*) echo "NOTE: a job named $LABEL is running but launchd did not say which file it came from; not stopping it (it may be genuine). The plist will still be quarantined; restart the Mac afterwards." ;;
        *) DO_BOOTOUT=1 ;;
      esac
    else
      echo "NOTE: the running job named $LABEL comes from a different file ($LPATH), so it is NOT stopped. Only this plist is quarantined."
    fi
  else
    echo "NOTE: $LABEL is not loaded in $DOMAIN; nothing to stop."
  fi
fi

# ---- Record the undo command FIRST, so a quarantined item can always be restored.
if [ ! -f "$UNDO" ]; then
  if [ "$IS_ROOT" -eq 1 ]; then
    { printf '#!/bin/bash\n# Undo for SYSTEM items quarantined with sudo, newest last.\n'
      printf '# Run:  sudo bash %q   (your own items are undone with: bash quarantine/UNDO.sh)\n' "$UNDO"
      printf 'set -u\n[ "$(id -u)" -eq 0 ] || { echo "Run with sudo, exactly as shown at the top of this file."; exit 1; }\n'
      printf 'QSYS=%q\n' "$QSYS"
      printf 'if [ -L "$QSYS" ] || [ ! -d "$QSYS" ] || [ ! -O "$QSYS" ]; then echo "REFUSED: $QSYS is not a root-owned folder; ask for help instead."; exit 1; fi\n'
    } > "$UNDO" || die "cannot write $UNDO; nothing was changed"
    chmod 644 "$UNDO" 2>/dev/null
  else
    { printf '#!/bin/bash\n# Undo for items quarantined WITHOUT sudo, newest last.\n'
      printf '# Run:  bash quarantine/UNDO.sh\n'
      printf '# System items (quarantined with sudo) have their own undo file; Claude shows its path when it moves one.\n'
      printf 'set -u\n'
    } > "$UNDO" || die "cannot write $UNDO; nothing was changed"
  fi
fi
{
  printf '\n# %s  quarantined %q  (%s)\n' "$(date)" "$ABS" "$STAMP"
  if [ "$DO_BOOTOUT" -eq 1 ]; then
    printf 'if [ -e %q ] || [ -L %q ]; then echo SKIPPED, something already exists at: %q; else mkdir -p %q && mv %q %q && echo Restored: %q && launchctl bootstrap %q %q; fi\n' \
      "$ABS" "$ABS" "$ABS" "$PDIR" "$DEST" "$ABS" "$ABS" "$DOMAIN" "$ABS"
  else
    printf 'if [ -e %q ] || [ -L %q ]; then echo SKIPPED, something already exists at: %q; else mkdir -p %q && mv %q %q && echo Restored: %q; fi\n' \
      "$ABS" "$ABS" "$ABS" "$PDIR" "$DEST" "$ABS" "$ABS"
  fi
} >> "$UNDO" || die "cannot write the undo line to $UNDO; nothing was changed"

# ---- Stop the job (only now that the move is known to be permitted and undo is recorded).
if [ "$DO_BOOTOUT" -eq 1 ]; then
  echo "Stopping $LABEL in $DOMAIN ..."
  launchctl bootout "$DOMAIN/$LABEL" 2>&1 || echo "(launchctl could not stop it; continuing. It stops for good after a restart.)"
fi

# ---- Move.
if ! mv "$ABS" "$DEST"; then
  printf '# (the move recorded above FAILED; nothing to restore for it)\n' >> "$UNDO" 2>/dev/null
  if [ "$DO_BOOTOUT" -eq 1 ]; then
    echo "MOVE FAILED: the job $LABEL WAS stopped, but its file is still in place at: $ABS" >&2
    echo "To start it again:  $( [ "$IS_ROOT" -eq 1 ] && printf 'sudo ' )launchctl bootstrap $(printf '%q %q' "$DOMAIN" "$ABS")" >&2
    exit 1
  fi
  die "move failed; nothing was changed"
fi

echo "Quarantined: $ABS"
echo "      now at: $DEST"
echo "Undo recorded in: $UNDO"
echo "To undo:  $UNDO_CMD"
echo "(Undo restores every item listed in that file that is not already back in place.)"
