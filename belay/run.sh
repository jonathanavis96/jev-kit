#!/usr/bin/env bash
# Stop-hook wrapper for jev-belay. Loads only the TypeSafe key, never prints
# it, and fails open (exits 0) whenever the key is missing or the kill switch
# is set -- exactly like the guard itself.
#
# The key-file path is not hard-coded here: it comes from the shared config
# (install/config.env's AIRLOCK_KEY_FILE), the same variable every other
# component in this repository reads its key path from.
set -u
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -e "$HOME/.config/airlock/disabled" ] && exit 0
[ -e "$HOME/.config/jev-guard/disabled" ] && exit 0
# Key-file resolution: the ONE shell implementation, shared with every other
# component here. The order and the pointer-file trust rules are documented in
# airlock/keyfile.py's module docstring. Fails open if the helper is missing.
# The installed wrapper lives in ~/bin, where ../install does not exist, so
# the deployed guard release's copy is tried next. Without it the fallback
# below ignored the pointer file and resolved a different key file.
keyfile_sh="$here/../install/keyfile.sh"
[ -r "$keyfile_sh" ] || \
  keyfile_sh="${AIRLOCK_HOME:-${JEV_HOME:-$HOME/.local/share/airlock}}/current/install/keyfile.sh"
if [ -r "$keyfile_sh" ]; then
  # shellcheck disable=SC1090
  . "$keyfile_sh"
else
  airlock_key_file() {
    local f="${AIRLOCK_KEY_FILE:-${JEVKIT_KEY_FILE:-}}"
    if [ -n "$f" ]; then printf '%s\n' "$f"; return 0; fi
    [ -r "$HOME/.config/jev-kit/env" ] && { printf '%s\n' "$HOME/.config/jev-kit/env"; return 0; }
    [ -r "$HOME/.config/airlock/env" ] && { printf '%s\n' "$HOME/.config/airlock/env"; return 0; }
    printf '%s\n' "$HOME/.config/jev-kit/env"
  }
fi
envfile="$(airlock_key_file)"
if [ -z "${TYPESAFE_API_KEY:-}" ] && [ -r "$envfile" ]; then
  # Surrounding whitespace and one pair of matching quotes are dropped, as
  # airlock/keyfile.py does: KEY="abc" is the key abc, not "abc".
  TYPESAFE_API_KEY="$(sed -n 's/^ *\(export \)\?TYPESAFE_API_KEY=//p' "$envfile" | head -1 \
    | sed "s/^[[:space:]]*//; s/[[:space:]]*\$//; s/^\"\(.*\)\"\$/\1/; s/^'\(.*\)'\$/\1/")"
fi
[ -n "${TYPESAFE_API_KEY:-}" ] || exit 0
export TYPESAFE_API_KEY JEV_BELAY_LOG=1
belay_home="${AIRLOCK_BELAY_DIR:-$HOME/.local/share/jev-belay}"
[ -e "$belay_home/current/belay.mjs" ] || belay_home="$here"
exec node "$belay_home/current/belay.mjs"
