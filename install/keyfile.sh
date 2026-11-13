#!/usr/bin/env bash
# The shell half of the key-file resolution order. Source it; do not run it.
#
#     . "$(dirname "${BASH_SOURCE[0]}")/../install/keyfile.sh"
#     KEY_FILE="$(airlock_key_file)"
#
# There are exactly two implementations of this order and this is one of them:
# `airlock/keyfile.py` is the other, and its module docstring is where the
# order and the pointer-file trust rules are WRITTEN DOWN. Read that first.
# Everything in the shell -- install/install.sh, belay/install.sh,
# belay/run.sh, monitoring/run_health_check.sh, compaction/install.sh -- sources
# this file rather than keeping its own copy, because five copies is five
# chances for one of them to quietly resolve a different file than the hook
# does.
#
# Prints a PATH on stdout. Never the key, never the file's contents. Fails
# open: any error anywhere prints the kit default ~/.config/jev-kit/env,
# which is what an un-configured machine uses anyway. The guard-era default
# ~/.config/airlock/env is still honoured ahead of the pointer file, so an
# existing install keeps working with no action.

# Is $1 a regular file (not a symlink), owned by us, and not group- or
# world-writable? Silent; the caller decides what to say.
airlock_keyfile_trusted_file() {
  local p="$1" info uid mode
  [ -f "$p" ] || return 1
  [ -L "$p" ] && return 1
  info="$(stat -c '%u %a' "$p" 2>/dev/null)" || return 1
  uid="${info%% *}"
  mode="${info##* }"
  [ "$uid" = "$(id -u)" ] || return 1
  # Last two octal digits are group and other. Either carrying the write bit
  # (2, 3, 6, 7) means somebody else chooses what we parse.
  case "$mode" in
    *[2367][0-7]|*[0-7][2367]) return 1 ;;
  esac
  return 0
}

airlock_keyfile_trusted_dir() {
  local p="$1" info uid mode
  [ -d "$p" ] || return 1
  # A symlinked directory is judged by where it leads (-L): the link's own
  # mode is always 777. The link itself must still be ours.
  if [ -L "$p" ]; then
    [ "$(stat -c '%u' "$p" 2>/dev/null)" = "$(id -u)" ] || return 1
  fi
  info="$(stat -L -c '%u %a' "$p" 2>/dev/null)" || return 1
  uid="${info%% *}"
  mode="${info##* }"
  [ "$uid" = "$(id -u)" ] || return 1
  case "$mode" in
    *[2367][0-7]|*[0-7][2367]) return 1 ;;
  esac
  return 0
}

# The pointer file's path, whether or not it exists. Mirrors
# airlock/paths.py config_dir(): the AIRLOCK_/PLUMBLINE_/JEV_GUARD_ override
# first, then whichever of the three directory names exists.
airlock_keyfile_pointer_path() {
  local dir=""
  for candidate in "${AIRLOCK_CONFIG_DIR:-}" "${PLUMBLINE_CONFIG_DIR:-}" "${JEV_GUARD_CONFIG_DIR:-}"; do
    if [ -n "$candidate" ]; then dir="${candidate/#\~/$HOME}"; break; fi
  done
  if [ -z "$dir" ]; then
    for name in airlock plumbline jev-guard; do
      if [ -d "$HOME/.config/$name" ]; then dir="$HOME/.config/$name"; break; fi
    done
  fi
  [ -n "$dir" ] || dir="$HOME/.config/airlock"
  printf '%s\n' "$dir/keyfile.path"
}

# The path the pointer records, if the pointer is trustworthy and names an
# absolute path to an existing regular file. Otherwise nothing, exit 1.
airlock_keyfile_pointer_target() {
  local pointer recorded
  pointer="$(airlock_keyfile_pointer_path)"
  airlock_keyfile_trusted_file "$pointer" || return 1
  airlock_keyfile_trusted_dir "$(dirname "$pointer")" || return 1
  recorded="$(head -n1 "$pointer" 2>/dev/null)" || return 1
  # Trim surrounding whitespace without a subshell.
  recorded="${recorded#"${recorded%%[![:space:]]*}"}"
  recorded="${recorded%"${recorded##*[![:space:]]}"}"
  case "$recorded" in ""|"#"*) return 1 ;; esac
  recorded="${recorded/#\~/$HOME}"
  case "$recorded" in /*) ;; *) return 1 ;; esac
  [ -f "$recorded" ] || return 1
  [ -L "$recorded" ] && return 1
  printf '%s\n' "$recorded"
}

# The two paths airlock/keyfile.py finds on its own: the kit default and the
# guard-era default. install/install.sh uses this to decide whether a pointer
# file is needed at all -- pointing at a path resolution already finds would be
# noise, and one more security-relevant file to keep correct.
airlock_keyfile_is_default() {
  case "$1" in
    "$HOME/.config/jev-kit/env"|"$HOME/.config/airlock/env") return 0 ;;
    *) return 1 ;;
  esac
}

airlock_key_file() {
  local f="${AIRLOCK_KEY_FILE:-${JEVKIT_KEY_FILE:-${PLUMBLINE_KEY_FILE:-${JEV_GUARD_KEY_FILE:-}}}}"
  if [ -n "$f" ]; then
    printf '%s\n' "${f/#\~/$HOME}"
    return 0
  fi
  # The kit-level default first, then the guard-era default, which stays
  # honoured for good so an existing install keeps working with no action.
  local d
  for d in "$HOME/.config/jev-kit/env" "$HOME/.config/airlock/env"; do
    if [ -r "$d" ]; then
      printf '%s\n' "$d"
      return 0
    fi
  done
  local recorded
  if recorded="$(airlock_keyfile_pointer_target)"; then
    printf '%s\n' "$recorded"
    return 0
  fi
  # Any extra path this machine's install/config.env names, in order.
  # Nothing is hard-coded here: on a fresh machine the loop is empty.
  local IFS=:
  local candidate
  for candidate in ${AIRLOCK_LEGACY_KEY_FILES:-}; do
    [ -n "$candidate" ] || continue
    candidate="${candidate/#\~/$HOME}"
    if [ -r "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  printf '%s\n' "$HOME/.config/jev-kit/env"
}
