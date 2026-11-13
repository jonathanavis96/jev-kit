#!/usr/bin/env bash
# Print, or (with --apply) apply, the edit that wires a settings.json's
# airlock PreToolUse hook at the deployed copy
# ($AIRLOCK_HOME/current/hooks/airlock.py) instead of a development checkout
# -- ADDING the entry if none is there yet (a first install has nothing to
# repoint), or repointing it if an airlock/plumbline/jev_guard hook command
# already exists somewhere else.
#
# Paths are ALWAYS passed as arguments -- this script never guesses which
# account trees exist on the box (~/.claude, ~/.claude-<account>, ~/.claude-*,
# etc). --apply backs up each file it touches (timestamped, same directory)
# before writing an existing file; a settings.json that does not exist yet is
# created outright, with just the entries this run adds.
set -euo pipefail

usage() {
  cat >&2 <<EOF
usage: $0 --print|--apply [--belay] [--function-hooks] [--no-session-check]
          [--no-browse-unlock] <settings.json> [...]

  --belay            also add the belay Stop hook (matcher "*", command
                     <HOME>/bin/airlock-belay-run, timeout 25) -- only if
                     that wrapper file actually exists on this machine.
  --function-hooks   also set env.CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1.
  --session-check    add the SessionStart session check (the default).
  --no-session-check leave the SessionStart entry out.
  --browse-unlock    add the browse unlock under PostToolUse and
                     PostToolUseFailure (the default). It is
                     what lets R11 stand aside when the kit's own 'browse'
                     tool has given up, so leaving it out means a session
                     whose 'browse' fails has no browser at all.
  --no-browse-unlock leave the browse-unlock entries out.
EOF
  exit 2
}

if [ "$#" -lt 2 ]; then
  usage
fi

MODE="$1"
shift
case "$MODE" in
  --print) APPLY=0 ;;
  --apply) APPLY=1 ;;
  *) usage ;;
esac

BELAY=0
FUNCTION_HOOKS=0
# The session check is a DEFAULT component on every platform: the guard fails
# open, so a dead guard is silent, and on a workstation nothing outside the
# machine can notice. --no-session-check opts out.
SESSION_CHECK=1
# Same again for the browse unlock: a default, and --no-browse-unlock opts out.
BROWSE_UNLOCK=1
while [ "$#" -gt 0 ]; do
  case "$1" in
    --belay) BELAY=1; shift ;;
    --function-hooks) FUNCTION_HOOKS=1; shift ;;
    --session-check) SESSION_CHECK=1; shift ;;
    --no-session-check) SESSION_CHECK=0; shift ;;
    --browse-unlock) BROWSE_UNLOCK=1; shift ;;
    --no-browse-unlock) BROWSE_UNLOCK=0; shift ;;
    --) shift; break ;;
    --*) usage ;;
    *) break ;;
  esac
done

[ "$#" -ge 1 ] || usage

AIRLOCK_HOME="${AIRLOCK_HOME:-$HOME/.local/share/airlock}"
NEW_HOOK="$AIRLOCK_HOME/current/hooks/airlock.py"
BELAY_WRAPPER="${AIRLOCK_BELAY_WRAPPER:-$HOME/bin/airlock-belay-run}"

# An absolute python3, same reasoning as the hook command itself: a hook
# runs with a minimal environment and an unpredictable working directory, so
# `python3 hooks/airlock.py` or anything relying on PATH is the wrong call.
PY="${AIRLOCK_PYTHON3:-}"
if [ -z "$PY" ]; then
  PY="$(command -v python3 || true)"
fi
if [ -z "$PY" ]; then
  echo "wire.sh: no python3 found on PATH; set AIRLOCK_PYTHON3 to an absolute interpreter path" >&2
  exit 2
fi
NEW_HOOK_COMMAND="$PY $NEW_HOOK"

SESSION_CHECK_HOOK="$AIRLOCK_HOME/current/hooks/airlock_session_check.py"
SESSION_CHECK_COMMAND="$PY $SESSION_CHECK_HOOK"

BROWSE_UNLOCK_HOOK="$AIRLOCK_HOME/current/hooks/airlock_browse_unlock.py"
BROWSE_UNLOCK_COMMAND="$PY $BROWSE_UNLOCK_HOOK"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

AIRLOCK_HOME="$AIRLOCK_HOME" NEW_HOOK="$NEW_HOOK" NEW_HOOK_COMMAND="$NEW_HOOK_COMMAND" \
  APPLY="$APPLY" BELAY="$BELAY" BELAY_WRAPPER="$BELAY_WRAPPER" FUNCTION_HOOKS="$FUNCTION_HOOKS" \
  SESSION_CHECK="$SESSION_CHECK" SESSION_CHECK_HOOK="$SESSION_CHECK_HOOK" \
  SESSION_CHECK_COMMAND="$SESSION_CHECK_COMMAND" \
  BROWSE_UNLOCK="$BROWSE_UNLOCK" BROWSE_UNLOCK_HOOK="$BROWSE_UNLOCK_HOOK" \
  BROWSE_UNLOCK_COMMAND="$BROWSE_UNLOCK_COMMAND" \
  "$PY" "$SCRIPT_DIR/_wire.py" "$@"
