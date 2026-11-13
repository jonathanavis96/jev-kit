#!/usr/bin/env bash
# airlock: prove each installed piece actually runs.
#
# A download that succeeded is not a capability that works. This script does
# not check that files exist -- it runs things and reads the output:
#
#   - the health check, end to end
#   - ONE REAL DENY and ONE REAL ALLOW through the actual hook process, in
#     enforce mode, against a throwaway HOME, so nothing touches the real log
#     or the real loop-protection state
#   - the SessionStart session check, against a throwaway HOME, timed
#   - a plocate query against the real index
#   - a daemon ping over the Unix socket
#
# Exit 0 if everything that is installed works, 1 otherwise. A component that
# is not installed is reported as "skipped", not as a failure.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -f "$SCRIPT_DIR/config.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$SCRIPT_DIR/config.env"
  set +a
fi

AIRLOCK_HOME="${AIRLOCK_HOME:-${PLUMBLINE_HOME:-${JEV_HOME:-$HOME/.local/share/airlock}}}"
PY="${PYTHON:-python3}"
: "${XDG_RUNTIME_DIR:=/run/user/$(id -u)}"
export XDG_RUNTIME_DIR

FAILED=0
PASSED=0
SKIPPED=0

pass() { printf '  PASS  %s\n' "$*"; PASSED=$((PASSED + 1)); }
fail() { printf '  FAIL  %s\n' "$*"; FAILED=$((FAILED + 1)); }
skip() { printf '  skip  %s\n' "$*"; SKIPPED=$((SKIPPED + 1)); }
head_() { printf '\n== %s\n' "$*"; }

# Which copy of airlock is live? Prefer the deployed release, since that is
# what settings.json and the units actually run.
LIVE="$REPO_ROOT"
if [ -e "$AIRLOCK_HOME/current" ]; then
  LIVE="$(readlink -f "$AIRLOCK_HOME/current")"
fi
HOOK="$LIVE/hooks/airlock.py"

echo "airlock doctor"
echo "  live copy: $LIVE"
echo "  python:    $("$PY" -c 'import sys;print(sys.executable, "%d.%d.%d"%sys.version_info[:3])' 2>/dev/null || echo "NOT USABLE")"

# ---------------------------------------------------------------------------
head_ "The hook process"

if [ ! -f "$HOOK" ]; then
  fail "no hook at $HOOK -- run install/install.sh --guard"
else
  TMPHOME="$(mktemp -d)"
  trap 'rm -rf "$TMPHOME"' EXIT
  # The checks below run the hook against a throwaway HOME. A config or state
  # directory exported by config.env (or the calling shell) would point the
  # hook back at the real ones -- the real rules.json, mode and kill switch --
  # so those variables are dropped for these runs.
  ISOLATED=(env)
  for var in AIRLOCK_CONFIG_DIR PLUMBLINE_CONFIG_DIR JEV_GUARD_CONFIG_DIR \
             AIRLOCK_STATE_DIR PLUMBLINE_STATE_DIR JEV_GUARD_STATE_DIR; do
    ISOLATED+=(-u "$var")
  done

  # --- one deny -----------------------------------------------------------
  # R6: opening a browser on a headless box. Code-only, so this needs no API
  # key and no network -- it proves the hook process, the rules table, the
  # mode resolution and the deny JSON, and nothing else.
  #
  # R6 is OFF by default on every platform now, so this check pins it on in
  # the throwaway HOME's own rules.json. That is deliberate: the assertion
  # here is about the hook machinery, not about this machine's R6 policy,
  # which is reported separately under "Mode and config" below.
  mkdir -p "$TMPHOME/.config/airlock"
  printf '%s\n' '{"R6-gui-or-browser": "deny"}' > "$TMPHOME/.config/airlock/rules.json"
  deny_out="$(printf '%s' '{"session_id":"doctor-deny","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"xdg-open https://example.com"}}' \
    | "${ISOLATED[@]}" HOME="$TMPHOME" AIRLOCK_MODE=enforce "$PY" "$HOOK" 2>/dev/null)"
  if printf '%s' "$deny_out" | "$PY" -c '
import json,sys
d = json.load(sys.stdin)["hookSpecificOutput"]
sys.exit(0 if d.get("permissionDecision") == "deny" else 1)
' 2>/dev/null; then
    pass "deny: xdg-open blocked in enforce mode"
    printf '        %s\n' "$(printf '%s' "$deny_out" | "$PY" -c 'import json,sys;print(json.load(sys.stdin)["hookSpecificOutput"]["permissionDecisionReason"].splitlines()[0])' 2>/dev/null)"
  else
    fail "deny: expected a deny for 'xdg-open', got: ${deny_out:-<nothing>}"
  fi

  # --- one allow ----------------------------------------------------------
  # An ordinary command no rule covers must produce NOTHING at all: no JSON,
  # no log row, no subprocess. Empty stdout is the whole assertion.
  allow_out="$(printf '%s' '{"session_id":"doctor-allow","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"echo hello"}}' \
    | "${ISOLATED[@]}" HOME="$TMPHOME" AIRLOCK_MODE=enforce "$PY" "$HOOK" 2>/dev/null)"
  if [ -z "$allow_out" ]; then
    pass "allow: 'echo hello' passes through silently, no output"
  else
    fail "allow: expected no output, got: $allow_out"
  fi

  # --- fail-open ----------------------------------------------------------
  broken_out="$(printf '%s' 'not json at all' \
    | "${ISOLATED[@]}" HOME="$TMPHOME" AIRLOCK_MODE=enforce "$PY" "$HOOK" 2>/dev/null; echo "rc=$?")"
  if [ "$broken_out" = "rc=0" ]; then
    pass "fail-open: malformed payload exits 0 with no output"
  else
    fail "fail-open: expected 'rc=0' and no output, got: $broken_out"
  fi

  # --- kill switch --------------------------------------------------------
  killed_out="$(printf '%s' '{"session_id":"doctor-kill","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"xdg-open https://example.com"}}' \
    | "${ISOLATED[@]}" HOME="$TMPHOME" AIRLOCK_MODE=enforce AIRLOCK_DISABLE=1 "$PY" "$HOOK" 2>/dev/null)"
  if [ -z "$killed_out" ]; then
    pass "kill switch: AIRLOCK_DISABLE=1 makes the hook a complete no-op"
  else
    fail "kill switch: expected no output, got: $killed_out"
  fi

  rm -rf "$TMPHOME"
  trap - EXIT
fi

# ---------------------------------------------------------------------------
head_ "Session check (SessionStart)"

# Two separate questions, and both matter. Is the entry REGISTERED -- a hook
# nobody calls is not a check -- and does it RUN inside its budget?
#
# The run is against a THROWAWAY HOME on purpose. This hook de-duplicates
# itself: showing a warning records that it was shown, and running it against
# the real state directory here would consume today's warning and leave the
# person's next real session silent about a genuine fault.
SESSION_HOOK="$LIVE/hooks/airlock_session_check.py"
if [ ! -f "$SESSION_HOOK" ]; then
  skip "no session check at $SESSION_HOOK (install/install.sh --session-check)"
else
  SC_HOME="$(mktemp -d)"
  SC_EVENT='{"session_id":"doctor-session","hook_event_name":"SessionStart","source":"startup","cwd":"/tmp"}'
  SC_START="$("$PY" -c 'import time;print(time.time())')"
  # HOME alone is not enough: install/config.env may have exported
  # AIRLOCK_CONFIG_DIR / AIRLOCK_STATE_DIR / AIRLOCK_HOME, and any one of
  # those would drag the run back to the real state directory.
  sc_out="$(printf '%s' "$SC_EVENT" | env -u AIRLOCK_CONFIG_DIR -u AIRLOCK_STATE_DIR \
    -u PLUMBLINE_CONFIG_DIR -u PLUMBLINE_STATE_DIR -u JEV_GUARD_CONFIG_DIR \
    -u JEV_GUARD_STATE_DIR -u PLUMBLINE_HOME -u JEV_HOME \
    HOME="$SC_HOME" AIRLOCK_HOME="$SC_HOME/.local/share/airlock" \
    "$PY" "$SESSION_HOOK" 2>/dev/null)"
  SC_RC=$?
  SC_MS="$("$PY" -c "import sys,time;print(int((time.time()-float(sys.argv[1]))*1000))" "$SC_START")"
  rm -rf "$SC_HOME"
  if [ "$SC_RC" -ne 0 ]; then
    fail "session check exited $SC_RC; it must always exit 0 (fail open)"
  elif [ "$SC_MS" -gt 1500 ]; then
    fail "session check took ${SC_MS}ms end to end; its own budget is 300ms plus interpreter start-up"
  else
    pass "session check ran in ${SC_MS}ms (budget 300ms plus interpreter start-up)"
  fi
  if [ -n "$sc_out" ]; then
    if printf '%s' "$sc_out" | "$PY" -c '
import json,sys
d = json.load(sys.stdin)
assert isinstance(d.get("systemMessage"), str) and d["systemMessage"]
h = d["hookSpecificOutput"]
assert h.get("hookEventName") == "SessionStart"
assert isinstance(h.get("additionalContext"), str)
' 2>/dev/null; then
      pass "session check output is a valid SessionStart hook result"
      printf '        %s\n' "$(printf '%s' "$sc_out" | "$PY" -c 'import json,sys;print(json.load(sys.stdin)["systemMessage"].splitlines()[0])' 2>/dev/null)"
      printf '        (that is against a THROWAWAY HOME with no key, so a message here is expected)\n'
    else
      fail "session check printed something that is not a valid hook result: ${sc_out:0:200}"
    fi
  else
    pass "session check was silent (nothing wrong to report on a throwaway HOME)"
  fi

  # Wiring. Paths are never guessed for an EDIT, but this is a read-only
  # report, so every account tree on the box is worth looking at.
  #
  # The verdict is deliberately per-FILE and relative to the guard. A file
  # that registers the PreToolUse guard but NOT the session check is a
  # half-wired install -- almost always a machine wired before this component
  # existed -- and that is a real fault worth a FAIL. A file with neither is
  # simply not wired, which is a supported state (`--wire` is opt-in), so it
  # is a skip with the command to fix it.
  SC_WIRED=0
  SC_HALF=0
  SC_ANY=0
  for f in "$HOME"/.claude*/settings.json "$HOME"/.claude*/settings.local.json; do
    [ -f "$f" ] || continue
    SC_ANY=1
    SC_STATE="$("$PY" - "$f" <<'PYSC' 2>/dev/null || echo error
import json, sys


def commands(data, event):
    out = []
    for entry in (data.get("hooks") or {}).get(event) or []:
        if not isinstance(entry, dict):
            continue
        for h in entry.get("hooks") or []:
            if isinstance(h, dict) and isinstance(h.get("command"), str):
                out.append(h["command"])
    return out


data = json.load(open(sys.argv[1]))
guard = any("hooks/airlock.py" in c or "airlock-hook.py" in c
            for c in commands(data, "PreToolUse"))
session = any("airlock_session_check.py" in c or "airlock-session-check.py" in c
              for c in commands(data, "SessionStart"))
print("wired" if session else ("half" if guard else "absent"))
PYSC
)"
    case "$SC_STATE" in
      wired)
        pass "wired: $f registers the SessionStart session check"
        SC_WIRED=1 ;;
      half)
        fail "$f registers the PreToolUse guard but NOT the SessionStart session check. Fix: install/install.sh --guard --session-check --wire $f"
        SC_HALF=1 ;;
    esac
  done
  if [ "$SC_WIRED" = "0" ] && [ "$SC_HALF" = "0" ]; then
    if [ "$SC_ANY" = "1" ]; then
      skip "no settings.json under $HOME wires airlock at all (--wire is opt-in). To add both entries: install/install.sh --guard --session-check --wire <settings.json>"
    else
      skip "no settings.json found under $HOME to check the wiring in"
    fi
  fi
fi

# ---------------------------------------------------------------------------
head_ "Mode and config"

MODE="$(cd "$LIVE" && "$PY" -c 'from airlock import mode; print(mode.resolve_mode())' 2>/dev/null)"
if [ -n "$MODE" ]; then
  pass "resolved mode: $MODE"
  if [ "$MODE" = "shadow" ]; then
    MODE_FILE="$(cd "$LIVE" && "$PY" -c 'from airlock import paths; print(paths.config_file("mode"))' 2>/dev/null)"
    printf '        shadow logs and never blocks. To arm it:  echo enforce > %s\n' "${MODE_FILE:-<config dir>/mode}"
  fi
else
  fail "could not resolve the mode -- is $LIVE importable?"
fi

# R6 (opening a GUI or a browser) is off by default on EVERY platform, and a
# headless machine turns it on with one entry in rules.json. Say which way
# this machine is set and why, because "the guard is installed" and "the guard
# will stop an agent opening a browser on this server" are different claims.
R6_LINE="$(cd "$LIVE" && "$PY" -c '
from airlock import headless, paths, rules
rid = headless.R6_RULE_ID
rule = rules.RULES_BY_ID[rid]
path = paths.config_file("rules.json")
ov = rules.load_action_overrides()
default = rules.default_action(rule)
if rid in ov:
    print("%s\t%s\tset to %r in %s" % (rid, ov[rid], ov[rid], path))
else:
    hl, why = headless.detect_headless()
    print("%s\t%s\tno entry in %s, so the built-in default applies; this machine looks %s (%s)"
          % (rid, default, path, "HEADLESS" if hl else "like a desktop", why))
' 2>/dev/null)"
if [ -n "$R6_LINE" ]; then
  R6_ACTION="$(printf '%s' "$R6_LINE" | cut -f2)"
  R6_WHY="$(printf '%s' "$R6_LINE" | cut -f3-)"
  if [ "$R6_ACTION" = "off" ]; then
    pass "R6 (GUI/browser): OFF -- $R6_WHY"
    R6_RULES_JSON="$(cd "$LIVE" && "$PY" -c 'from airlock import paths;print(paths.config_file("rules.json"))' 2>/dev/null)"
    printf '        headless machine? turn it on with this one command:\n'
    printf '          (cd %s && %s -m airlock.headless merge "%s")\n' \
      "$LIVE" "$PY" "${R6_RULES_JSON:-$HOME/.config/airlock/rules.json}"
  else
    pass "R6 (GUI/browser): $R6_ACTION -- $R6_WHY"
  fi
else
  fail "could not read the R6 setting -- is $LIVE importable?"
fi

if (cd "$LIVE" && "$PY" -c '
from airlock import paths
c, s = paths.config_dir(), paths.state_dir()
print("config:", c)
print("state: ", s)
' 2>/dev/null | sed "s/^/        /"); then
  pass "config and state directories resolve"
else
  fail "config/state directories do not resolve"
fi

# ---------------------------------------------------------------------------
head_ "The API key"
# Presence and PATHS only. The value is never read into a variable, never
# printed. Which file is in use matters when the answer is surprising -- the
# resolution order (and why a pointer file can be refused) is documented in
# airlock/keyfile.py's module docstring, which is the only place it lives.
if (cd "$LIVE" && "$PY" -c '
import os
from airlock import keyfile
print("in use:  %s" % keyfile.key_file())
for label, path in (("kit  ", keyfile.DEFAULT_ENV_FILE),
                    ("guard", keyfile.GUARD_ENV_FILE)):
    expanded = os.path.expanduser(path)
    print("%s default: %s (%s)"
          % (label, expanded, "present" if os.path.isfile(expanded) else "absent"))
pointer = keyfile.pointer_file_path()
if pointer and os.path.exists(pointer):
    target = keyfile.pointer_target()
    print("pointer: %s -> %s" % (pointer, target or "(not honoured)"))
else:
    print("pointer: %s (absent; a default path is in use)" % pointer)
for note in keyfile.pointer_diagnostics():
    print("note:    %s" % note)
' 2>/dev/null | sed "s/^/        /"); then
  :
else
  fail "could not resolve the key-file path"
fi
if (cd "$LIVE" && "$PY" -c '
import sys
from airlock import keyfile
sys.exit(0 if keyfile.get_api_key() else 1)
' 2>/dev/null); then
  pass "an API key is loadable (its value was not printed, and never is)"
else
  skip "no API key found; every guard fails open and judges nothing"
fi

# ---------------------------------------------------------------------------
head_ "Daemon"
SOCK="$(cd "$LIVE" && "$PY" -c 'from airlock import paths; print(paths.runtime_socket())' 2>/dev/null)"
if [ -z "$SOCK" ]; then
  fail "could not resolve the daemon socket path"
elif [ ! -S "$SOCK" ]; then
  skip "no socket at $SOCK (daemon not installed, or systemd is off -- the client falls back to direct HTTPS)"
else
  if (cd "$LIVE" && "$PY" - <<'PY' 2>/dev/null
import json, socket, sys
from airlock import paths
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
s.connect(paths.runtime_socket())
s.sendall(b'{"op": "ping"}\n')
line = s.makefile("rb").readline()
s.close()
sys.exit(0 if json.loads(line).get("pong") else 1)
PY
  ); then
    pass "daemon ping: socket $SOCK answered {\"pong\": true}"
  else
    fail "daemon socket $SOCK exists but did not answer a ping"
  fi
fi

# ---------------------------------------------------------------------------
head_ "Health check"
if [ ! -f "$LIVE/airlock/health.py" ]; then
  skip "no health module in the live copy"
else
  HEALTH_JSON="$(cd "$LIVE" && timeout 20 "$PY" -m airlock.health 2>/dev/null)"
  HEALTH_RC=$?
  if [ -z "$HEALTH_JSON" ]; then
    fail "health check produced no output (exit $HEALTH_RC)"
  else
    STATUS="$(printf '%s' "$HEALTH_JSON" | "$PY" -c 'import json,sys;print(json.load(sys.stdin).get("status","?"))' 2>/dev/null)"
    case "$STATUS" in
      healthy) pass "health: healthy (exit $HEALTH_RC)" ;;
      degraded) pass "health: degraded (exit $HEALTH_RC) -- it ran and reported honestly" ;;
      *) skip "health: $STATUS (exit $HEALTH_RC); usually means no daemon and/or no key" ;;
    esac
    printf '        %s\n' "$(printf '%s' "$HEALTH_JSON" | cut -c1-200)"
  fi
fi

# ---------------------------------------------------------------------------
head_ "Filesearch"
DB="$HOME/.cache/plocate/home.db"
if ! command -v plocate >/dev/null 2>&1; then
  skip "plocate not installed"
elif [ ! -f "$DB" ]; then
  skip "no index at $DB (run filesearch/install.sh)"
else
  HITS="$(plocate -d "$DB" -i -c 'airlock' 2>/dev/null)"
  if [ -n "$HITS" ]; then
    pass "plocate query answered from $DB ($HITS match(es) for 'airlock')"
  else
    # Zero matches is still a working index -- prove it with a pattern that
    # must exist, the index file's own directory.
    if plocate -d "$DB" -i -c 'plocate' >/dev/null 2>&1; then
      pass "plocate query answered from $DB (0 matches for 'airlock'; index may predate this install)"
    else
      fail "plocate could not query $DB"
    fi
  fi
fi

# ---------------------------------------------------------------------------
head_ "Timers"
if ! command -v systemctl >/dev/null 2>&1 || ! systemctl --user show-environment >/dev/null 2>&1; then
  skip "no systemd user session; nothing is scheduled (see install/install.sh --help)"
else
  for unit in airlock-daemon.service airlock-health.timer airlock-tune.timer airlock-filesearch.timer; do
    if systemctl --user list-unit-files "$unit" 2>/dev/null | grep -q "$unit"; then
      state="$(systemctl --user is-active "$unit" 2>/dev/null)"
      enabled="$(systemctl --user is-enabled "$unit" 2>/dev/null)"
      case "$state" in
        active|activating) pass "$unit: $state, $enabled" ;;
        *) fail "$unit installed but $state ($enabled)" ;;
      esac
    else
      skip "$unit not installed"
    fi
  done
fi

# ---------------------------------------------------------------------------
head_ "Tuning"
if [ -f "$LIVE/tuning/tune.sh" ]; then
  # shellcheck disable=SC1091
  . "$REPO_ROOT/install/repo-path.sh"

  # The judge binary, resolved by tune.py itself so doctor cannot disagree
  # with the run. This check is a FAIL, not a skip: a missing `claude` is how
  # tuning ran twelve times and changed nothing, exiting 0 every time because
  # tuning is designed to be optional. Silent is exactly what it must not be.
  TUNE_CONFIG_DIR_D="${AIRLOCK_CONFIG_DIR:-$HOME/.config/airlock}"
  if [ -f "$TUNE_CONFIG_DIR_D/tune.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "$TUNE_CONFIG_DIR_D/tune.env"
    set +a
    pass "tune.env present at $TUNE_CONFIG_DIR_D/tune.env"
  else
    skip "no $TUNE_CONFIG_DIR_D/tune.env (written by install/install.sh --tuning); relying on PATH and the usual per-user locations"
  fi
  if JUDGE_BIN_D="$("$PY" "$LIVE/tuning/tune.py" --print-judge-bin 2>/dev/null)" && [ -n "$JUDGE_BIN_D" ]; then
    pass "judge binary: $JUDGE_BIN_D (model ${AIRLOCK_TUNE_JUDGE_MODEL:-opus}, effort ${AIRLOCK_TUNE_JUDGE_EFFORT:-high}, account ${AIRLOCK_TUNE_CLAUDE_CONFIG_DIR:-${CLAUDE_CONFIG_DIR:-$HOME/.claude}})"
  else
    fail "no judge binary resolves: tuning is installed but every run will record \"judge binary not found\" and change nothing. Set AIRLOCK_TUNE_CLAUDE_BIN in $TUNE_CONFIG_DIR_D/tune.env, or re-run install/install.sh --tuning from a shell where \`command -v claude\` works."
    "$PY" "$LIVE/tuning/tune.py" --print-judge-bin 2>&1 | sed 's/^/        /' || true
  fi

  # What the last run actually did, and how long ago. One line, so "is tuning
  # alive?" does not need the jsonl read by hand.
  TUNE_LOG_D="${AIRLOCK_TUNE_STATE_DIR:-${AIRLOCK_STATE_DIR:-$HOME/.local/state/airlock}}/tune_log.jsonl"
  if [ -s "$TUNE_LOG_D" ]; then
    LAST_RUN_D="$("$PY" - "$TUNE_LOG_D" <<'PYDOC' 2>/dev/null || true
import json, sys, time, calendar
last = None
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    try:
        last = json.loads(line)
    except Exception:
        continue
if not last:
    sys.exit(1)
category = last.get("category") or ("ran_committed" if last.get("committed") else "unknown (pre-category log row)")
ts = last.get("ts") or ""
age = ""
try:
    age_s = time.time() - calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
    age = ", %.1f h ago" % (age_s / 3600.0)
except Exception:
    pass
print("%s%s -- %s" % (category, age, last.get("reason", "")))
PYDOC
)"
    if [ -n "$LAST_RUN_D" ]; then
      case "$LAST_RUN_D" in
        could_not_run*) fail "last tuning run: $LAST_RUN_D" ;;
        *) pass "last tuning run: $LAST_RUN_D" ;;
      esac
    else
      skip "tune log at $TUNE_LOG_D has no readable rows yet"
    fi
  else
    skip "no tuning runs recorded yet at $TUNE_LOG_D"
  fi

  if TUNE_REPO="$(airlock_tune_repo "$LIVE/tuning")"; then
    pass "tuning repo resolved: $TUNE_REPO"
    STATE_DIR_D="${AIRLOCK_TUNE_STATE_DIR:-$HOME/.local/state/airlock}"
    WORKTREE_DIR_D="${AIRLOCK_TUNE_WORKTREE_DIR:-$STATE_DIR_D/tune-worktree}"
    if [ ! -e "$WORKTREE_DIR_D" ]; then
      skip "no tune-worktree yet at $WORKTREE_DIR_D (created on first tuning run)"
    elif [ ! -e "$WORKTREE_DIR_D/.git" ]; then
      fail "$WORKTREE_DIR_D exists but is not a git worktree"
    else
      WT_MAIN="$(git -C "$WORKTREE_DIR_D" worktree list --porcelain 2>/dev/null | awk '/^worktree /{print $2; exit}')"
      if [ -n "$WT_MAIN" ] && [ "$(cd "$WT_MAIN" 2>/dev/null && pwd)" = "$(cd "$TUNE_REPO" && pwd)" ]; then
        pass "tune-worktree at $WORKTREE_DIR_D matches the resolved repo"
      else
        fail "tune-worktree at $WORKTREE_DIR_D belongs to $WT_MAIN, not the resolved repo $TUNE_REPO (retired automatically on the next tuning run)"
      fi
    fi
  else
    skip "no repository resolved for tuning (no AIRLOCK_TUNE_REPO, no repo.path pointer, deployed release has no .git); tuning exits 0 without running"
  fi
else
  skip "tuning not installed"
fi

# ---------------------------------------------------------------------------
head_ "Optional components"
REVIEW_DIR="${AIRLOCK_REVIEW_DIR:-$HOME/code/jev-review}"
if [ -d "$REVIEW_DIR/.git" ]; then
  pass "review: clone at $REVIEW_DIR ($(git -C "$REVIEW_DIR" rev-parse --short HEAD 2>/dev/null))"
else
  skip "review: not installed"
fi
# browse: run the server through a real MCP handshake over stdio. It needs the
# vendored agent, so without one it is a skip and not a failure. No call is
# made, and JEV_BROWSE_PREWARM=0 says so explicitly even though off is already
# the default, so no Chromium starts and no key is read.
BROWSE_SERVER="$LIVE/browse/server.py"
BROWSE_DIR="${JEV_ULTRAFAST_DIR:-${AIRLOCK_BROWSER_DIR:-$LIVE/vendor/jev-ultrafast}}"
BROWSE_VENV="${JEV_ULTRAFAST_VENV:-${AIRLOCK_HOME:-$HOME/.local/share/airlock}/jev-ultrafast-venv}"
if [ ! -f "$BROWSE_SERVER" ]; then
  skip "browse: not present in the live copy"
elif [ ! -f "$BROWSE_DIR/jev_ultrafast/agent.py" ]; then
  skip "browse: no vendored jev-ultrafast at $BROWSE_DIR"
elif [ ! -x "$BROWSE_VENV/bin/python" ] && ! command -v uv >/dev/null 2>&1; then
  skip "browse: no environment at $BROWSE_VENV and no uv (browser/install.sh)"
else
  BROWSE_OUT="$(printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"doctor","version":"0"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
    | JEV_BROWSE_PREWARM=0 timeout 30 "$PY" "$BROWSE_SERVER" 2>/dev/null)"
  if printf '%s' "$BROWSE_OUT" | grep -q '"serverInfo"' \
     && printf '%s' "$BROWSE_OUT" | grep -q '"name": "browse"'; then
    pass "browse: server answered initialize and tools/list over stdio (tool: browse)"
  else
    fail "browse: $BROWSE_SERVER did not answer the MCP handshake"
  fi
fi

if [ -f "$LIVE/shim/shim.py" ]; then
  if "$PY" -c "import ast,sys; ast.parse(open('$LIVE/shim/shim.py').read())" 2>/dev/null; then
    pass "shim: shim.py parses (stdlib-only; nothing to install)"
  else
    fail "shim: shim.py does not parse"
  fi
else
  skip "shim: not present in the live copy"
fi

if [ -x "$HOME/bin/claude-auto-update" ]; then
  if systemctl --user list-unit-files claude-auto-update.timer >/dev/null 2>&1 \
     && systemctl --user list-unit-files claude-auto-update.timer 2>/dev/null | grep -q claude-auto-update.timer; then
    state="$(systemctl --user is-active claude-auto-update.timer 2>/dev/null)"
    pass "claude-update: $HOME/bin/claude-auto-update, timer $state"
  else
    pass "claude-update: $HOME/bin/claude-auto-update (no systemd timer; check cron)"
  fi
else
  skip "claude-update: not installed"
fi

BELAY_HOME="${AIRLOCK_BELAY_DIR:-$HOME/.local/share/jev-belay}"
if [ -x "$HOME/bin/airlock-belay-run" ] && [ -e "$BELAY_HOME/current" ]; then
  pass "belay: wrapper at $HOME/bin/airlock-belay-run, current -> $(readlink -f "$BELAY_HOME/current" 2>/dev/null)"
else
  skip "belay: not installed"
fi

if command -v claude >/dev/null 2>&1 && claude plugin list 2>/dev/null | grep -q 'fast-jev-compaction'; then
  pass "compaction: fast-jev-compaction plugin installed (remember: unredacted, ~25k tokens/request)"
else
  skip "compaction: not installed"
fi

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed, %d skipped\n' "$PASSED" "$FAILED" "$SKIPPED"
[ "$FAILED" -eq 0 ] || exit 1
exit 0
