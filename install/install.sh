#!/usr/bin/env bash
# airlock: one entry point to install this repository onto a machine.
#
#   install/install.sh                       # guard + daemon + monitoring + filesearch
#   install/install.sh --all                 # everything
#   install/install.sh --guard --tuning      # just those two
#   install/install.sh --wire ~/.claude/settings.json
#
# What it does NOT do unless you ask:
#   - it never edits a settings.json without --wire (it prints the edit
#     instead, via install/wire.sh --print)
#   - it never installs the components that send more off the machine, or that
#     need a system package or a second toolchain, by default: browser,
#     review, shim, tuning and compaction are all opt-in
#   - the DEFAULT set is: guard, session-check, daemon, monitoring, filesearch,
#     claude-update, belay. `--belay` clones a pinned third-party repository (jev-belay), so a
#     default run does reach the network; use explicit component flags to avoid
#     that
#   - it never runs sudo, and never writes outside $HOME
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Machine-specific values live in install/config.env (gitignored). Nothing in
# this repository hard-codes a home directory or an account name.
if [ -f "$SCRIPT_DIR/config.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$SCRIPT_DIR/config.env"
  set +a
  CONFIG_SOURCED="$SCRIPT_DIR/config.env"
else
  CONFIG_SOURCED=""
fi

AIRLOCK_HOME="${AIRLOCK_HOME:-${PLUMBLINE_HOME:-${JEV_HOME:-$HOME/.local/share/airlock}}}"
UNIT_DIR="$HOME/.config/systemd/user"

usage() {
  cat <<EOF
airlock installer

usage: $0 [components] [options]

Components (default: --guard --session-check --daemon --monitoring
            --filesearch --claude-update --belay):
  --guard        the PreToolUse guard itself: deploy a release, create the
                 config directory, print the settings.json edit
  --session-check  the SessionStart check that tells YOU, at the moment you
                 start a session, when the guard is not judging anything.
                 On by default; --no-session-check leaves it out
  --no-session-check  do not register the SessionStart entry
  --daemon       the warm-connection daemon (systemd user unit)
  --tuning       the unattended tuning timer
  --monitoring   the five-minute health check timer
  --filesearch   the per-user plocate index and its hourly timer
  --browser      sync the vendored browser-use/jev-ultrafast environment
  --browse-mcp   check the 'browse' MCP server over that clone and print
                 (never apply) the mcpServers block for ~/.claude.json
  --review       clone devagrawal09/jev-review at a pin (needs Node 24)
  --shim         the OpenAI-shaped shim over the claude CLI
  --claude-update  the idle-only Claude Code auto-updater and its timer
  --belay        clone valentynkit/jev-belay at a pin, install the wrapper,
                 and print (never apply) the Stop-hook settings.json block
  --compaction   tamaratran/fast-jev-compaction -- reads compaction/README.md
                 first: it sends far more off the machine than anything else
                 here
  --all          every component above

Options:
  --wire <settings.json> [...]  actually apply the hook edit to those files
                                (each is backed up first). Without this, the
                                edit is only printed.
  --headless     treat this machine as headless: turn rule R6 (opening a GUI
                 or a browser) on in rules.json. Detected automatically on a
                 Linux box with no display; this forces it
  --no-headless  never touch R6, whatever the detection says
  --no-systemd   skip every timer and unit; the hook still works, and the
                 client falls back to a direct HTTPS call with no daemon
  --check-only   check prerequisites and print the plan, install nothing
  -h, --help     this

On WSL without systemd, --no-systemd is selected automatically and the script
prints how to turn systemd on if you want the timers.
EOF
  exit "${1:-0}"
}

# --- argument parsing -------------------------------------------------------
WANT_GUARD=0; WANT_DAEMON=0; WANT_TUNING=0; WANT_MONITORING=0
WANT_FILESEARCH=0; WANT_BROWSER=0; WANT_REVIEW=0; WANT_SHIM=0
WANT_CLAUDE_UPDATE=0; WANT_BELAY=0; WANT_COMPACTION=0
WANT_BROWSE_MCP=0
# The session check rides with the guard: it is part of the DEFAULT set on
# every platform and is not one of the flags that makes the default set go
# away, because a guard installed without it is a guard whose death is silent.
WANT_SESSION_CHECK=1
ANY_COMPONENT=0
# Whether filesearch was asked for BY NAME. A missing `plocate` is a hard
# failure only then: aborting a whole default install over one optional
# component would leave a cold agent with nothing at all installed.
FILESEARCH_EXPLICIT=0
NO_SYSTEMD=0
CHECK_ONLY=0
# R6 (GUI/browser) is off by default on every platform. "auto" means detect;
# "yes"/"no" are --headless / --no-headless and skip detection entirely.
HEADLESS_CHOICE=auto
WIRE_FILES=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --guard) WANT_GUARD=1; ANY_COMPONENT=1; shift ;;
    --daemon) WANT_DAEMON=1; ANY_COMPONENT=1; shift ;;
    --tuning) WANT_TUNING=1; ANY_COMPONENT=1; shift ;;
    --monitoring) WANT_MONITORING=1; ANY_COMPONENT=1; shift ;;
    --filesearch) WANT_FILESEARCH=1; FILESEARCH_EXPLICIT=1; ANY_COMPONENT=1; shift ;;
    --browser) WANT_BROWSER=1; ANY_COMPONENT=1; shift ;;
    --browse-mcp) WANT_BROWSE_MCP=1; ANY_COMPONENT=1; shift ;;
    --review) WANT_REVIEW=1; ANY_COMPONENT=1; shift ;;
    --shim) WANT_SHIM=1; ANY_COMPONENT=1; shift ;;
    --claude-update) WANT_CLAUDE_UPDATE=1; ANY_COMPONENT=1; shift ;;
    --belay) WANT_BELAY=1; ANY_COMPONENT=1; shift ;;
    --compaction) WANT_COMPACTION=1; ANY_COMPONENT=1; shift ;;
    --session-check) WANT_SESSION_CHECK=1; shift ;;
    --no-session-check) WANT_SESSION_CHECK=0; shift ;;
    --all)
      WANT_GUARD=1; WANT_DAEMON=1; WANT_TUNING=1; WANT_MONITORING=1
      WANT_FILESEARCH=1; WANT_BROWSER=1; WANT_REVIEW=1; WANT_SHIM=1
      WANT_CLAUDE_UPDATE=1; WANT_BELAY=1; WANT_COMPACTION=1
      WANT_BROWSE_MCP=1
      FILESEARCH_EXPLICIT=1; ANY_COMPONENT=1; shift ;;
    --headless) HEADLESS_CHOICE=yes; shift ;;
    --no-headless) HEADLESS_CHOICE=no; shift ;;
    --no-systemd) NO_SYSTEMD=1; shift ;;
    --check-only) CHECK_ONLY=1; shift ;;
    --wire)
      shift
      while [ "$#" -gt 0 ] && [ "${1#--}" = "$1" ]; do
        WIRE_FILES+=("$1"); shift
      done
      [ "${#WIRE_FILES[@]}" -gt 0 ] || { echo "--wire needs at least one settings.json path" >&2; exit 2; }
      ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 2 ;;
  esac
done

if [ "$ANY_COMPONENT" = "0" ]; then
  WANT_GUARD=1; WANT_DAEMON=1; WANT_MONITORING=1; WANT_FILESEARCH=1
  WANT_CLAUDE_UPDATE=1; WANT_BELAY=1
fi

# --- output helpers ---------------------------------------------------------
PROBLEMS=0
step()  { printf '\n== %s\n' "$*"; }
ok()    { printf '   ok    %s\n' "$*"; }
warn()  { printf '   warn  %s\n' "$*"; }
fail()  { printf '   FAIL  %s\n' "$*"; PROBLEMS=$((PROBLEMS + 1)); }

# --- prerequisites ----------------------------------------------------------
step "Prerequisites"

if [ -n "$CONFIG_SOURCED" ]; then
  ok "config: $CONFIG_SOURCED"
else
  warn "no install/config.env (copy install/config.env.example if this machine needs one)"
fi

PY=""
for candidate in python3 python3.14 python3.13 python3.12 python3.11 python3.10; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
      PY="$(command -v "$candidate")"
      break
    fi
  fi
done
if [ -n "$PY" ]; then
  ok "python3 $("$PY" -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])') at $PY"
else
  fail "python3 >= 3.10 not found; the guard is pure stdlib Python and needs it"
fi

# systemd user session
SYSTEMD_OK=0
: "${XDG_RUNTIME_DIR:=/run/user/$(id -u)}"
export XDG_RUNTIME_DIR
if [ "$NO_SYSTEMD" = "1" ]; then
  warn "systemd: skipped (--no-systemd)"
elif command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
  SYSTEMD_OK=1
  ok "systemd user session reachable (XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR)"
else
  NO_SYSTEMD=1
  warn "no systemd user session; degrading to no-systemd mode"
  if grep -qi microsoft /proc/version 2>/dev/null; then
    cat <<'EOF'

   This looks like WSL. WSL does not run systemd unless you turn it on.
   To get the daemon and the timers, add this to /etc/wsl.conf INSIDE the
   distribution, then shut the distribution down from Windows and start it
   again:

       [boot]
       systemd=true

   Then, from Windows:   wsl --shutdown

   Without systemd, airlock still works, with three differences:
     - no warm daemon, so airlock/client.py makes a direct HTTPS call per
       judgement (roughly 0.9s instead of 0.3s; the enforce-mode budget
       still applies and it still fails open)
     - no health-check timer and no tuning timer; run
       monitoring/run_health_check.sh and tuning/tune.sh by hand or from cron
     - no hourly plocate refresh; rebuild the index with
       filesearch/install.sh --no-systemd

EOF
  fi
fi

if command -v plocate >/dev/null 2>&1 && command -v updatedb >/dev/null 2>&1; then
  ok "plocate present"
elif [ "$FILESEARCH_EXPLICIT" = "1" ]; then
  fail "plocate not installed (sudo apt install plocate) -- needed for --filesearch"
elif [ "$WANT_FILESEARCH" = "1" ]; then
  # Part of the DEFAULT set, not asked for by name. Drop it and carry on: the
  # guard, the daemon and the rest are what a first install is actually for.
  WANT_FILESEARCH=0
  warn "plocate not installed; skipping filesearch (install it and re-run with"
  warn "  --filesearch to add the index later: sudo apt install plocate)"
else
  warn "plocate not installed (only needed for --filesearch)"
fi

if command -v node >/dev/null 2>&1; then
  ok "node $(node --version)"
else
  if [ "$WANT_REVIEW" = "1" ] || [ "$WANT_BROWSER" = "1" ]; then
    fail "node not found -- needed for --review and for --browser's Chromium launcher"
  else
    warn "node not found (only needed for --browser and --review)"
  fi
fi

if command -v uv >/dev/null 2>&1; then
  ok "uv $(uv --version 2>/dev/null | head -1)"
else
  if [ "$WANT_BROWSER" = "1" ]; then
    warn "uv not found; --browser cannot sync the browser agent's dependencies"
  else
    warn "uv not found (only needed for --browser)"
  fi
fi

if command -v git >/dev/null 2>&1; then
  ok "git $(git --version | awk '{print $3}')"
else
  fail "git not found"
fi

# The key: checked for presence only. Its value is never read, printed or
# logged here.
# Key-file resolution: the ONE shell implementation, shared with every other
# component here. The order and the pointer-file trust rules are documented in
# airlock/keyfile.py's module docstring. Fails open if the helper is missing.
if [ -r "$SCRIPT_DIR/keyfile.sh" ]; then
  . "$SCRIPT_DIR/keyfile.sh"
else
  airlock_key_file() {
    local f="${AIRLOCK_KEY_FILE:-${JEVKIT_KEY_FILE:-}}"
    if [ -n "$f" ]; then printf '%s\n' "$f"; return 0; fi
    [ -r "$HOME/.config/jev-kit/env" ] && { printf '%s\n' "$HOME/.config/jev-kit/env"; return 0; }
    [ -r "$HOME/.config/airlock/env" ] && { printf '%s\n' "$HOME/.config/airlock/env"; return 0; }
    printf '%s\n' "$HOME/.config/jev-kit/env"
  }
  airlock_keyfile_is_default() {
    case "$1" in
      "$HOME/.config/jev-kit/env"|"$HOME/.config/airlock/env") return 0 ;;
      *) return 1 ;;
    esac
  }
fi
KEY_FILE_EXPANDED="$(airlock_key_file)"
KEY_FILE="$KEY_FILE_EXPANDED"
if [ -n "${TYPESAFE_API_KEY:-}" ]; then
  ok "TYPESAFE_API_KEY is set in this environment"
elif [ -r "$KEY_FILE_EXPANDED" ] && grep -q '^ *\(export \)\?TYPESAFE_API_KEY=' "$KEY_FILE_EXPANDED" 2>/dev/null; then
  ok "key file $KEY_FILE_EXPANDED contains a TYPESAFE_API_KEY line"
else
  warn "no TYPESAFE_API_KEY found (env, or $KEY_FILE_EXPANDED)."
  warn "  every component in the kit reads this one key. Create it with:"
  warn "    mkdir -p ~/.config/jev-kit && touch ~/.config/jev-kit/env"
  warn "    chmod 700 ~/.config/jev-kit && chmod 600 ~/.config/jev-kit/env"
  warn "  then put one TYPESAFE_API_KEY= line in it. Never print the value."
  warn "  the guard still installs and still fails open; it just judges nothing."
fi

if [ "$PROBLEMS" -gt 0 ]; then
  echo
  echo "$PROBLEMS prerequisite problem(s). Nothing was installed." >&2
  exit 1
fi

# --- plan -------------------------------------------------------------------
step "Plan"
plan() { [ "$1" = "1" ] && echo "   install  $2" || true; }
plan "$WANT_GUARD" "guard"
plan "$WANT_SESSION_CHECK" "session-check (SessionStart hook)"
plan "$WANT_DAEMON" "daemon"
plan "$WANT_TUNING" "tuning"
plan "$WANT_MONITORING" "monitoring"
plan "$WANT_FILESEARCH" "filesearch"
plan "$WANT_BROWSER" "browser"
plan "$WANT_BROWSE_MCP" "browse-mcp (prints the mcpServers block, applies nothing)"
plan "$WANT_REVIEW" "review"
plan "$WANT_SHIM" "shim"
plan "$WANT_CLAUDE_UPDATE" "claude-update"
plan "$WANT_BELAY" "belay"
plan "$WANT_COMPACTION" "compaction"
echo "   AIRLOCK_HOME=$AIRLOCK_HOME"
echo "   systemd: $([ "$NO_SYSTEMD" = "1" ] && echo "no (timers and units skipped)" || echo yes)"

if [ "$CHECK_ONLY" = "1" ]; then
  echo
  echo "--check-only: nothing installed."
  exit 0
fi

# --- helpers ----------------------------------------------------------------
install_unit() {
  local src="$1" name="$2"
  mkdir -p "$UNIT_DIR"
  install -m 644 "$src" "$UNIT_DIR/$name"
  ok "unit $name -> $UNIT_DIR"
}

enable_unit() {
  local name="$1"
  if [ "$NO_SYSTEMD" = "1" ]; then
    warn "not enabling $name (no systemd)"
    return 0
  fi
  systemctl --user daemon-reload
  if systemctl --user enable --now "$name" >/dev/null 2>&1; then
    ok "enabled $name"
  else
    warn "could not enable $name; try: systemctl --user enable --now $name"
  fi
}

# --- guard ------------------------------------------------------------------
if [ "$WANT_GUARD" = "1" ]; then
  step "Guard"

  if [ -d "$HOME/.config/jev-guard" ] || [ -d "$HOME/.local/state/jev-guard" ]; then
    warn "this machine still has jev-guard directories."
    warn "  airlock reads them as-is for now (see airlock/paths.py)."
    warn "  To rename them:  install/migrate-from-jev-guard.sh --dry-run"
  fi

  CONFIG_DIR="$("$PY" -c "import sys;sys.path.insert(0,'$REPO_ROOT');from airlock import paths;print(paths.config_dir())")"
  STATE_DIR="$("$PY" -c "import sys;sys.path.insert(0,'$REPO_ROOT');from airlock import paths;print(paths.state_dir())")"
  mkdir -p "$CONFIG_DIR" "$STATE_DIR"
  chmod 700 "$STATE_DIR" 2>/dev/null || true
  # 700 on the config dir is not tidiness: airlock/keyfile.py REFUSES to follow
  # the pointer file below out of a group- or world-writable directory, because
  # anyone who can write that directory chooses which file the hook parses for a
  # secret. A machine with umask 002 creates 775 dirs by default, so say it.
  chmod 700 "$CONFIG_DIR" 2>/dev/null || true
  ok "config dir $CONFIG_DIR (mode 700)"
  ok "state dir  $STATE_DIR (mode 700)"

  # Record WHERE the key file is, never what is in it. A Claude Code hook runs
  # with a minimal environment and never sources install/config.env, so a
  # machine that keeps its key anywhere other than the default needs the path
  # persisted somewhere airlock/keyfile.py can read it. This is that file.
  # It holds a path and nothing else; `install/config.env` remains the only
  # place a human edits.
  # The pointer is only ever followed when it names an ABSOLUTE path, so refuse
  # to write anything else rather than leave a pointer that silently does
  # nothing (see airlock/keyfile.py for the full list of trust checks).
  # Both defaults -- the kit's ~/.config/jev-kit/env and the guard-era
  # ~/.config/airlock/env -- are found by resolution on their own, so neither
  # needs a pointer.
  POINTER_TARGET="$KEY_FILE_EXPANDED"
  if ! airlock_keyfile_is_default "$POINTER_TARGET"; then
    case "$POINTER_TARGET" in
      /*) ;;
      *) fail "key-file path '$POINTER_TARGET' is not absolute; not recording a pointer"
         POINTER_TARGET="$HOME/.config/jev-kit/env" ;;
    esac
  fi
  if ! airlock_keyfile_is_default "$POINTER_TARGET"; then
    ( umask 077; printf '%s\n' "$POINTER_TARGET" > "$CONFIG_DIR/keyfile.path" )
    chmod 600 "$CONFIG_DIR/keyfile.path" 2>/dev/null || true
    ok "recorded key-file path in $CONFIG_DIR/keyfile.path (path only, no value)"
    if [ ! -e "$POINTER_TARGET" ]; then
      warn "  $POINTER_TARGET does not exist yet; until it does the pointer is"
      warn "  ignored and the guard judges nothing (it still fails open)."
    fi
  elif [ -f "$CONFIG_DIR/keyfile.path" ]; then
    rm -f "$CONFIG_DIR/keyfile.path"
    ok "removed $CONFIG_DIR/keyfile.path (a default path is in use)"
  fi

  # --- R6: is this a headless machine? -------------------------------------
  # R6 blocks xdg-open, wslview, explorer.exe and the browser binaries. It
  # ships OFF on every platform, because most people run Claude Code where
  # there IS a desktop. A machine with no display wants it on, and this is the
  # first-class way to say so: one entry merged into rules.json, the existing
  # file backed up first, and an explicit R6 value in it NEVER overwritten.
  # Detection is conservative on purpose (see airlock/headless.py): a false
  # "headless" arms a rule against something the user can legitimately do,
  # while a false "desktop" just leaves the shipped default in place.
  RULES_JSON="$CONFIG_DIR/rules.json"
  case "$HEADLESS_CHOICE" in
    no)
      ok "R6 (GUI/browser): left off (--no-headless)" ;;
    yes|auto)
      HEADLESS=0
      HEADLESS_WHY=""
      if [ "$HEADLESS_CHOICE" = "yes" ]; then
        HEADLESS=1
        HEADLESS_WHY="--headless was given"
      else
        if HEADLESS_WHY="$(cd "$REPO_ROOT" && "$PY" -m airlock.headless detect 2>/dev/null)"; then
          HEADLESS=1
        else
          HEADLESS=0
        fi
      fi
      if [ "$HEADLESS" = "1" ]; then
        MERGE_OUT="$(cd "$REPO_ROOT" && "$PY" -m airlock.headless merge "$RULES_JSON" 2>&1)"
        MERGE_STATUS="${MERGE_OUT%%	*}"
        MERGE_DETAIL="${MERGE_OUT#*	}"
        case "$MERGE_STATUS" in
          written)
            ok "R6 (GUI/browser) turned ON: headless machine, so {\"R6-gui-or-browser\": \"deny\"} was merged into $RULES_JSON (${HEADLESS_WHY}${MERGE_DETAIL:+; backup $MERGE_DETAIL})" ;;
          already)
            ok "R6 (GUI/browser): $MERGE_DETAIL -- your value wins, nothing written" ;;
          *)
            warn "R6 (GUI/browser): headless detected but rules.json was not written: $MERGE_DETAIL"
            warn "  turn it on by hand with:  (cd $REPO_ROOT && $PY -m airlock.headless merge \"$RULES_JSON\")" ;;
        esac
      else
        ok "R6 (GUI/browser): left off -- ${HEADLESS_WHY:-this machine looks like it has a desktop}"
        printf '         turn it on later with:  (cd %s && %s -m airlock.headless merge "%s")\n' \
          "$REPO_ROOT" "$PY" "$RULES_JSON"
      fi ;;
  esac

  # --- R11: a Playwright MCP call is pointed at the browse tool -------------
  # On by default, on every platform, and it needs no entry in rules.json to
  # be on. The line is printed because a rule that blocks a Playwright MCP
  # call should not be a surprise, and because the off switch should be on
  # screen next to it.
  ok "R11 (browse via Jev): ON by default -- a Playwright MCP browsing call is denied and pointed at the 'browse' tool (--browse-mcp); shell commands are never touched"
  printf '         turn it off with:  {"R11-browse-via-jev": "off"} in %s\n' "$CONFIG_DIR/rules.json"

  if [ ! -f "$CONFIG_DIR/mode" ]; then
    echo "shadow" > "$CONFIG_DIR/mode"
    ok "mode set to shadow (log only). Change it with: echo enforce > $CONFIG_DIR/mode"
  else
    ok "mode left as '$(head -1 "$CONFIG_DIR/mode" | awk '{print $1}')' (not overwritten)"
  fi

  echo "   running the unit tests before deploying..."
  # A clean environment and a throwaway HOME: this machine's own config.env
  # (sourced above) and its rules.json must not leak into the suite.
  TEST_HOME="$(mktemp -d)"
  if ( cd "$REPO_ROOT" && env -i PATH="$PATH" HOME="$TEST_HOME" "$PY" -m unittest discover -s tests >/dev/null 2>&1 ); then
    rm -rf "$TEST_HOME"
    ok "unit tests pass"
  else
    rm -rf "$TEST_HOME"
    fail "unit tests fail in this checkout; refusing to deploy it"
    exit 1
  fi

  if AIRLOCK_HOME="$AIRLOCK_HOME" JEV_HOME="$AIRLOCK_HOME" "$SCRIPT_DIR/deploy.sh" >/dev/null 2>&1; then
    ok "deployed: $AIRLOCK_HOME/current -> $(readlink -f "$AIRLOCK_HOME/current" 2>/dev/null)"
  else
    warn "deploy.sh did not complete (it needs a committed 'main' in the main checkout)."
    warn "  falling back to pointing 'current' at this checkout, which is fine for a"
    warn "  first install but means a git operation here changes what is live."
    mkdir -p "$AIRLOCK_HOME"
    ln -sfn "$REPO_ROOT" "$AIRLOCK_HOME/.current.tmp.$$"
    mv -T "$AIRLOCK_HOME/.current.tmp.$$" "$AIRLOCK_HOME/current"
    ok "current -> $REPO_ROOT"
  fi

  HOOK="$AIRLOCK_HOME/current/hooks/airlock.py"
  SESSION_CHECK_HOOK="$AIRLOCK_HOME/current/hooks/airlock_session_check.py"
  BROWSE_UNLOCK_HOOK="$AIRLOCK_HOME/current/hooks/airlock_browse_unlock.py"
  echo
  echo "   The settings.json edit. Register this ONE entry, matcher \"*\" -- the"
  echo "   rules table filters in code, far more cheaply than a regex matcher:"
  echo
  cat <<EOF
     {
       "hooks": {
         "PreToolUse": [
           {
             "matcher": "*",
             "hooks": [
               { "type": "command",
                 "command": "$PY $HOOK",
                 "timeout": 5 }
             ]
           }
         ]
       }
     }
EOF
  echo
  if [ "$WANT_SESSION_CHECK" = "1" ]; then
    echo "   And the SessionStart entry. The guard fails open, so a dead guard is"
    echo "   silent; this is what tells YOU, at the moment you start a session."
    echo "   It prints nothing at all when everything is healthy:"
    echo
    cat <<EOF
     {
       "hooks": {
         "SessionStart": [
           {
             "matcher": "*",
             "hooks": [
               { "type": "command",
                 "command": "$PY $SESSION_CHECK_HOOK",
                 "timeout": 5 }
             ]
           }
         ]
       }
     }
EOF
    echo
  fi
  echo "   And the browse-unlock entries, the only way past R11. When the kit's"
  echo "   own \`browse\` tool gives up on a goal, this records it and R11 warns"
  echo "   instead of blocking for the next 30 minutes of that session. It goes"
  echo "   under PostToolUse AND PostToolUseFailure, because a \`browse\` call"
  echo "   that errors only ever reaches the second. They are the entries with a"
  echo "   real matcher, because they have one tool to watch:"
  echo
  cat <<EOF
     {
       "hooks": {
         "PostToolUse": [
           {
             "matcher": "mcp__browse__browse",
             "hooks": [
               { "type": "command",
                 "command": "$PY $BROWSE_UNLOCK_HOOK",
                 "timeout": 5 }
             ]
           }
         ],
         "PostToolUseFailure": [
           {
             "matcher": "mcp__browse__browse",
             "hooks": [
               { "type": "command",
                 "command": "$PY $BROWSE_UNLOCK_HOOK",
                 "timeout": 5 }
             ]
           }
         ]
       }
     }
EOF
  echo
  if [ "${#WIRE_FILES[@]}" -gt 0 ]; then
    echo "   --wire given; applying to ${#WIRE_FILES[@]} file(s) (each backed up first):"
    WIRE_EXTRA_FLAGS=()
    [ "$WANT_BELAY" = "1" ] && WIRE_EXTRA_FLAGS+=("--belay")
    [ "$WANT_SESSION_CHECK" = "1" ] || WIRE_EXTRA_FLAGS+=("--no-session-check")
    AIRLOCK_HOME="$AIRLOCK_HOME" JEV_HOME="$AIRLOCK_HOME" AIRLOCK_PYTHON3="$PY" \
      "$SCRIPT_DIR/wire.sh" --apply "${WIRE_EXTRA_FLAGS[@]}" "${WIRE_FILES[@]}"
  else
    echo "   No --wire given, so no settings.json was touched. To preview an edit"
    echo "   to an existing entry:"
    echo "       install/wire.sh --print <settings.json> [...]"
    echo "   and to apply it:"
    echo "       install/install.sh --guard --wire <settings.json> [...]"
  fi
fi

# --- daemon -----------------------------------------------------------------
if [ "$WANT_DAEMON" = "1" ]; then
  step "Daemon"
  if [ "$NO_SYSTEMD" = "1" ]; then
    warn "skipped: no systemd."
    warn "  airlock/client.py falls back to a direct HTTPS call automatically,"
    warn "  so every judgement still works -- it just costs ~0.9s instead of ~0.3s."
  else
    install_unit "$REPO_ROOT/deploy/airlock-daemon.service" "airlock-daemon.service"
    enable_unit "airlock-daemon.service"
  fi
fi

# --- tuning -----------------------------------------------------------------
if [ "$WANT_TUNING" = "1" ]; then
  step "Tuning"
  # The unit runs the DEPLOYED release ($AIRLOCK_HOME/current/tuning/tune.sh),
  # an exported tree with no .git of its own -- it cannot derive "the repo"
  # from its own location. Record the checkout install.sh was just run from
  # (this one, $REPO_ROOT) so tune.py/tune.sh/promote.sh can resolve it via
  # the repo.path pointer. Same trust checks as keyfile.path (see
  # airlock/repo_path.py): the pointer file and its directory are ours alone,
  # and the recorded path is absolute and an existing checkout.
  TUNING_CONFIG_DIR="$("$PY" -c "import sys;sys.path.insert(0,'$REPO_ROOT');from airlock import paths;print(paths.config_dir())")"
  mkdir -p "$TUNING_CONFIG_DIR"
  chmod 700 "$TUNING_CONFIG_DIR" 2>/dev/null || true
  if [ -e "$REPO_ROOT/.git" ]; then
    ( umask 077; printf '%s\n' "$REPO_ROOT" > "$TUNING_CONFIG_DIR/repo.path" )
    chmod 600 "$TUNING_CONFIG_DIR/repo.path" 2>/dev/null || true
    ok "recorded tuning repo path in $TUNING_CONFIG_DIR/repo.path -> $REPO_ROOT"
  else
    fail "$REPO_ROOT has no .git; not recording a repo.path pointer (tuning will find nothing to commit to)"
  fi
  # Resolve the judge binary NOW, from the installing shell's PATH, and
  # record the absolute path. A systemd user unit runs with a minimal PATH
  # that does not include an npm global prefix under $HOME, so `claude`
  # resolved by name works by hand and fails on the timer -- silently, since
  # the run exits 0 by design. tune.sh sources this file; it holds paths and
  # names only, never a key, and is written 600 regardless.
  TUNE_ENV="$TUNING_CONFIG_DIR/tune.env"
  TUNE_JUDGE_BIN="${AIRLOCK_TUNE_CLAUDE_BIN:-$(command -v claude 2>/dev/null || true)}"
  if [ -z "$TUNE_JUDGE_BIN" ]; then
    TUNE_JUDGE_BIN="$("$PY" "$REPO_ROOT/tuning/tune.py" --print-judge-bin 2>/dev/null || true)"
  fi
  {
    umask 077
    {
      printf '# Written by install/install.sh --tuning on %s.
' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf '# Sourced by tuning/tune.sh. Paths and names only -- never a key.
'
      if [ -n "$TUNE_JUDGE_BIN" ]; then
        printf 'AIRLOCK_TUNE_CLAUDE_BIN=%s
' "$TUNE_JUDGE_BIN"
      else
        printf '# No `claude` binary found at install time. Set one here:
'
        printf '#AIRLOCK_TUNE_CLAUDE_BIN=/absolute/path/to/claude
'
      fi
      printf '# Which Claude account tree the judge bills. Unset = ~/.claude.
'
      if [ -n "${AIRLOCK_TUNE_CLAUDE_CONFIG_DIR:-}" ]; then
        printf 'AIRLOCK_TUNE_CLAUDE_CONFIG_DIR=%s
' "$AIRLOCK_TUNE_CLAUDE_CONFIG_DIR"
      elif [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then
        printf 'AIRLOCK_TUNE_CLAUDE_CONFIG_DIR=%s
' "$CLAUDE_CONFIG_DIR"
      else
        printf '#AIRLOCK_TUNE_CLAUDE_CONFIG_DIR=$HOME/.claude
'
      fi
      printf '# Judge model and effort. Unset = opus / high.
'
      if [ -n "${AIRLOCK_TUNE_JUDGE_MODEL:-}" ]; then
        printf 'AIRLOCK_TUNE_JUDGE_MODEL=%s
' "$AIRLOCK_TUNE_JUDGE_MODEL"
      else
        printf '#AIRLOCK_TUNE_JUDGE_MODEL=opus
'
      fi
      if [ -n "${AIRLOCK_TUNE_JUDGE_EFFORT:-}" ]; then
        printf 'AIRLOCK_TUNE_JUDGE_EFFORT=%s
' "$AIRLOCK_TUNE_JUDGE_EFFORT"
      else
        printf '#AIRLOCK_TUNE_JUDGE_EFFORT=high
'
      fi
    } > "$TUNE_ENV"
  }
  chmod 600 "$TUNE_ENV" 2>/dev/null || true
  if [ -n "$TUNE_JUDGE_BIN" ]; then
    ok "judge binary resolved: $TUNE_JUDGE_BIN (recorded in $TUNE_ENV)"
  else
    fail "no \`claude\` binary found on PATH or in the usual per-user locations; tuning will record \"judge binary not found\" and change nothing until AIRLOCK_TUNE_CLAUDE_BIN is set in $TUNE_ENV"
  fi

  if [ "$NO_SYSTEMD" = "1" ]; then
    warn "skipped: no systemd. Run tuning/tune.sh by hand or from cron."
  else
    install_unit "$REPO_ROOT/tuning/airlock-tune.service" "airlock-tune.service"
    install_unit "$REPO_ROOT/tuning/airlock-tune.timer" "airlock-tune.timer"
    enable_unit "airlock-tune.timer"
    warn "auto-promotion stays OFF unless \$AIRLOCK_CONFIG_DIR/auto-promote exists."
  fi
fi

# --- monitoring -------------------------------------------------------------
if [ "$WANT_MONITORING" = "1" ]; then
  step "Monitoring"
  if [ "$NO_SYSTEMD" = "1" ]; then
    warn "skipped: no systemd. Run monitoring/run_health_check.sh by hand or from cron."
  else
    install_unit "$REPO_ROOT/monitoring/airlock-health.service" "airlock-health.service"
    install_unit "$REPO_ROOT/monitoring/airlock-health.timer" "airlock-health.timer"
    enable_unit "airlock-health.timer"
    if [ -z "${AIRLOCK_KUMA_PUSH_URL:-}" ] && [ -z "${GS_KUMA_AIRLOCK_PUSH_URL:-}" ] \
       && [ -z "${GS_KUMA_JEV_PUSH_URL:-}" ]; then
      warn "AIRLOCK_KUMA_PUSH_URL is not set, so nothing is pushed to Uptime Kuma."
      warn "  Create the push monitor, then put the URL in the key file (it is a"
      warn "  capability token, so it is treated as a secret). The health check"
      warn "  still runs and still writes health.jsonl without it."
    fi
  fi
fi

# --- filesearch -------------------------------------------------------------
if [ "$WANT_FILESEARCH" = "1" ]; then
  step "Filesearch"
  if [ "$NO_SYSTEMD" = "1" ]; then
    "$REPO_ROOT/filesearch/install.sh" --no-systemd || warn "filesearch/install.sh reported a problem"
  else
    "$REPO_ROOT/filesearch/install.sh" || warn "filesearch/install.sh reported a problem"
  fi
fi

# --- optional components ----------------------------------------------------
if [ "$WANT_BROWSER" = "1" ]; then
  step "Browser"
  "$REPO_ROOT/browser/install.sh" || warn "browser/install.sh reported a problem"
fi

# After --browser on purpose: the server drives the vendored agent that step
# builds an environment for.
if [ "$WANT_BROWSE_MCP" = "1" ]; then
  step "Browse MCP server"
  "$REPO_ROOT/browse/install.sh" || warn "browse/install.sh reported a problem"
fi

if [ "$WANT_REVIEW" = "1" ]; then
  step "Review"
  "$REPO_ROOT/review/install.sh" || warn "review/install.sh reported a problem"
fi

if [ "$WANT_SHIM" = "1" ]; then
  step "Shim"
  ok "shim/shim.py is stdlib-only Python; there is nothing to install."
  echo "   Run it in the foreground (or in tmux) when something needs it:"
  echo "       python3 $REPO_ROOT/shim/shim.py"
  echo "   See shim/README.md -- PageIndex local indexing works through it,"
  echo "   chat does not."
fi

if [ "$WANT_CLAUDE_UPDATE" = "1" ]; then
  step "claude-update"
  if [ "$NO_SYSTEMD" = "1" ]; then
    "$REPO_ROOT/claude-update/install.sh" --no-systemd || warn "claude-update/install.sh reported a problem"
  else
    "$REPO_ROOT/claude-update/install.sh" || warn "claude-update/install.sh reported a problem"
  fi
fi

if [ "$WANT_BELAY" = "1" ]; then
  step "Belay"
  "$REPO_ROOT/belay/install.sh" || warn "belay/install.sh reported a problem"
  # The guard step wired settings.json before the belay wrapper existed, so
  # _wire.py skipped the Stop hook then. Now that it is installed, wire again:
  # _wire.py is idempotent, so this adds the Stop hook and nothing else.
  if [ "$WANT_GUARD" = "1" ] && [ "${#WIRE_FILES[@]}" -gt 0 ]; then
    JEV_HOME="$AIRLOCK_HOME" AIRLOCK_HOME="$AIRLOCK_HOME" AIRLOCK_PYTHON3="$PY" \
      "$SCRIPT_DIR/wire.sh" --apply "${WIRE_EXTRA_FLAGS[@]}" "${WIRE_FILES[@]}" \
      || warn "wiring the belay Stop hook reported a problem"
  fi
fi

if [ "$WANT_COMPACTION" = "1" ]; then
  step "Compaction"
  warn "compaction/README.md first: it sends far more off the machine than"
  warn "  anything else in this repository (up to ~25,000 tokens of raw tool"
  warn "  inputs/results per request, unredacted). Not run automatically here;"
  warn "  install it yourself once you have read that and loaded the key:"
  warn "      compaction/install.sh"
fi

# --- done -------------------------------------------------------------------
step "Done"
echo "   Prove it actually runs:"
echo "       install/doctor.sh"
if [ "$NO_SYSTEMD" = "1" ]; then
  echo
  echo "   Installed in no-systemd mode. Nothing is scheduled; the hook still"
  echo "   works and still fails open."
fi
exit 0
