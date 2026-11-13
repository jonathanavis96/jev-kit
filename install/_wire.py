#!/usr/bin/env python3
"""Helper for install/wire.sh.

Two jobs, both idempotent:

  1. REPOINT an existing airlock PreToolUse hook command at the deployed
     copy. Surgical text substitution, not a JSON re-serialize, so this edit
     changes exactly the hook command string(s) and nothing else about a
     hand-authored settings.json (key order, indentation, unrelated hooks).

  2. ADD whatever is missing -- the PreToolUse entry itself (a first install
     has nothing to repoint: there is no airlock hook command anywhere yet),
     the SessionStart session-check entry (a DEFAULT component: the guard
     fails open, so a dead guard is silent, and on a workstation the only
     reliable moment to say so is when somebody starts a session), the
     PostToolUse and PostToolUseFailure browse-unlock entries (also a
     default: they are the only thing
     that lets R11 stand aside when the kit's own `browse` tool has given up
     -- see hooks/airlock_browse_unlock.py), and, opt in per flag, the belay
     Stop hook and the function-hooks env var.
     Adding necessarily changes the JSON's structure, so this path
     re-serializes the whole file (via json.load/json.dump, which preserves
     existing key order -- Python dicts keep insertion order) rather than
     doing text surgery on a shape that was not there to begin with. Every
     existing key and hook survives; only the missing pieces are appended.

A file that needs ONLY a repoint (the common case on a machine that already
wired an earlier release) still goes through the byte-preserving text path.
A file that needs anything ADDED goes through the structural path, even if
it also needs a repoint -- there is no way to add new nested JSON without
becoming a JSON re-serializer for that file.

Reads NEW_HOOK, NEW_HOOK_COMMAND, APPLY, BELAY, BELAY_WRAPPER,
FUNCTION_HOOKS, SESSION_CHECK, SESSION_CHECK_HOOK, SESSION_CHECK_COMMAND,
BROWSE_UNLOCK, BROWSE_UNLOCK_HOOK and BROWSE_UNLOCK_COMMAND from the
environment (set by wire.sh) and the settings.json paths from argv.
Never touches a path not given on the command line.
"""
import copy
import datetime
import json
import os
import re
import shutil
import sys

NEW_HOOK = os.environ["NEW_HOOK"]
NEW_HOOK_COMMAND = os.environ.get("NEW_HOOK_COMMAND", NEW_HOOK)
APPLY = os.environ.get("APPLY") == "1"
BELAY = os.environ.get("BELAY") == "1"
BELAY_WRAPPER = os.environ.get("BELAY_WRAPPER", "")
FUNCTION_HOOKS = os.environ.get("FUNCTION_HOOKS") == "1"
FUNCTION_HOOKS_ENV_KEY = "CLAUDE_CODE_ENABLE_FUNCTION_HOOKS"
# The session check is a DEFAULT component, so it defaults to ON here too and
# wire.sh has to pass SESSION_CHECK=0 to leave it out. Its own hard budget is
# 300 ms; the 5 s registered here is the same generous ceiling the PreToolUse
# entry carries, for a hook that is meant never to approach it.
SESSION_CHECK = os.environ.get("SESSION_CHECK", "1") == "1"
SESSION_CHECK_HOOK = os.environ.get("SESSION_CHECK_HOOK", "")
SESSION_CHECK_COMMAND = os.environ.get("SESSION_CHECK_COMMAND", SESSION_CHECK_HOOK)
# The browse unlock is a DEFAULT too, for the same reason the session check
# is: without it R11 denies every Playwright call in a session where the kit's
# own `browse` tool has already failed, and the agent is left with no browser.
# It is the only way past that rule, so an install that skips it installs a
# strictness nobody chose.
BROWSE_UNLOCK = os.environ.get("BROWSE_UNLOCK", "1") == "1"
BROWSE_UNLOCK_HOOK = os.environ.get("BROWSE_UNLOCK_HOOK", "")
BROWSE_UNLOCK_COMMAND = os.environ.get("BROWSE_UNLOCK_COMMAND", BROWSE_UNLOCK_HOOK)
# The one matcher in the whole file that is not "*". PostToolUse fires after
# every tool call in the session, and this hook has exactly one tool to say
# anything about, so the filtering is worth doing before the interpreter
# starts rather than inside it.
BROWSE_UNLOCK_MATCHER = "mcp__browse__browse"
# The unlock is registered under BOTH of these. A `browse` call that raises
# never reaches PostToolUse: Claude Code sends it to PostToolUseFailure
# instead, and an errored call is the commonest way `browse` gives up. Wired
# under PostToolUse alone, the unlock never saw one (2026-09-25).
BROWSE_UNLOCK_EVENTS = ("PostToolUse", "PostToolUseFailure")
# 5 s here on every platform, including native Windows: the enforce judgement
# budget there is 2000ms (airlock/enforce.py:WINDOWS_DEFAULT_BUDGET_MS, no
# warm daemon so every call is a fresh HTTPS connection, measured median
# 1030ms / max 1359ms), which leaves 3s of room for interpreter start-up and
# the rest of the hook's own work before this ceiling could fire.
PRETOOLUSE_TIMEOUT = 5
BELAY_TIMEOUT = 25
SESSION_CHECK_TIMEOUT = 5
# The browse unlock reads one payload and writes one small JSON file. 5 s is
# the same generous ceiling the other two carry, for a hook that should never
# be near it.
BROWSE_UNLOCK_TIMEOUT = 5

# Matches a JSON string value that is (or ends in) a path to airlock.py's
# hook entry point -- e.g. "$HOME/code/airlock/hooks/airlock.py" or
# "$HOME/.local/share/airlock/current/hooks/airlock.py" (written out in
# full in the file it reads; nothing here assumes a particular user).
# Deliberately anchored on "hooks/airlock.py" so it matches regardless of
# which checkout or release directory currently precedes it.
# Matches the new name and BOTH older names (`hooks/plumbline.py`,
# `hooks/jev_guard.py`), so wiring a machine that predates either rename
# repoints it in one pass.
#
# Captured in two parts, because a hook command is normally
# "<interpreter> <path>" and the interpreter is a deliberate choice -- a
# machine that pins /usr/bin/python3 rather than relying on the shebang and
# the file's mode bit must keep doing so after a rewire. Group 1 is
# everything up to and including the last space before the path; group 2 is
# the path itself, and only group 2 is replaced.
#
# HOOK_COMMAND_QUOTED=1 selects the Windows shape instead. There the command
# is "<interpreter>" "<script>" -- both parts quoted, because a Windows
# profile directory can contain a space -- and the path separator is a
# backslash, which inside a JSON string is written as an escaped pair. The
# two shapes are kept as separate patterns rather than one permissive
# pattern: allowing spaces inside the path in the POSIX pattern would make
# `/usr/bin/env python3 /x/hooks/airlock.py` split in the wrong place and
# silently drop the `python3`.
_HOOK_PATTERN = re.compile(
    r'"((?:(?:[^"\\]|\\.)*?\s)?)((?:[^"\\\s]|\\.)*hooks/(?:airlock|plumbline|jev_guard)\.py)"')

# Same match, applied to a bare (unquoted) command string already extracted
# from parsed JSON -- used when walking the structure instead of the text.
_HOOK_CMD_RE = re.compile(
    r'^((?:(?:[^\\]|\\.)*?\s)?)((?:[^\\\s]|\\.)*hooks/(?:airlock|plumbline|jev_guard)\.py)$')

# The Windows pair. In the raw JSON text an inner quote is \" and a path
# separator is \\, hence the doubled escapes; in an already-parsed command
# string both are single characters.
#
# On Windows the path being matched is usually NOT `hooks\airlock.py`: the
# stable thing settings.json points at is the launcher, `airlock-hook.py` in
# the install root (see install/windows_common.py for why), so both spellings
# are matched. Without the launcher spelling every re-wire would look like a
# first install and rewrite a file that needed nothing.
_WIN_HOOK_TAIL = r'(?:hooks\\\\(?:airlock|plumbline|jev_guard)|airlock-hook)\.py'
_WIN_HOOK_TAIL_PARSED = r'(?:hooks[\\\\/](?:airlock|plumbline|jev_guard)|airlock-hook)\.py'
#
# Two details make or break these. The prefix group is GREEDY, so it ends at
# the LAST opening quote rather than the first -- a lazy prefix stops at the
# quote that opens the interpreter and silently drops `py.exe` from the
# rewritten command. And the path group may contain an escaped BACKSLASH but
# never an escaped QUOTE, so it cannot run past the end of its own quoted
# argument into the next one.
_WIN_PATH_CHARS = r'(?:[^"\\]|\\\\)*?'
_WIN_HOOK_PATTERN = re.compile(
    r'"((?:[^"\\]|\\.)*\\")(' + _WIN_PATH_CHARS + _WIN_HOOK_TAIL + r')(\\")"')
_WIN_HOOK_CMD_RE = re.compile(
    r'^((?:[^"]|"[^"]*")*")([^"]*?' + _WIN_HOOK_TAIL_PARSED + r')(")$')

# The SAME two shapes again, for the SessionStart session check. Kept as its
# own pair rather than folded into the patterns above, because the two hooks
# are repointed independently: a machine can perfectly well have a current
# PreToolUse entry and a session-check entry still pointing at an old release,
# and one pattern matching both would make "how many did we repoint" a lie.
#
# They cannot collide. The guard's pattern is anchored on the literal
# `hooks/airlock.py`; `hooks/airlock_session_check.py` does not end in that,
# and `airlock-session-check.py` does not end in `airlock-hook.py`.
_SESSION_TAIL = r'hooks/airlock_session_check\.py'
_SESSION_PATTERN = re.compile(
    r'"((?:(?:[^"\\]|\\.)*?\s)?)((?:[^"\\\s]|\\.)*' + _SESSION_TAIL + r')"')
_SESSION_CMD_RE = re.compile(
    r'^((?:(?:[^\\]|\\.)*?\s)?)((?:[^\\\s]|\\.)*' + _SESSION_TAIL + r')$')

_WIN_SESSION_TAIL = r'(?:hooks\\\\airlock_session_check|airlock-session-check)\.py'
_WIN_SESSION_TAIL_PARSED = r'(?:hooks[\\\\/]airlock_session_check|airlock-session-check)\.py'

# And a THIRD pair, for the PostToolUse browse unlock. Same reasoning as the
# session check's: the three hooks are repointed independently, and one
# pattern covering several of them would make the "how many did we repoint"
# count a lie. None of the three can collide -- each is anchored on its own
# file name, and no name is a suffix of another.
_BROWSE_TAIL = r'hooks/airlock_browse_unlock\.py'
_BROWSE_PATTERN = re.compile(
    r'"((?:(?:[^"\\]|\\.)*?\s)?)((?:[^"\\\s]|\\.)*' + _BROWSE_TAIL + r')"')
_BROWSE_CMD_RE = re.compile(
    r'^((?:(?:[^\\]|\\.)*?\s)?)((?:[^\\\s]|\\.)*' + _BROWSE_TAIL + r')$')

_WIN_BROWSE_TAIL = r'(?:hooks\\\\airlock_browse_unlock|airlock-browse-unlock)\.py'
_WIN_BROWSE_TAIL_PARSED = r'(?:hooks[\\\\/]airlock_browse_unlock|airlock-browse-unlock)\.py'

QUOTED = os.environ.get("HOOK_COMMAND_QUOTED") == "1"

_WIN_SESSION_PATTERN = re.compile(
    r'"((?:[^"\\]|\\.)*\\")(' + _WIN_PATH_CHARS + _WIN_SESSION_TAIL + r')(\\")"')
_WIN_SESSION_CMD_RE = re.compile(
    r'^((?:[^"]|"[^"]*")*")([^"]*?' + _WIN_SESSION_TAIL_PARSED + r')(")$')

_WIN_BROWSE_PATTERN = re.compile(
    r'"((?:[^"\\]|\\.)*\\")(' + _WIN_PATH_CHARS + _WIN_BROWSE_TAIL + r')(\\")"')
_WIN_BROWSE_CMD_RE = re.compile(
    r'^((?:[^"]|"[^"]*")*")([^"]*?' + _WIN_BROWSE_TAIL_PARSED + r')(")$')


def _shaped(prefix, command=None):
    """A Windows command prefix in the shell shape this install wants.

    Without Git Bash the hook runs under PowerShell and needs its call
    operator (`& "py" "launcher"`); with Git Bash it must not have one, or
    bash reads `&` as a syntax error, exits 2 and blocks every tool call.
    Which one applies follows from NEW_HOOK_COMMAND, the command the
    installer built for this machine, so installing or removing Git for
    Windows and re-running --wire fixes the shape instead of keeping the old
    one. `command` is the command built for the hook being repointed (the
    guard's by default). POSIX prefixes are returned untouched."""
    if not QUOTED:
        return prefix
    want = NEW_HOOK_COMMAND if command is None else command
    bare = prefix[2:] if prefix.startswith("& ") else prefix
    return "& " + bare if (want or "").lstrip().startswith("& ") else bare


def _shape_ok(prefix, command=None):
    return _shaped(prefix, command) == prefix


def _text_pattern():
    return _WIN_HOOK_PATTERN if QUOTED else _HOOK_PATTERN


def _cmd_pattern():
    return _WIN_HOOK_CMD_RE if QUOTED else _HOOK_CMD_RE


def _session_text_pattern():
    return _WIN_SESSION_PATTERN if QUOTED else _SESSION_PATTERN


def _session_cmd_pattern():
    return _WIN_SESSION_CMD_RE if QUOTED else _SESSION_CMD_RE


def _browse_text_pattern():
    return _WIN_BROWSE_PATTERN if QUOTED else _BROWSE_PATTERN


def _browse_cmd_pattern():
    return _WIN_BROWSE_CMD_RE if QUOTED else _BROWSE_CMD_RE


def _json_inner(value):
    """`value` escaped for use INSIDE a JSON string literal. On Linux this is
    almost always the identity; on Windows it turns each backslash into the
    escaped pair the file actually contains."""
    return json.dumps(value)[1:-1]


def _backup(path):
    backup = "%s.bak.%s" % (path, datetime.datetime.now().strftime("%Y%m%dT%H%M%S"))
    shutil.copy2(path, backup)
    return backup


def _pretooluse_block():
    return {"matcher": "*", "hooks": [
        {"type": "command", "command": NEW_HOOK_COMMAND, "timeout": PRETOOLUSE_TIMEOUT}]}


def _belay_block():
    return {"matcher": "*", "hooks": [
        {"type": "command", "command": BELAY_WRAPPER, "timeout": BELAY_TIMEOUT}]}


def _session_check_block():
    return {"matcher": "*", "hooks": [
        {"type": "command", "command": SESSION_CHECK_COMMAND,
         "timeout": SESSION_CHECK_TIMEOUT}]}


def _browse_unlock_block():
    return {"matcher": BROWSE_UNLOCK_MATCHER, "hooks": [
        {"type": "command", "command": BROWSE_UNLOCK_COMMAND,
         "timeout": BROWSE_UNLOCK_TIMEOUT}]}


def _event_has_browse(data, event):
    """True if `event` already runs the browse-unlock hook, at any path. A
    stale path is the repoint's business, not a reason to add a second one."""
    pattern = _browse_cmd_pattern()
    for entry in ((data.get("hooks") or {}).get(event) or []):
        if not isinstance(entry, dict):
            continue
        for h in entry.get("hooks") or []:
            cmd = h.get("command") if isinstance(h, dict) else None
            if isinstance(cmd, str) and pattern.match(cmd):
                return True
    return False


def _browse_unlock_ok():
    """Same test as the session check's, and for the same reason: an entry
    pointing at nothing would run and fail after every `browse` call."""
    return bool(BROWSE_UNLOCK and BROWSE_UNLOCK_HOOK
                and os.path.isfile(BROWSE_UNLOCK_HOOK))


def _session_check_ok():
    """Only wire it if we were actually told where it is AND the file is
    there. A SessionStart entry pointing at nothing would run, fail and print
    an error at the top of every session -- the exact opposite of a component
    whose entire promise is silence when healthy."""
    return bool(SESSION_CHECK and SESSION_CHECK_HOOK
                and os.path.isfile(SESSION_CHECK_HOOK))


def _matcher_block(entries, matcher):
    for entry in entries:
        if isinstance(entry, dict) and entry.get("matcher") == matcher:
            return entry
    return None


def _has_command(entries, command):
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for h in entry.get("hooks") or []:
            if isinstance(h, dict) and h.get("command") == command:
                return True
    return False


def _append_hook(data, event, block, command, matcher="*"):
    """Add `block`'s single hook to `data["hooks"][event]`, reusing an
    existing entry with the SAME matcher when one is there rather than adding
    a second one. No-op if `command` is already present anywhere in `event`.

    `matcher` is "*" for every hook here but the browse unlock, which is
    registered against one tool name and must never be merged into a "*"
    entry -- that would run it after every tool call in the session."""
    hooks = data.setdefault("hooks", {})
    entries = hooks.setdefault(event, [])
    if _has_command(entries, command):
        return False
    existing = _matcher_block(entries, matcher)
    if existing is not None:
        existing.setdefault("hooks", []).append(block["hooks"][0])
    else:
        entries.append(block)
    return True


def _fresh_settings():
    data = {"hooks": {"PreToolUse": [_pretooluse_block()]}}
    if _session_check_ok():
        data["hooks"]["SessionStart"] = [_session_check_block()]
    if _browse_unlock_ok():
        for event in BROWSE_UNLOCK_EVENTS:
            data["hooks"][event] = [_browse_unlock_block()]
    if BELAY and BELAY_WRAPPER and os.path.isfile(BELAY_WRAPPER):
        data["hooks"]["Stop"] = [_belay_block()]
    if FUNCTION_HOOKS:
        data["env"] = {FUNCTION_HOOKS_ENV_KEY: "1"}
    return data


def _describe_fresh():
    lines = ["  PreToolUse: matcher \"*\", command \"%s\", timeout %d"
             % (NEW_HOOK_COMMAND, PRETOOLUSE_TIMEOUT)]
    if SESSION_CHECK:
        if _session_check_ok():
            lines.append("  SessionStart (session check): matcher \"*\", "
                         "command \"%s\", timeout %d"
                         % (SESSION_CHECK_COMMAND, SESSION_CHECK_TIMEOUT))
        else:
            lines.append("  SessionStart (session check): SKIPPED, no hook at %s"
                         % (SESSION_CHECK_HOOK or "<unset>"))
    if BROWSE_UNLOCK:
        if _browse_unlock_ok():
            for event in BROWSE_UNLOCK_EVENTS:
                lines.append("  %s (browse unlock): matcher \"%s\", "
                             "command \"%s\", timeout %d"
                             % (event, BROWSE_UNLOCK_MATCHER,
                                BROWSE_UNLOCK_COMMAND, BROWSE_UNLOCK_TIMEOUT))
        else:
            lines.append("  PostToolUse (browse unlock): SKIPPED, no hook at %s"
                         % (BROWSE_UNLOCK_HOOK or "<unset>"))
    if BELAY:
        if BELAY_WRAPPER and os.path.isfile(BELAY_WRAPPER):
            lines.append("  Stop (belay): matcher \"*\", command \"%s\", timeout %d"
                          % (BELAY_WRAPPER, BELAY_TIMEOUT))
        else:
            lines.append("  Stop (belay): SKIPPED, no wrapper at %s" % (BELAY_WRAPPER or "<unset>"))
    if FUNCTION_HOOKS:
        lines.append("  env.%s = \"1\"" % FUNCTION_HOOKS_ENV_KEY)
    return lines


def _process_missing(path):
    if not APPLY:
        print("%s: does not exist; --apply would create it with:" % path)
        for line in _describe_fresh():
            print(line)
        return True
    data = _fresh_settings()
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, indent=2) + "\n")
    print("%s: did not exist, created with:" % path)
    for line in _describe_fresh():
        print(line)
    return True


def _repoint_one(text, pattern, new_path, command=None):
    if QUOTED:
        def _replace(match):
            return '"%s%s%s"' % (_shaped(match.group(1), command), _json_inner(new_path),
                                 match.group(3))
    else:
        def _replace(match):
            return '"%s%s"' % (match.group(1), _json_inner(new_path))
    return pattern.sub(_replace, text)


def _repoint_text(text):
    """Pure text substitution: repoint every airlock hook command found to its
    new path, keeping each command's own interpreter prefix.

    All three hooks are repointed in the one pass -- the PreToolUse guard, the
    SessionStart session check and the PostToolUse browse unlock -- because a
    machine re-wiring after a release needs all of them to follow, and doing
    them separately would mean three backups of the same file for one logical
    edit."""
    text = _repoint_one(text, _text_pattern(), NEW_HOOK)
    if SESSION_CHECK_HOOK:
        text = _repoint_one(text, _session_text_pattern(), SESSION_CHECK_HOOK,
                            SESSION_CHECK_COMMAND)
    if BROWSE_UNLOCK_HOOK:
        text = _repoint_one(text, _browse_text_pattern(), BROWSE_UNLOCK_HOOK,
                            BROWSE_UNLOCK_COMMAND)
    return text


def _structural_repoint(data, pattern=None, new_path=None, command=None):
    """Walk hooks.PreToolUse (and, defensively, every hook block) and
    repoint any command whose path is an old airlock/plumbline/jev_guard
    hook path, in place. Returns True if anything changed.

    `pattern`/`new_path` select which of the two hooks is being repointed;
    the defaults are the PreToolUse guard, which is what every existing
    caller means."""
    pattern = pattern or _cmd_pattern()
    new_path = new_path or NEW_HOOK
    changed = False
    hooks = data.get("hooks") or {}
    for entries in hooks.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for h in entry.get("hooks") or []:
                if not isinstance(h, dict):
                    continue
                cmd = h.get("command")
                if not isinstance(cmd, str):
                    continue
                m = pattern.match(cmd)
                if m and (m.group(2) != new_path or not _shape_ok(m.group(1), command)):
                    tail = m.group(3) if QUOTED else ""
                    h["command"] = _shaped(m.group(1), command) + new_path + tail
                    changed = True
    return changed


def process(path):
    if not os.path.isfile(path):
        return _process_missing(path)

    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    try:
        data = json.loads(text)
    except Exception as exc:
        print("%s: not valid JSON (%s), refusing to touch it" % (path, exc), file=sys.stderr)
        return False

    matches = [(m[0], m[1]) for m in _text_pattern().findall(text)]
    needs_repoint = bool(matches) and not all(
        hook_path == _json_inner(NEW_HOOK) and _shape_ok(prefix)
        for prefix, hook_path in matches)
    needs_add_pretooluse = not matches

    belay_ok = BELAY and bool(BELAY_WRAPPER) and os.path.isfile(BELAY_WRAPPER)
    belay_missing_wrapper = BELAY and not belay_ok
    stop_entries = (data.get("hooks") or {}).get("Stop") or []
    needs_belay = belay_ok and not _has_command(stop_entries, BELAY_WRAPPER)

    needs_function_hooks = FUNCTION_HOOKS and (data.get("env") or {}).get(FUNCTION_HOOKS_ENV_KEY) != "1"

    # The SessionStart session check. Two separate questions, deliberately:
    # is there an entry at all (add it), and does the entry that IS there
    # point somewhere stale (repoint it). Conflating them would make a first
    # install and a re-wire the same code path and get one of them wrong.
    session_ok = _session_check_ok()
    # Only NOISY when a path was actually named and is not there. A caller
    # that never passed SESSION_CHECK_HOOK at all (an old wire.sh, or a test
    # exercising the guard entry alone) gets silence, not a warning about a
    # component it never asked for.
    session_missing_hook = bool(SESSION_CHECK and SESSION_CHECK_HOOK and not session_ok)
    session_matches = [(m[0], m[1]) for m in _session_text_pattern().findall(text)]
    needs_add_session = session_ok and not session_matches
    needs_repoint_session = bool(session_matches) and SESSION_CHECK_HOOK and not all(
        hook_path == _json_inner(SESSION_CHECK_HOOK) and _shape_ok(prefix, SESSION_CHECK_COMMAND)
        for prefix, hook_path in session_matches)

    # The PostToolUse browse unlock, the same two questions again.
    browse_ok = _browse_unlock_ok()
    browse_missing_hook = bool(BROWSE_UNLOCK and BROWSE_UNLOCK_HOOK and not browse_ok)
    browse_matches = [(m[0], m[1]) for m in _browse_text_pattern().findall(text)]
    # Asked per event: an install from before PostToolUseFailure was wired
    # has the PostToolUse entry and still needs the other one.
    browse_events_to_add = [e for e in BROWSE_UNLOCK_EVENTS
                            if browse_ok and not _event_has_browse(data, e)]
    needs_add_browse = bool(browse_events_to_add)
    needs_repoint_browse = bool(browse_matches) and BROWSE_UNLOCK_HOOK and not all(
        hook_path == _json_inner(BROWSE_UNLOCK_HOOK) and _shape_ok(prefix, BROWSE_UNLOCK_COMMAND)
        for prefix, hook_path in browse_matches)

    needs_repoint = needs_repoint or needs_repoint_session or needs_repoint_browse
    needs_add = (needs_add_pretooluse or needs_add_session or needs_add_browse
                 or needs_belay or needs_function_hooks)

    if not (needs_repoint or needs_add):
        if matches:
            print("%s: already wired to %s" % (path, NEW_HOOK))
        else:
            print("%s: nothing to add or repoint" % path)
        if belay_missing_wrapper:
            print("%s: --belay given but no wrapper at %s, skipping Stop hook"
                  % (path, BELAY_WRAPPER or "<unset>"))
        if session_missing_hook:
            print("%s: --session-check given but no hook at %s, skipping "
                  "SessionStart entry" % (path, SESSION_CHECK_HOOK or "<unset>"))
        if browse_missing_hook:
            print("%s: no browse-unlock hook at %s, skipping PostToolUse entry"
                  % (path, BROWSE_UNLOCK_HOOK or "<unset>"))
        return False

    # A pure repoint -- nothing to ADD -- keeps the byte-preserving text
    # path: it is both the common case (a machine re-wiring after a
    # release) and the one this design exists to protect (see module
    # docstring and tests/test_wire.py's TestInterpreterPrefix/TestSafety).
    if needs_repoint and not needs_add:
        new_text = _repoint_text(text)
        try:
            json.loads(new_text)
        except Exception as exc:
            print("%s: substitution would produce invalid JSON (%s), refusing" % (path, exc),
                  file=sys.stderr)
            return False
        # Only the hooks this run was actually told where to find are counted
        # or printed: _repoint_text leaves the others alone, so counting them
        # would report an edit that did not happen.
        pairs = [(m, NEW_HOOK, NEW_HOOK_COMMAND) for m in matches]
        total = len(matches)
        if SESSION_CHECK_HOOK:
            pairs += [(m, SESSION_CHECK_HOOK, SESSION_CHECK_COMMAND) for m in session_matches]
            total += len(session_matches)
        if BROWSE_UNLOCK_HOOK:
            pairs += [(m, BROWSE_UNLOCK_HOOK, BROWSE_UNLOCK_COMMAND) for m in browse_matches]
            total += len(browse_matches)
        if not APPLY:
            print("%s: would repoint %d hook path(s)" % (path, total))
            for (prefix, hook_path), target, command in sorted(set(pairs)):
                if hook_path != target or not _shape_ok(prefix, command):
                    print("  - %s%s" % (prefix, hook_path))
                    print("    -> %s%s" % (_shaped(prefix, command), target))
            return True
        backup = _backup(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_text)
        print("%s: backed up to %s, %d hook path(s) repointed (interpreter prefix kept)"
              % (path, backup, total))
        return True

    # Something needs ADDING (possibly alongside a repoint): structural
    # edit. Still idempotent -- run again and every branch above reports
    # nothing left to do.
    actions = []
    new_data = copy.deepcopy(data)
    if needs_repoint:
        if _structural_repoint(new_data):
            actions.append("repointed %d existing hook path(s) to %s" % (len(matches), NEW_HOOK))
        if needs_repoint_session and _structural_repoint(
                new_data, _session_cmd_pattern(), SESSION_CHECK_HOOK, SESSION_CHECK_COMMAND):
            actions.append("repointed %d session-check hook path(s) to %s"
                           % (len(session_matches), SESSION_CHECK_HOOK))
        if needs_repoint_browse and _structural_repoint(
                new_data, _browse_cmd_pattern(), BROWSE_UNLOCK_HOOK, BROWSE_UNLOCK_COMMAND):
            actions.append("repointed %d browse-unlock hook path(s) to %s"
                           % (len(browse_matches), BROWSE_UNLOCK_HOOK))
    if needs_add_pretooluse:
        if _append_hook(new_data, "PreToolUse", _pretooluse_block(), NEW_HOOK_COMMAND):
            actions.append('added PreToolUse: matcher "*", command "%s", timeout %d'
                            % (NEW_HOOK_COMMAND, PRETOOLUSE_TIMEOUT))
    if needs_add_session:
        if _append_hook(new_data, "SessionStart", _session_check_block(),
                        SESSION_CHECK_COMMAND):
            actions.append('added SessionStart (session check): matcher "*", '
                           'command "%s", timeout %d'
                           % (SESSION_CHECK_COMMAND, SESSION_CHECK_TIMEOUT))
    for event in browse_events_to_add:
        if _append_hook(new_data, event, _browse_unlock_block(),
                        BROWSE_UNLOCK_COMMAND, BROWSE_UNLOCK_MATCHER):
            actions.append('added %s (browse unlock): matcher "%s", '
                           'command "%s", timeout %d'
                           % (event, BROWSE_UNLOCK_MATCHER,
                              BROWSE_UNLOCK_COMMAND, BROWSE_UNLOCK_TIMEOUT))
    if needs_belay:
        if _append_hook(new_data, "Stop", _belay_block(), BELAY_WRAPPER):
            actions.append('added Stop (belay): matcher "*", command "%s", timeout %d'
                            % (BELAY_WRAPPER, BELAY_TIMEOUT))
    if needs_function_hooks:
        new_data.setdefault("env", {})[FUNCTION_HOOKS_ENV_KEY] = "1"
        actions.append('set env.%s = "1"' % FUNCTION_HOOKS_ENV_KEY)

    new_text = json.dumps(new_data, indent=2) + "\n"
    try:
        json.loads(new_text)
    except Exception as exc:
        print("%s: edit would produce invalid JSON (%s), refusing" % (path, exc), file=sys.stderr)
        return False

    if not APPLY:
        print("%s: --apply would:" % path)
        for a in actions:
            print("  %s" % a)
        if belay_missing_wrapper:
            print("  (--belay given but no wrapper at %s, skipping Stop hook)"
                  % (BELAY_WRAPPER or "<unset>"))
        if session_missing_hook:
            print("  (--session-check given but no hook at %s, skipping "
                  "SessionStart entry)" % (SESSION_CHECK_HOOK or "<unset>"))
        if browse_missing_hook:
            print("  (no browse-unlock hook at %s, skipping PostToolUse entry)"
                  % (BROWSE_UNLOCK_HOOK or "<unset>"))
        return True

    backup = _backup(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_text)
    print("%s: backed up to %s" % (path, backup))
    for a in actions:
        print("  %s" % a)
    if belay_missing_wrapper:
        print("  (--belay given but no wrapper at %s, skipping Stop hook)"
              % (BELAY_WRAPPER or "<unset>"))
    if session_missing_hook:
        print("  (--session-check given but no hook at %s, skipping "
              "SessionStart entry)" % (SESSION_CHECK_HOOK or "<unset>"))
    if browse_missing_hook:
        print("  (no browse-unlock hook at %s, skipping PostToolUse entry)"
              % (BROWSE_UNLOCK_HOOK or "<unset>"))
    return True


def main():
    paths = sys.argv[1:]
    if not paths:
        print("no settings.json paths given", file=sys.stderr)
        return 2
    # One file that cannot be read or written must not stop the others, and
    # must not look like success: it is reported, and the exit status is 1.
    failed = False
    for path in paths:
        try:
            process(path)
        except Exception as exc:
            failed = True
            print("%s: could not wire (%s: %s), left as it was"
                  % (path, type(exc).__name__, exc), file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
