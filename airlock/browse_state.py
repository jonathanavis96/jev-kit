"""Per-session record that the kit's `browse` tool gave up on a goal.

R11 is strict (see airlock/rules.py, prefilter_browser_driving): a stamp does
not lift it and repeating the call does not either. That is right while
`browse` can do the job, and wrong the moment it cannot. Jev's chooser sees
one step at a time, only inside the viewport, so a multi-hop goal is beyond
it -- measured on a two-hop Wikipedia link-navigation task, where `browse`
came back `blocked`. A strict rule on top of that leaves the session with no
browser at all, which is worse than the cost it was saving.

So `browse` giving up is the one thing that opens the door. A PostToolUse hook
(hooks/airlock_browse_unlock.py) writes a row here when a `browse` call comes
back `blocked`, or when the call itself errored, and R11 reads it: an
unexpired row for this session turns the deny into a warn. Nothing else does.
Thirty minutes, then the door closes again.

State lives beside the loop-protection file, at
~/.local/state/airlock/browse_unlock.json (%LOCALAPPDATA%\\airlock\\state\\
on Windows), directory 700 and file 600 on POSIX, under the same whole-file
lock, through the same airlock/platform_compat.py calls. The lock matters for
the same reason it does there: a PostToolUse hook and a PreToolUse hook can be
in this file at the same moment.

Fail-safe direction, and it is the OPPOSITE of state.py's. Any failure reading
or writing this file means `unlocked()` returns False, so the consequence of a
broken file is that R11 keeps denying -- the strict behaviour the branch
already ships -- rather than a permanent silent unlock.

SUBAGENTS SHARE THE PARENT'S session_id. Measured on this box: a subagent's
tool calls log the same `session_id` as the session that dispatched it (one
airlock log, one id, across both). So the unlock a subagent earns is the
session's unlock, parent and siblings included. That is accepted rather than
worked around: the id in the payload is the only handle a hook gets, and an
agent that had to give up on `browse` is evidence about the task, not about
which agent asked.
"""
import json
import os
import time

from . import paths
from . import platform_compat

STATE_DIR = paths.state_dir()
STATE_FILE = STATE_DIR / "browse_unlock.json"

# How long one `browse` failure keeps Playwright MCP open. Thirty minutes is
# long enough to finish the task that needed it and short enough that the next
# unrelated piece of browsing starts at `browse` again.
UNLOCK_WINDOW_S = 1800

# The statuses worth recording. `done` is `browse` succeeding, so it records
# nothing. "error" is this module's own name for a call that failed outright
# (isError, or a transport error), not something browse/server.py returns.
GAVE_UP_STATUSES = frozenset(("blocked", "error"))

_GOAL_LIMIT = 300


def _ensure_dir():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    platform_compat.restrict_path(STATE_DIR, 0o700)


def _open_locked(lock_kind):
    _ensure_dir()
    # O_BINARY is Windows-only and 0 on POSIX (see airlock/log.py): the file
    # is truncated and seeked by offset, so newline translation would corrupt
    # it. Same call shape as airlock/state.py, deliberately.
    fd = os.open(str(STATE_FILE),
                 os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0), 0o600)
    platform_compat.lock_file(fd, lock_kind)
    return fd


def _close(fd):
    platform_compat.unlock_file(fd)
    try:
        os.close(fd)
    except Exception:
        pass


def _load(fd):
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        raw = os.read(fd, 10 * 1024 * 1024)
        if not raw:
            return {}
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save(fd, data):
    raw = json.dumps(data).encode("utf-8")
    os.ftruncate(fd, 0)
    os.lseek(fd, 0, os.SEEK_SET)
    os.write(fd, raw)


def _prune(data, now):
    """Drop every row past the window. The window is the whole life of a row,
    so nothing here outlives its usefulness by even a minute."""
    for sess in list(data.keys()):
        row = data.get(sess)
        try:
            stale = not isinstance(row, dict) or (now - float(row.get("ts"))) > UNLOCK_WINDOW_S
        except Exception:
            stale = True
        if stale:
            del data[sess]
    return data


def record_gave_up(session_id, status, goal=None, url=None):
    """Record that `browse` gave up in this session. Never raises.

    One row per session, overwritten: the question R11 asks is "has browse
    given up recently", and the latest answer is the only one that matters.
    `goal` and `url` are carried for the log and for anybody reading the file
    by hand; nothing reads them to make a decision.
    """
    status = (status or "").strip().lower()
    if status not in GAVE_UP_STATUSES:
        return False
    try:
        fd = _open_locked(platform_compat.LOCK_EXCLUSIVE)
    except Exception:
        return False
    try:
        data = _load(fd)
        now = time.time()
        data = _prune(data, now)
        row = {"ts": now, "status": status}
        if goal:
            row["goal"] = str(goal)[:_GOAL_LIMIT]
        if url:
            row["url"] = str(url)[:_GOAL_LIMIT]
        data[session_id or ""] = row
        _save(fd, data)
    except Exception:
        return False
    finally:
        _close(fd)
    return True


def recent_give_up(session_id, window_s=UNLOCK_WINDOW_S):
    """The row for this session if `browse` gave up within window_s, else
    None. Never raises; any failure reads as None, so R11 stays strict."""
    try:
        fd = _open_locked(platform_compat.LOCK_SHARED)
    except Exception:
        return None
    try:
        data = _load(fd)
    finally:
        _close(fd)

    row = data.get(session_id or "")
    if not isinstance(row, dict):
        return None
    try:
        if (time.time() - float(row.get("ts"))) > window_s:
            return None
    except Exception:
        return None
    return row


def claim_announcement(session_id):
    """True exactly once per unlock window: the first Playwright call after
    `browse` gave up. Every later call in the same window gets False, so R11's
    "the door is open" notice is said once instead of on every call (it was
    repeated on each click, wait and snapshot, which read as spam). A new
    `browse` failure writes a fresh row without the flag, so the next window
    announces again. Never raises; a failure reads as False (stay quiet --
    the call is allowed either way, only the notice is at stake)."""
    try:
        fd = _open_locked(platform_compat.LOCK_EXCLUSIVE)
    except Exception:
        return False
    try:
        data = _load(fd)
        row = data.get(session_id or "")
        if not isinstance(row, dict) or row.get("announced"):
            return False
        row["announced"] = True
        _save(fd, data)
        return True
    except Exception:
        return False
    finally:
        _close(fd)


def unlocked(session_id, window_s=UNLOCK_WINDOW_S):
    """True if this session may use Playwright MCP because `browse` gave up."""
    return recent_give_up(session_id, window_s) is not None
