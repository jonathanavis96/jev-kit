"""Small persistent state for enforce mode: loop protection.

If the same session gets denied the same normalised command (or the same
Agent description) again within LOOP_WINDOW_S, the repeat is allowed rather
than denied again -- a wrong deny can wedge a session into repeating the same
blocked call forever otherwise. State lives at
~/.local/state/airlock/loop_state.json (%LOCALAPPDATA%\\airlock\\state\\
loop_state.json on Windows), directory mode 700 and file mode 600 on POSIX,
guarded with a whole-file lock so concurrent PreToolUse hook processes never
corrupt it. The lock and the permission call both go through
airlock/platform_compat.py: flock and chmod on POSIX, a byte-range lock and
the per-user %LOCALAPPDATA% ACL on Windows.

Fail-safe direction: any failure reading/writing this file means
was_recently_denied() returns False (i.e. "no prior denial seen") -- the
consequence is one extra deny gets emitted rather than a wrong one being
silently allowed through loop protection.

A rule whose match carries `strict` never consults this file, though it still
writes to it. Only R11 is strict; airlock/enforce.py says why.
"""
import json
import os
import time

from . import paths, platform_compat

STATE_DIR = paths.state_dir()
STATE_FILE = STATE_DIR / "loop_state.json"

# Keep the file bounded: prune entries far older than any window callers will
# realistically pass (the brief's loop window is 10 minutes).
PRUNE_AFTER_S = 3600


def _key_str(key):
    """key is (kind, normalised_value), e.g. ("bash", "find / -name foo")."""
    kind, value = key
    return "%s\x00%s" % (kind, value)


def ensure_dir(state_dir):
    state_dir.mkdir(parents=True, exist_ok=True)
    platform_compat.restrict_path(state_dir, 0o700)


def open_locked(state_file, lock_kind):
    """Open (creating, mode 600) and lock a JSON state file. Shared with
    airlock/browse_state.py, which keeps its own file under the same rules."""
    ensure_dir(state_file.parent)
    # O_BINARY is a Windows-only flag and 0 on POSIX (see airlock/log.py):
    # this file is seeked and truncated by offset, so text-mode newline
    # translation would corrupt it outright.
    fd = os.open(str(state_file),
                 os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0), 0o600)
    platform_compat.lock_file(fd, lock_kind)
    return fd


def close(fd):
    platform_compat.unlock_file(fd)
    try:
        os.close(fd)
    except Exception:
        pass


def load(fd):
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        raw = os.read(fd, 10 * 1024 * 1024)
        if not raw:
            return {}
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save(fd, data):
    raw = json.dumps(data).encode("utf-8")
    os.ftruncate(fd, 0)
    os.lseek(fd, 0, os.SEEK_SET)
    os.write(fd, raw)


def _ensure_dir():
    ensure_dir(STATE_DIR)


def _open_locked(lock_kind):
    return open_locked(STATE_FILE, lock_kind)


def _entries(data, session_id):
    """This session's {key: ts} map, or {} when the file holds anything
    else there (valid JSON of the wrong shape must not raise)."""
    entries = data.get(session_id or "")
    return entries if isinstance(entries, dict) else {}


def _prune(data, now):
    for sess in list(data.keys()):
        entries = data.get(sess)
        if not isinstance(entries, dict):
            # A row of the wrong shape can never be read, and leaving it in
            # place made every later record_denial() raise here and give up:
            # loop protection silently stopped recording for good.
            del data[sess]
            continue
        for k in list(entries.keys()):
            try:
                stale = (now - entries[k]) > PRUNE_AFTER_S
            except Exception:
                stale = True
            if stale:
                del entries[k]
        if entries:
            data[sess] = entries
        else:
            del data[sess]
    return data


def was_recently_denied(session_id, key, window_s):
    """True if (session_id, key) was recorded by record_denial() within the
    last window_s seconds. Never raises."""
    try:
        fd = _open_locked(platform_compat.LOCK_SHARED)
    except Exception:
        return False
    try:
        data = load(fd)
    finally:
        close(fd)

    try:
        ts = _entries(data, session_id).get(_key_str(key))
        if ts is None:
            return False
        # A stamp from the future (clock stepped back) is not a recent deny.
        return 0 <= (time.time() - ts) <= window_s
    except Exception:
        return False


def record_denial(session_id, key):
    """Record that (session_id, key) was just denied, for future loop
    protection. Never raises."""
    try:
        fd = _open_locked(platform_compat.LOCK_EXCLUSIVE)
    except Exception:
        return
    try:
        data = _prune(load(fd), time.time())
        data.setdefault(session_id or "", {})[_key_str(key)] = time.time()
        save(fd, data)
    except Exception:
        return
    finally:
        close(fd)
