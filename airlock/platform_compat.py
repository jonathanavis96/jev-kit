"""Every place airlock has to care which operating system it is on.

The rest of the package imports from here rather than testing `sys.platform`
inline, for two reasons. The first is that a single module is the only way to
keep the Windows support honest: there is one list of the things POSIX gives
us that Windows does not, and it is this file. The second is testability --
every function takes an optional `windows` argument, so the whole Windows code
path is exercised by the Linux test suite by injecting `windows=True`. No test
in this repository requires a Windows machine to pass.

What actually differs, and what this module does about it:

  file locking      POSIX has `fcntl.flock`; Windows has `msvcrt.locking`,
                    which is a mandatory BYTE-RANGE lock with no shared mode.
                    We take the byte-range lock well past end of file so it
                    can never collide with the file's own data, and treat a
                    shared lock as exclusive (correct, just less concurrent).
  detached children The shadow worker must outlive the hook process.
                    POSIX: `start_new_session=True`. Windows: the
                    DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP creation
                    flags, which is the documented equivalent.
  file permissions  `chmod 0o600` means something on POSIX and almost nothing
                    on Windows, where it only toggles the read-only attribute
                    and says nothing about who may read the file. On Windows
                    we do not pretend: we skip the chmod and rely on the
                    per-user ACL that %APPDATA% and %LOCALAPPDATA% already
                    carry, and `describe_permissions` says so out loud rather
                    than reporting a mode that would be a lie.
  unix sockets      `socket.AF_UNIX` does not exist on Windows, so the warm
                    daemon has no transport there. Windows clients go straight
                    to the direct HTTPS call.

Stdlib only, and it imports nothing else from airlock, so the hot path in
hooks/airlock.py can use it without dragging in client, guards or policy.
"""
import os
import sys

# `cygwin` is here because a CPython built for Cygwin reports that and behaves
# like POSIX; it is deliberately NOT treated as Windows. Only a native Windows
# CPython reports "win32" (including 64-bit builds).
WINDOWS_PLATFORMS = ("win32",)


def is_windows(windows=None, platform=None):
    """True on a native Windows CPython.

    `windows` is the injection point every caller in this package forwards:
    pass True/False to force the answer in a test. `platform` forces the
    `sys.platform` string instead, for tests that want to assert the real
    detection logic. Never raises.
    """
    if windows is not None:
        return bool(windows)
    try:
        return (platform if platform is not None else sys.platform) in WINDOWS_PLATFORMS
    except Exception:
        return False


def has_unix_sockets(windows=None, platform=None):
    """Can this machine speak to the warm daemon at all?

    False on Windows: there is no `AF_UNIX`, the daemon is out of scope
    there, and `airlock/client.py` must fall back to the direct HTTPS call
    (roughly 0.9 s cold against roughly 0.3 s warm) without ever raising.
    """
    if is_windows(windows, platform):
        return False
    try:
        import socket
        return hasattr(socket, "AF_UNIX")
    except Exception:
        return False


# --- detached child processes ------------------------------------------------

# Values from the Win32 CreateProcess documentation. Hard-coded rather than
# read off the `subprocess` module because on Linux `subprocess` does not
# define them at all, and this module is imported on both.
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000


def detached_popen_kwargs(windows=None, platform=None):
    """The `subprocess.Popen` keyword arguments that detach a child so it
    survives the parent exiting.

    On POSIX this is exactly the `start_new_session=True` the shadow path has
    always used, byte for byte. On Windows it is
    DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW -- the
    first two are the documented equivalent of a new session, and the third
    stops a console window flashing up on every judged tool call.
    """
    if is_windows(windows, platform):
        return {"creationflags": DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW}
    return {"start_new_session": True}


# --- file locking ------------------------------------------------------------

# Where the Windows byte-range lock is taken. Past any plausible end of file,
# so the lock byte is never a byte the file actually uses: Windows byte-range
# locks are MANDATORY, and a lock over live data would make an unrelated read
# in another process fail rather than wait.
_WIN_LOCK_OFFSET = 1 << 40

LOCK_SHARED = "shared"
LOCK_EXCLUSIVE = "exclusive"


def _win_lock_call(fd, mode):
    import msvcrt
    pos = os.lseek(fd, 0, os.SEEK_CUR)
    try:
        os.lseek(fd, _WIN_LOCK_OFFSET, os.SEEK_SET)
        msvcrt.locking(fd, mode, 1)
    finally:
        try:
            os.lseek(fd, pos, os.SEEK_SET)
        except Exception:
            pass


def lock_file(fd, kind=LOCK_EXCLUSIVE, windows=None, platform=None):
    """Take a whole-file advisory lock on `fd`. Returns True if the lock was
    taken, False if it could not be (which every caller in this package treats
    as "carry on unlocked" -- a logging or loop-protection write is never
    allowed to fail because a lock could not be acquired).

    On Windows there is no shared mode, so a shared request takes the
    exclusive lock. That is safe, just less concurrent, and both callers hold
    the lock for microseconds.
    """
    try:
        if is_windows(windows, platform):
            import msvcrt
            _win_lock_call(fd, msvcrt.LK_LOCK)
            return True
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_SH if kind == LOCK_SHARED else fcntl.LOCK_EX)
        return True
    except Exception:
        return False


def unlock_file(fd, windows=None, platform=None):
    """Release a lock taken by `lock_file`. Never raises."""
    try:
        if is_windows(windows, platform):
            import msvcrt
            _win_lock_call(fd, msvcrt.LK_UNLCK)
            return True
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)
        return True
    except Exception:
        return False


# --- file permissions --------------------------------------------------------

def restrict_path(path, mode, windows=None, platform=None):
    """Make `path` private to this user.

    POSIX: `chmod` to `mode` (0o700 for a directory, 0o600 for a file), the
    behaviour every existing caller already had.

    Windows: deliberately NOTHING. `os.chmod` there sets only the read-only
    attribute; it cannot express "owner only" and setting it would make the
    file harder to rewrite while giving no privacy at all. Privacy on Windows
    comes from the directory: %APPDATA% and %LOCALAPPDATA% are per-user and
    already carry an ACL that denies other non-administrative users. Returns
    True when a mode was actually applied, False when there was nothing
    meaningful to apply or the attempt failed. Never raises.
    """
    if is_windows(windows, platform):
        return False
    try:
        os.chmod(str(path), mode)
        return True
    except Exception:
        return False


def describe_permissions(path, windows=None, platform=None):
    """One honest sentence about who can read `path`, for the doctor.

    Returns (ok, text). On POSIX `ok` means the mode really is no wider than
    owner-only. On Windows there is no POSIX mode to read, so `ok` reports
    only that the path is inside the per-user profile, and the text says
    plainly that this is an ACL claim rather than a mode check.
    """
    path = str(path)
    if is_windows(windows, platform):
        profile = os.environ.get("USERPROFILE") or ""
        # A path test, not a string prefix: C:\Users\al is not the profile
        # of C:\Users\alice\x.
        from . import winpath
        inside = bool(profile) and winpath.is_under(path, profile)
        if inside:
            return True, ("inside the per-user profile; access is governed by the "
                          "Windows ACL on that profile, not by a POSIX mode")
        return False, ("outside %USERPROFILE%; airlock cannot vouch for who can read it. "
                       "Move it under %APPDATA%\\airlock")
    try:
        import stat
        actual = stat.S_IMODE(os.stat(path).st_mode)
    except Exception as exc:
        return False, "cannot stat: %s" % (str(exc)[:120],)
    if actual & 0o077:
        return False, "mode %o is readable by group or other" % actual
    return True, "mode %o, owner only" % actual


def pointer_trust_notes(pointer, windows=None, platform=None):
    """What could and could not be checked about a security-relevant POINTER
    file on this platform, as diagnostic lines.

    A pointer file (`keyfile.path`, `repo.path`) decides which file another
    process reads for a secret, or which git checkout the tuning loop commits
    to, so both modules trust one only after an ownership and mode check. That
    check is a POSIX check: there is no `os.getuid()` on Windows, and
    `os.stat().st_mode` there is a synthesised value that says nothing at all
    about who may write the file.

    So on Windows this returns the honest description from
    `describe_permissions` plus one line naming exactly what was NOT checked,
    and the caller records both and follows the pointer anyway. Pretending the
    ownership check passed would be a lie; refusing every pointer on Windows
    would take the guard offline over a question the stdlib cannot answer
    there. Saying so is the third option, and it is the one taken.

    On POSIX this returns () -- the real checks run and say everything.
    Never raises.
    """
    if not is_windows(windows, platform):
        return ()
    notes = []
    try:
        ok, text = describe_permissions(pointer, windows=windows, platform=platform)
        notes.append("pointer %s: %s" % (pointer, text))
        if not ok:
            notes.append("pointer %s could not be shown to be private; it is "
                         "still followed, and this line is the warning" % pointer)
    except Exception:
        notes.append("pointer %s: permissions could not be described" % pointer)
    notes.append(
        "Windows pointer trust: CHECKED that it is a regular file, that the "
        "recorded path is absolute and that the target exists; NOT CHECKED "
        "owner uid or a POSIX mode, because Windows has neither. Privacy here "
        "rests on the per-user ACL of %APPDATA%, not on a mode.")
    return tuple(notes)
