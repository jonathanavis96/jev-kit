"""Read the TypeSafe API key without ever printing it.

The hook process usually will NOT have TYPESAFE_API_KEY in its environment
(Claude Code hooks inherit a minimal env), so this falls back to parsing a key
file for a `TYPESAFE_API_KEY=` line. Never logs, never echoes, never shells out
to read the file (no cat/curl with the key on a command line) -- plain Python
file I/O only.

RESOLUTION ORDER -- the one place it is written down
====================================================

Everything that needs the key resolves it in exactly this order. There is one
implementation per language and no third copy: `airlock/keyfile.py` for Python
(the guard, the daemon, the health check, the eval, and the native-Windows
installer and doctor) and `install/keyfile.sh` for the shell (the installer,
the belay wrapper, the health-check wrapper, the compaction installer). Change
the order here and there, together, or not at all.

  1. `TYPESAFE_API_KEY` in the environment. No file is read at all.
  2. `AIRLOCK_KEY_FILE`, then `JEVKIT_KEY_FILE` (then the legacy
     `PLUMBLINE_KEY_FILE`, `JEV_GUARD_KEY_FILE`) -- an explicit override,
     honoured as given.
  3. the KIT default, if it exists.
  4. the GUARD-ERA default, if it exists. Still fully honoured: an existing
     install keeps working with no action at all.
  5. the path recorded in the POINTER FILE `$AIRLOCK_CONFIG_DIR/keyfile.path`,
     if the pointer passes the checks below.
  6. each path in `AIRLOCK_LEGACY_KEY_FILES` (colon-separated), in order.
  7. otherwise the kit default, whether or not it exists. If it does not,
     there is no key, and every guard fails open and judges nothing.

Steps 3 and 4 are per-platform, and only the spelling differs:

                 kit default (3)          guard-era default (4)
  POSIX          ~/.config/jev-kit/env    ~/.config/airlock/env
  Windows        %APPDATA%\\jev-kit\\env    %APPDATA%\\airlock\\env

The Windows pair goes through `paths.kit_config_dir()` and
`paths.config_dir()`, so `JEVKIT_CONFIG_DIR`, `AIRLOCK_CONFIG_DIR` and the
guard's legacy-name fallback all still apply there. The POSIX pair is
deliberately kept as the two literal paths below rather than being derived
from `config_dir()`: deriving it would make a machine that still has only a
`~/.config/plumbline` directory resolve its key somewhere the old code never
looked.

Why the kit default is not under the guard's directory
------------------------------------------------------

One `TYPESAFE_API_KEY` is read by every component in the kit -- the guard, the
belay wrapper, compaction, the document classifier, log triage, the browser
agent and the review wrapper. A key that every component reads does not belong
in any single component's config directory, so the kit-level default is
`~/.config/jev-kit/env` (`%APPDATA%\\jev-kit\\env` on Windows). Everything that
is genuinely the guard's own -- the mode file, `rules.json`, `tiers.json`, the
kill switch, the state and release directories -- stays under `airlock/`.

Why a pointer file at all
-------------------------

A hook runs with a bare environment and never sources `install/config.env`, so
a machine that keeps its key somewhere other than the default has no way to
tell the hook where. `install/install.sh` (and `install/windows_install.py`)
writes the PATH of the key file (only ever the path, never the value) into
`$AIRLOCK_CONFIG_DIR/keyfile.path`, and step 5 reads it.

That makes the pointer a security-relevant file: whoever can write it chooses
which file this process parses for a secret, and R1 in `airlock/rules.py`
protects whatever it names. So it is trusted only when:

  * the pointer file is a regular file (not a symlink, not a fifo), owned by
    the current uid, and not group- or world-writable;
  * its directory is owned by the current uid and not group- or world-writable
    (a writable directory means the pointer can be replaced wholesale);
  * the recorded path is ABSOLUTE after `~` expansion -- a relative path would
    resolve against whatever directory the hook happened to start in;
  * the recorded path is an existing regular file.

Any check failing means the pointer is ignored and resolution carries on at
step 6, exactly as if the pointer did not exist. Nothing raises, nothing
blocks. The reason is recorded in `pointer_diagnostics()` (path names and
permission bits only, never file contents) so `install/doctor.sh` can say why
a pointer is not being honoured; with `AIRLOCK_DEBUG=1` it also goes to stderr.

A world-READABLE target is a warning, not a rejection: the key is still the
one the machine intends to use, and refusing it would take the guard offline
over a permission the human can fix in one command.

The ownership and mode halves of that list are POSIX checks, and Windows has
neither a uid nor a meaningful `st_mode`. There, the two structural checks
still run (regular file; absolute, existing target) and the two permission
checks are replaced by `platform_compat.pointer_trust_notes()`, which records
what was checked and what was not instead of pretending the check passed. The
pointer is then followed: refusing every pointer on Windows would take the
guard offline over a question the stdlib cannot answer there, and claiming the
ownership check passed would be a lie. The diagnostics say which of the two
happened, and `install/windows_doctor.py` prints them.
"""
import os
import stat

from . import paths, platform_compat
from .platform_compat import is_windows

ENV_VAR = "TYPESAFE_API_KEY"

# The kit-level default is deliberately machine-neutral, so a fresh machine
# needs no config at all. Every component in the kit reads the same key, so it
# does not live under the guard's own directory.
DEFAULT_ENV_FILE = "~/.config/jev-kit/env"

# The default from when the kit was only the guard. Still honoured, in full and
# for good: an install that already has its key here keeps working with no
# action. Never remove it, and never stop R1 protecting it.
GUARD_ENV_FILE = "~/.config/airlock/env"

# Every default the POSIX resolution order consults, newest first. Use
# default_env_files(), which answers for the running platform.
DEFAULT_ENV_FILES = (DEFAULT_ENV_FILE, GUARD_ENV_FILE)

# A one-line file holding the PATH of the key file, never its contents.
POINTER_FILE = "keyfile.path"

# Extra key-file paths this machine wants honoured, colon-separated, from
# AIRLOCK_LEGACY_KEY_FILES in install/config.env. Empty on a fresh machine.
LEGACY_ENV_VAR = "AIRLOCK_LEGACY_KEY_FILES"

DEBUG_ENV = "AIRLOCK_DEBUG"

# Group- or world-writable bits. Either on a pointer file (or its directory)
# means somebody other than the owner can choose which file we parse.
_WRITABLE_BY_OTHERS = stat.S_IWGRP | stat.S_IWOTH

_DIAGNOSTICS = []


def _note(message):
    """Record why something about the pointer was refused or is worth saying.

    Paths and permission bits only. A file's CONTENTS never reach here, so a
    diagnostic can always be printed safely.
    """
    try:
        if message not in _DIAGNOSTICS:
            _DIAGNOSTICS.append(message)
        if os.environ.get(DEBUG_ENV) == "1":
            import sys
            sys.stderr.write("airlock keyfile: %s\n" % message)
    except Exception:
        pass


def pointer_diagnostics():
    """Everything _note() has recorded in this process, oldest first."""
    return tuple(_DIAGNOSTICS)


def reset_diagnostics():
    del _DIAGNOSTICS[:]


def default_env_files(windows=None):
    """Steps 3 and 4 for this platform: the kit default, then the guard-era
    default. Never raises.

    POSIX returns the two literal paths above, unchanged. Windows returns
    %APPDATA%\\jev-kit\\env and the guard's own config directory + `env`, so an
    AIRLOCK_CONFIG_DIR override and the legacy-name fallback still apply to
    the second one.
    """
    if not is_windows(windows):
        return DEFAULT_ENV_FILES
    out = []
    for resolver in (paths.kit_config_dir, paths.config_dir):
        try:
            out.append(str(resolver(windows=windows) / "env"))
        except Exception:
            continue
    return tuple(out)


def pointer_file_path():
    """Absolute path of the pointer file, whether or not it exists, or None if
    even the config directory cannot be resolved. Never raises."""
    try:
        return str(paths.config_file(POINTER_FILE))
    except Exception:
        return None


def _owned_and_unwritable(st, what, where):
    """True iff `st` is owned by this uid and not group/world writable.

    POSIX only; `pointer_target` calls it only where `os.getuid()` exists.
    """
    try:
        if st.st_uid != os.getuid():
            _note("ignoring pointer: %s %s is owned by uid %d, not %d"
                  % (what, where, st.st_uid, os.getuid()))
            return False
        if st.st_mode & _WRITABLE_BY_OTHERS:
            _note("ignoring pointer: %s %s is group- or world-writable (mode %o)"
                  % (what, where, stat.S_IMODE(st.st_mode)))
            return False
    except Exception:
        return False
    return True


def pointer_target(check=True, windows=None):
    """The path recorded in the pointer file, or None.

    With `check` true (the default, and what resolution uses) every trust check
    in the module docstring must pass. With `check` false the recorded path is
    returned whether or not it is trustworthy -- R1 uses that, because a
    pointer we refuse to FOLLOW still names a file that must not be printed
    into a transcript. Never raises.
    """
    try:
        pointer = pointer_file_path()
    except Exception:
        return None
    if not pointer:
        return None
    try:
        st = os.lstat(pointer)
    except Exception:
        return None

    win = is_windows(windows)

    if check:
        if not stat.S_ISREG(st.st_mode):
            _note("ignoring pointer: %s is not a regular file" % pointer)
            return None
        if win:
            # No uid, no meaningful mode. Say what was and was not checked
            # rather than pretending the POSIX check passed.
            for line in platform_compat.pointer_trust_notes(pointer, windows=windows):
                _note(line)
        else:
            if not _owned_and_unwritable(st, "pointer file", pointer):
                return None
            parent = os.path.dirname(pointer) or "."
            try:
                link_st = os.lstat(parent)
                # The directory a symlink leads to is what holds the pointer,
                # so it is what gets checked. A symlink's own mode is always
                # 777 on Linux, and checking that rejected every config dir
                # reached through one (migrate-to-airlock.sh leaves them).
                dir_st = os.stat(parent)
            except Exception:
                return None
            if stat.S_ISLNK(link_st.st_mode) and link_st.st_uid != os.getuid():
                _note("ignoring pointer: pointer directory %s is a symlink owned by uid %d, not %d"
                      % (parent, link_st.st_uid, os.getuid()))
                return None
            if not _owned_and_unwritable(dir_st, "pointer directory", parent):
                return None

    try:
        with open(pointer, "r") as f:
            recorded = f.readline().strip()
    except Exception:
        return None
    if not recorded or recorded.startswith("#"):
        return None
    try:
        target = os.path.expanduser(recorded)
    except Exception:
        return None
    if not target:
        return None

    if check:
        if not os.path.isabs(target):
            _note("ignoring pointer: recorded path %r is not absolute" % target)
            return None
        try:
            target_st = os.stat(target)
        except FileNotFoundError:
            # A pointer to a file that is not there yet is not an error: the
            # human may not have created the key file. Fall through quietly.
            _note("pointer names %s, which does not exist; falling back" % target)
            return None
        except Exception:
            return None
        if not stat.S_ISREG(target_st.st_mode):
            _note("ignoring pointer: %s is not a regular file" % target)
            return None
        if win:
            # st_mode on Windows is synthesised and S_IROTH is always set on
            # a readable file, so testing it would emit a warning about every
            # key file on every machine. Ask the platform instead.
            try:
                ok, text = platform_compat.describe_permissions(target, windows=windows)
                if not ok:
                    _note("key file %s: %s" % (target, text))
            except Exception:
                pass
        elif target_st.st_mode & stat.S_IROTH:
            # Warn only: it is still the key file this machine means to use.
            _note("key file %s is world-readable (mode %o); chmod 600 it"
                  % (target, stat.S_IMODE(target_st.st_mode)))
    return target


def legacy_env_files():
    """Extra key-file paths from the environment. Never raises."""
    raw = paths.env(LEGACY_ENV_VAR, default="")
    if not raw:
        return ()
    return tuple(part for part in raw.split(os.pathsep) if part.strip())


def default_env_file(windows=None):
    """Steps 3 to 7: the key file to read when no *_KEY_FILE override is set.
    Never raises."""
    candidates = default_env_files(windows=windows)
    generic = os.path.expanduser(candidates[0]) if candidates else os.path.expanduser(DEFAULT_ENV_FILE)
    try:
        for candidate in candidates:
            expanded = os.path.expanduser(candidate)
            if os.path.isfile(expanded):
                return expanded
        recorded = pointer_target(windows=windows)
        if recorded:
            return recorded
        for legacy in legacy_env_files():
            candidate = os.path.expanduser(legacy)
            if os.path.isfile(candidate):
                return candidate
    except Exception:
        pass
    return generic


def key_file(windows=None):
    """Steps 2 to 7, resolved NOW rather than at import time.

    Resolving per call is what makes a pointer written after a release was
    deployed take effect: the daemon is long-lived, and `ENV_FILE` below froze
    the answer at import. It is one or two stat calls, on a path that already
    does file I/O.
    """
    override = paths.env("AIRLOCK_KEY_FILE", "JEVKIT_KEY_FILE",
                         "PLUMBLINE_KEY_FILE", "JEV_GUARD_KEY_FILE")
    if override:
        try:
            return os.path.expanduser(override)
        except Exception:
            return override
    return default_env_file(windows=windows)


# Kept for anything that imports the constant. Prefer key_file().
ENV_FILE = key_file()


def get_env_value(name):
    """Return `name` from the environment, else from the key file, else None.

    The key file is a plain `NAME=value` env file, so anything else a
    component needs beside the TypeSafe key can live there too and be found
    by the same resolution order. Never raises."""
    try:
        value = os.environ.get(name)
        if value:
            return value
    except Exception:
        pass

    try:
        path = key_file()
    except Exception:
        path = ENV_FILE

    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):].strip()
                if not line.startswith(name + "="):
                    continue
                value = line.split("=", 1)[1].strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]
                return value or None
    except Exception:
        return None
    return None


def get_api_key():
    """Return the API key string, or None if it cannot be found. Never raises."""
    return get_env_value(ENV_VAR)
