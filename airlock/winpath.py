"""Windows path shapes, as a Claude Code session on Windows actually emits them.

There are three spellings of the same directory in play at once on a native
Windows machine, and the guard sees all three:

  C:\\Users\\alice\\code    the Windows spelling. `tool_input.file_path` always
                          arrives like this, even when the hook itself is
                          running under Git Bash (Claude Code's hooks
                          reference says so explicitly).
  /c/Users/alice/code     the MSYS spelling Git Bash uses for `$PWD` and for
                          anything the model types at a Bash prompt. Git for
                          Windows is the documented way to get the Bash tool
                          on native Windows, so this is the common case.
  /cygdrive/c/Users/...   the Cygwin spelling, accepted for completeness.

Every one of them has to compare equal, and on Windows the comparison itself
is case-insensitive: `C:\\USERS\\Alice` and `c:\\users\\alice` are one
directory. This module reduces all of that to a single canonical form --
uppercase drive letter, backslash separators, no trailing separator except on
a bare drive root -- and answers the two questions airlock/scope.py needs:
is this path a drive root, and are these two paths the same place?

Nothing here touches the filesystem, so it is safe to call on a Linux box
about a Windows path that does not exist there, which is exactly what the
Windows unit tests do.
"""
import os
import re

# "/c/..." or bare "/c"
_MSYS_DRIVE_RE = re.compile(r"^/([A-Za-z])(?=/|$)")
# "/cygdrive/c/..." or bare "/cygdrive/c"
_CYGDRIVE_RE = re.compile(r"^/cygdrive/([A-Za-z])(?=/|$)")
# "C:" at the start of a Windows path
_DRIVE_RE = re.compile(r"^([A-Za-z]):")
# A whole path that is nothing but a drive root: "C:", "C:\", "C:\\\\"
_DRIVE_ROOT_RE = re.compile(r"^[A-Za-z]:\\?$")
# A UNC share root: "\\\\server\\share" with nothing after it
_UNC_ROOT_RE = re.compile(r"^\\\\[^\\]+\\[^\\]+\\?$")

# %VAR% and $env:VAR, the two ways a Windows path variable gets written in a
# command line Claude Code might issue.
_PERCENT_VAR_RE = re.compile(r"%([A-Za-z_][A-Za-z_0-9()]*)%")
_PS_ENV_VAR_RE = re.compile(r"\$env:([A-Za-z_][A-Za-z_0-9]*)", re.IGNORECASE)


def looks_windows_path(path):
    """True for a string that is unambiguously a Windows or MSYS path.

    Used to decide whether a root extracted from a command line should be
    canonicalised as Windows rather than left as POSIX; a Git Bash session on
    Windows mixes both in the same command.
    """
    if not path:
        return False
    s = str(path)
    return bool(
        _DRIVE_RE.match(s)
        or _CYGDRIVE_RE.match(s)
        or _MSYS_DRIVE_RE.match(s)
        or s.startswith("\\\\")
        or "\\" in s
    )


def canonical(path):
    """One canonical spelling for a Windows path. Never raises.

    Uppercase drive letter, backslash separators, repeated separators
    collapsed, trailing separator dropped except on a bare drive root or a
    UNC share root. A path that is not recognisably Windows (a plain POSIX
    path such as `/home/x`) comes back with separators normalised and
    nothing else assumed.
    """
    if path is None:
        return ""
    s = str(path).strip().strip('"').strip("'")
    if not s:
        return ""

    m = _CYGDRIVE_RE.match(s)
    if m:
        s = m.group(1) + ":" + s[len("/cygdrive/") + 1:]
    else:
        m = _MSYS_DRIVE_RE.match(s)
        if m:
            s = m.group(1) + ":" + s[2:]

    s = s.replace("/", "\\")

    unc = s.startswith("\\\\")
    head = "\\\\" if unc else ""
    body = s[2:] if unc else s
    while "\\\\" in body:
        body = body.replace("\\\\", "\\")
    s = head + body

    if _DRIVE_RE.match(s):
        s = s[0].upper() + s[1:]
        if len(s) == 2:
            return s + "\\"
        if _DRIVE_ROOT_RE.match(s):
            return s[:2] + "\\"

    if len(s) > 1 and s.endswith("\\") and not _UNC_ROOT_RE.match(s):
        s = s.rstrip("\\") or s[:1]
    return s


def same_path(a, b):
    """Are these two spellings the same directory? Case-insensitive, which is
    what Windows itself does."""
    return canonical(a).lower() == canonical(b).lower()


def is_drive_root(path):
    """`C:\\`, `C:`, `/c`, `/c/`, `/cygdrive/c` -- the whole of one volume.

    A search rooted here is disk-wide by definition, which is the Windows
    equivalent of a `find /` on Linux. A UNC share root counts too: it is
    somebody's whole file server.
    """
    c = canonical(path)
    # A bare separator is the root of whatever the current drive is -- what
    # `find / -name x` means when a Git Bash session on Windows types it.
    if c == "\\":
        return True
    return bool(_DRIVE_ROOT_RE.match(c) or _UNC_ROOT_RE.match(c))


def is_absolute(path):
    """True for `C:\\...`, `\\\\server\\share\\...` or a bare-rooted `\\...`."""
    c = canonical(path)
    if not c:
        return False
    if c.startswith("\\\\"):
        return True
    if c.startswith("\\"):
        return True
    return bool(_DRIVE_RE.match(c) and len(c) > 2 and c[2] == "\\") or bool(_DRIVE_ROOT_RE.match(c))


def is_under(path, parent):
    """True if `path` is `parent` or sits beneath it, case-insensitively."""
    p = canonical(path).lower()
    q = canonical(parent).lower()
    if not p or not q:
        return False
    if p == q:
        return True
    if not q.endswith("\\"):
        q += "\\"
    return p.startswith(q)


def expand_vars(text, env=None):
    """Expand `%VAR%` and `$env:VAR` against `env` (default os.environ).

    An unknown variable is left exactly as written rather than replaced with
    an empty string: turning `%NOPE%\\code` into `\\code` would silently
    change a single-directory search into something that looks rooted at a
    drive. Never raises.
    """
    if not text:
        return text
    env = os.environ if env is None else env

    def _percent(m):
        return str(env.get(m.group(1)) or m.group(0))

    def _psenv(m):
        for key in env:
            if key.lower() == m.group(1).lower():
                return str(env[key] or m.group(0))
        return m.group(0)

    try:
        return _PS_ENV_VAR_RE.sub(_psenv, _PERCENT_VAR_RE.sub(_percent, str(text)))
    except Exception:
        return text


def home(env=None):
    """The Windows user profile, canonicalised. `%USERPROFILE%` first (it is
    what Windows itself sets), then `%HOMEDRIVE%%HOMEPATH%`, then `$HOME`,
    which Git Bash sets and Windows does not."""
    env = os.environ if env is None else env
    profile = env.get("USERPROFILE")
    if not profile:
        drive, tail = env.get("HOMEDRIVE"), env.get("HOMEPATH")
        if drive and tail:
            profile = drive + tail
    if not profile:
        profile = env.get("HOME")
    return canonical(profile) if profile else ""
