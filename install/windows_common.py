#!/usr/bin/env python3
"""Shared machinery for the native-Windows installer, doctor and uninstaller.

The Linux installer is bash. Windows has no bash unless Git for Windows is
there, and the whole point of a native install is not to require it, so the
Windows side is Python -- which the guard already is.

The one design decision worth reading before anything else is how `current`
works, because Windows does not hand out symlink privilege to an ordinary
user and the Linux installer's atomic symlink flip is therefore not available.

WHAT WE DO INSTEAD, AND WHY
---------------------------
Two mechanisms, in this order:

1. A **directory junction** (`mklink /J`). A junction needs no privilege at
   all -- unlike a symlink, which needs Developer Mode or an elevated shell --
   and once made, `...\\airlock\\current\\hooks\\airlock.py` is a path that just
   works, exactly like the Linux symlink. It is the preferred mechanism.
   It has two limits: it is NTFS-only, and it cannot cross to a network
   location.

2. A **text pointer**, `current.txt`, holding the absolute path of the live
   release. Always written, junction or not, because it is the thing that
   cannot fail: no filesystem feature, no privilege, no volume type.

The hook registered in settings.json points at neither. It points at a small
stable launcher, `airlock-hook.py`, written once into the install home. The
launcher resolves `current.txt` first, then the junction, and runs the
real hook IN THE SAME PROCESS, so there is no second interpreter start-up to
pay for. That keeps settings.json stable across every deploy and rollback: a
rollback rewrites one line of `current.txt` and the next tool call picks it
up, which is the same promise the Linux symlink makes.

The SessionStart session check gets its own launcher, `airlock-session-check.py`,
written the same way and for the same reason. Two launchers rather than one
launcher with an argument: a hook command in settings.json is a string a human
reads, and `"py.exe" "...\airlock-session-check.py"` says what it is, where
`"py.exe" "...\airlock-hook.py" session-check` says almost nothing and invites
a re-wire to drop the argument.

Nothing here ever needs Administrator, writes outside the user's profile, or
touches the registry, a service, or PATH.
"""
import datetime
import json
import os
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from airlock import paths
from airlock.platform_compat import is_windows

LAUNCHER_NAME = "airlock-hook.py"
SESSION_LAUNCHER_NAME = "airlock-session-check.py"
POINTER_NAME = "current.txt"
CURRENT_NAME = "current"
RELEASES_NAME = "releases"
KEEP_RELEASES = 5
TASK_NAME = "airlock-health"

# Files and directories a release copy does NOT need. Keeping the release
# small keeps the deploy fast and keeps a stray .git out of %LOCALAPPDATA%.
EXCLUDE_NAMES = {
    ".git", ".github", "graphify-out", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".venv", "node_modules",
}


# --- the launcher ------------------------------------------------------------

LAUNCHER_TEMPLATE = '''#!/usr/bin/env python3
"""Stable entry point for the airlock %(what)s on Windows.

settings.json points here and never at a release directory, so a deploy or a
rollback never has to touch settings.json: it rewrites the `current` pointer
beside this file and the next tool call follows it.

Resolution order:
  1. `current.txt`, a one-line file holding the release path, which always
     works because it needs no filesystem feature and no privilege. It comes
     first because it is what a rollback edits: read second, the junction
     would win and the rollback would do nothing;
  2. the `current` directory junction, if the installer managed to make one.

The real hook is then run IN THIS PROCESS (runpy, __name__ == "__main__"), so
the indirection costs one small file read rather than a second interpreter
start-up. Fail-open like everything else: if the pointer is missing or broken
this exits 0 having printed nothing, which Claude Code reads as "allow".
"""
import os
import runpy
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _release_root():
    try:
        with open(os.path.join(HERE, "current.txt"), "r") as f:
            recorded = f.read().strip()
    except Exception:
        recorded = ""
    if recorded and os.path.isdir(recorded):
        return recorded
    junction = os.path.join(HERE, "current")
    if os.path.isdir(junction):
        return junction
    return None


def main():
    root = _release_root()
    if not root:
        return
    hook = os.path.join(root, "hooks", "%(script)s")
    if not os.path.isfile(hook):
        return
    if root not in sys.path:
        sys.path.insert(0, root)
    runpy.run_path(hook, run_name="__main__")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        pass
    sys.exit(0)
'''

#: Kept as its own name because install/windows_uninstall.py and the tests
#: both reference "the PreToolUse launcher source" specifically.
LAUNCHER_SOURCE = LAUNCHER_TEMPLATE % {
    "what": "PreToolUse hook", "script": "airlock.py"}
SESSION_LAUNCHER_SOURCE = LAUNCHER_TEMPLATE % {
    "what": "SessionStart session check", "script": "airlock_session_check.py"}


# --- small helpers -----------------------------------------------------------

def stamp():
    return datetime.datetime.now().strftime("%Y%m%dT%H%M%S")


def backup(path):
    """Copy `path` to a timestamped sibling and return the new path."""
    target = "%s.bak.%s" % (path, stamp())
    shutil.copy2(path, target)
    return target


def run(argv, timeout=60):
    """Run a command, return (returncode, combined output). Never raises."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()
    except Exception as exc:
        return 1, str(exc)[:300]


def install_root(env=None):
    """%LOCALAPPDATA%\\airlock (or $AIRLOCK_HOME), the parent of releases\\,
    current and the launcher."""
    return str(paths.install_home())


def launcher_path(env=None):
    return os.path.join(install_root(env), LAUNCHER_NAME)


def session_launcher_path(env=None):
    return os.path.join(install_root(env), SESSION_LAUNCHER_NAME)


def pointer_path(env=None):
    return os.path.join(install_root(env), POINTER_NAME)


def current_path(env=None):
    return os.path.join(install_root(env), CURRENT_NAME)


def resolve_current(env=None):
    """The live release directory, or None. Same order the launcher uses:
    `current.txt` first, since that is what a rollback edits."""
    try:
        with open(pointer_path(env), "r") as f:
            recorded = f.read().strip()
    except Exception:
        recorded = ""
    if recorded and os.path.isdir(recorded):
        return recorded
    junction = current_path(env)
    return junction if os.path.isdir(junction) else None


# --- the Python interpreter to put in the hook command ------------------------

def find_python(env=None):
    """An ABSOLUTE interpreter path for the hook command.

    A hook runs with a minimal environment, so `python` on PATH is not a
    promise. Windows also has no `python3` at all: what it has is the `py`
    launcher in System32, and whatever python.exe an install put on PATH --
    where it is frequently the Microsoft Store alias stub, which is why
    `sys.executable` is preferred over both when this script is itself
    running under a real interpreter.
    """
    env = os.environ if env is None else env
    candidates = []
    explicit = env.get("AIRLOCK_PYTHON")
    if explicit:
        candidates.append(explicit)
    exe = sys.executable
    if exe and os.path.isfile(exe) and "windowsapps" not in exe.lower():
        candidates.append(exe)
    windir = env.get("SystemRoot") or env.get("WINDIR") or "C:\\Windows"
    candidates.append(os.path.join(windir, "py.exe"))
    for entry in (env.get("PATH") or "").split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry or "windowsapps" in entry.lower():
            continue
        candidates.append(os.path.join(entry, "python.exe"))
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


# --- which shell will run the hook command ------------------------------------

def find_git_bash(env=None):
    """Git Bash, if it is installed.

    It decides the SHAPE of the hook command. Claude Code's settings
    reference: a command hook's shell "Defaults to `bash`, or to `powershell`
    on Windows when Git Bash isn't installed." A bare `"a" "b"` is a valid
    command in bash and is NOT one in PowerShell, where it parses as a string
    expression -- PowerShell needs the call operator, `& "a" "b"`. So the two
    forms are mutually exclusive and the installer picks by detection.
    """
    env = os.environ if env is None else env
    explicit = env.get("CLAUDE_CODE_GIT_BASH_PATH")
    if explicit and os.path.isfile(explicit):
        return explicit
    for base in (env.get("ProgramFiles"), env.get("ProgramFiles(x86)"),
                 env.get("LOCALAPPDATA")):
        if not base:
            continue
        for tail in ("Git\\bin\\bash.exe", "Git\\usr\\bin\\bash.exe",
                     "Programs\\Git\\bin\\bash.exe"):
            candidate = os.path.join(base, tail)
            if os.path.isfile(candidate):
                return candidate
    return None


def quote(path):
    """Quote a path for a hook command string. Always quoted, even without a
    space: a profile directory with a space in it is common enough
    (`C:\\Users\\Jane Smith`) that making the quoting conditional would mean
    two shapes to get right instead of one."""
    return '"%s"' % path


def hook_command(python_exe, launcher, git_bash=None):
    """The exact string that goes in settings.json.

    With Git Bash:      "<py>" "<launcher>"
    Without Git Bash:   & "<py>" "<launcher>"     (PowerShell's call operator)
    """
    body = "%s %s" % (quote(python_exe), quote(launcher))
    return body if git_bash else "& " + body


# --- settings.json -----------------------------------------------------------

def default_settings_files(env=None):
    """%USERPROFILE%\\.claude\\settings.json, plus any settings.local.json
    beside it. Nothing is guessed beyond that; extra paths are passed on the
    command line, exactly as install/wire.sh does on Linux."""
    env = os.environ if env is None else env
    home = env.get("USERPROFILE") or os.path.expanduser("~")
    claude = os.path.join(home, ".claude")
    out = [os.path.join(claude, "settings.json")]
    local = os.path.join(claude, "settings.local.json")
    if os.path.isfile(local):
        out.append(local)
    return out


def wire(settings_files, hook_path, hook_cmd, apply=True, env=None,
         session_hook_path=None, session_hook_cmd=None):
    """Wire (or repoint) the PreToolUse hook, through install/_wire.py.

    _wire.py is the file that knows how to edit a settings.json without
    reformatting it, how to back it up first, and how to be idempotent. This
    just hands it the Windows-shaped values through the environment it reads,
    exactly as install/wire.sh hands it the Linux ones.
    """
    import importlib

    child_env = dict(os.environ if env is None else env)
    child_env["NEW_HOOK"] = hook_path
    child_env["NEW_HOOK_COMMAND"] = hook_cmd
    child_env["APPLY"] = "1" if apply else "0"
    child_env["BELAY"] = "0"
    child_env["FUNCTION_HOOKS"] = "0"
    child_env["HOOK_COMMAND_QUOTED"] = "1"
    # The SessionStart session check, in the SAME quoted Windows shape (with
    # PowerShell's call operator where there is no Git Bash) -- so both hooks
    # are registered in one edit, one backup, and one idempotency check.
    child_env["SESSION_CHECK"] = "1" if session_hook_path else "0"
    child_env["SESSION_CHECK_HOOK"] = session_hook_path or ""
    child_env["SESSION_CHECK_COMMAND"] = session_hook_cmd or session_hook_path or ""

    old = dict(os.environ)
    os.environ.clear()
    os.environ.update(child_env)
    try:
        wire_mod = importlib.import_module("_wire") if os.path.dirname(
            os.path.abspath(__file__)) in sys.path else None
        if wire_mod is None:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            wire_mod = importlib.import_module("_wire")
        importlib.reload(wire_mod)
        changed = []
        for path in settings_files:
            parent = os.path.dirname(path)
            if parent and not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)
            changed.append((path, wire_mod.process(path)))
        return changed
    finally:
        os.environ.clear()
        os.environ.update(old)


# --- Task Scheduler ----------------------------------------------------------

def health_task_command(python_exe, release_root):
    """The command a scheduled health check runs. `-m airlock.health` from
    the release root, so it follows a deploy."""
    return '%s -m airlock.health' % quote(python_exe)


def create_health_task(python_exe, release_root, name=TASK_NAME):
    """Register an hourly health check with Task Scheduler.

    Created ONLY when the installer is given --schedule-health explicitly.
    A scheduled task is a machine-level change that outlives the session that
    made it, so it is never on by default, exactly as `--wire` is not.
    """
    argv = [
        "schtasks", "/Create", "/F",
        "/TN", name,
        "/SC", "HOURLY",
        "/TR", '%s -m airlock.health' % quote(python_exe),
        "/RL", "LIMITED",
    ]
    code, out = run(argv)
    return code == 0, out


def delete_health_task(name=TASK_NAME):
    code, out = run(["schtasks", "/Delete", "/F", "/TN", name])
    return code == 0, out


def health_task_exists(name=TASK_NAME):
    code, _out = run(["schtasks", "/Query", "/TN", name])
    return code == 0


# --- release deployment -------------------------------------------------------

def copy_release(source, dest):
    """Copy the repository into a release directory, minus the noise."""
    def ignore(_dir, names):
        return [n for n in names if n in EXCLUDE_NAMES]
    shutil.copytree(source, dest, ignore=ignore)
    # copytree copies the SOURCE directory's mtime onto dest, so every release
    # carried the checkout's mtime and prune_releases could not tell new from
    # old. Stamp it now.
    os.utime(dest, None)
    return dest


def make_junction(link, target):
    """Try a directory junction. Returns (ok, how) where `how` is one of
    'junction' or a short reason it could not be made. No privilege is
    required for a junction, unlike a symlink -- but it is NTFS-only, so this
    is allowed to fail and the text pointer carries on regardless."""
    if os.path.isdir(link) or os.path.islink(link):
        code, _ = run(["cmd", "/c", "rmdir", link])
        if code != 0 and os.path.isdir(link):
            return False, "could not remove the existing %s" % link
    code, out = run(["cmd", "/c", "mklink", "/J", link, target])
    if code == 0 and os.path.isdir(link):
        return True, "junction"
    return False, (out or "mklink failed")


def write_pointer(root, release_dir):
    path = os.path.join(root, POINTER_NAME)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(release_dir + "\n")
    os.replace(tmp, path)
    return path


def write_launcher(root, name=LAUNCHER_NAME, source=None):
    path = os.path.join(root, name)
    with open(path, "w") as f:
        f.write(LAUNCHER_SOURCE if source is None else source)
    return path


def write_session_launcher(root):
    return write_launcher(root, SESSION_LAUNCHER_NAME, SESSION_LAUNCHER_SOURCE)


def prune_releases(releases_dir, keep=KEEP_RELEASES, current=None):
    """Keep the newest `keep` releases, never deleting the live one."""
    try:
        entries = [os.path.join(releases_dir, n) for n in os.listdir(releases_dir)]
    except Exception:
        return []
    entries = [e for e in entries if os.path.isdir(e)]
    # The name (a stamp() timestamp) breaks ties: releases copied before
    # copy_release reset the mtime all share the checkout's.
    entries.sort(key=lambda p: (os.path.getmtime(p), os.path.basename(p)), reverse=True)
    pruned = []
    current_real = os.path.normcase(os.path.abspath(current)) if current else None
    for old in entries[keep:]:
        if current_real and os.path.normcase(os.path.abspath(old)) == current_real:
            continue
        try:
            shutil.rmtree(old)
            pruned.append(old)
        except Exception:
            continue
    return pruned


# --- reporting ---------------------------------------------------------------

def require_windows(what):
    """These scripts install a Windows hook command into a Windows
    settings.json. Running them on Linux would write nonsense, so they say so
    and stop -- except under AIRLOCK_FORCE_WINDOWS_INSTALL=1, which the unit
    tests set to exercise the whole path against a temporary directory."""
    if is_windows() or os.environ.get("AIRLOCK_FORCE_WINDOWS_INSTALL") == "1":
        return True
    sys.stderr.write(
        "%s is the NATIVE WINDOWS installer and this is not Windows.\n"
        "  On Linux, WSL or macOS use install/install.sh instead.\n" % what)
    return False


def print_json(obj):
    print(json.dumps(obj, indent=2, default=str))
