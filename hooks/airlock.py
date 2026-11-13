#!/usr/bin/env python3
"""PreToolUse hook entry point for airlock.

Mode-dependent (see airlock/mode.py for resolution order: env
AIRLOCK_MODE, else the first word of ~/.config/airlock/mode, else
"shadow"):

- shadow (default): unchanged from the original shadow-only behaviour below
  -- never blocks, never prints anything, hands the real Jev judgement off to
  a detached background process (airlock/worker.py), and exits 0 with no
  stdout, well under 100ms.
- enforce: judges SYNCHRONOUSLY, in this process, through airlock/enforce.py
  (client.ask() under a hard budget -- AIRLOCK_BUDGET_MS, default 1500ms,
  2000ms on native Windows, where there is no warm daemon and every call is
  a fresh HTTPS connection; see airlock/enforce.py:budget_ms).
  A deny is the documented PreToolUse JSON on stdout with exit 0. Fail-open
  on any timeout, exception, or malformed answer.
- off: complete no-op, same as the kill switch.

Any exception anywhere in this file is swallowed silently -- a broken guard
can never block or slow a tool call it wasn't explicitly told to deny.

Kill switch: env AIRLOCK_DISABLE=1, or the file
~/.config/airlock/disabled existing, makes this file a complete no-op and
wins over mode entirely -- for every REAL caller. The one exception is the
A/B bench (bench/run.py): --settings merges additively with the account's
own settings.json rather than replacing it (confirmed empirically), and the
account's settings.json already registers the MAIN CHECKOUT's copy of this
same hook in shadow mode. Disabling that live copy for a bench trial the
ordinary way (AIRLOCK_DISABLE=1) would also disable THIS copy, since both
read the same kill switch -- so a bench trial that wants this worktree's copy
active in enforce mode sets env AIRLOCK_BENCH_FORCE_MODE=enforce, which
makes this copy skip the shared kill switch entirely and use that mode
directly. This is a narrow, explicitly-named escape hatch for benchmarking
only -- no production caller ever sets it, and it does nothing unless the
value is a valid mode.

Wiring note for the director: add this file's ABSOLUTE path (not "~/...") to
settings.json hooks.PreToolUse with matcher "*" (EVERY tool -- the rules table
in airlock/rules.py does the filtering in code, far cheaper than a regex
matcher could). A leading "~" in a hook command silently never runs on this
box.
"""
import json
import os
import sys

# subprocess and tempfile are imported lazily inside _spawn_shadow_worker:
# they cost several ms of start-up each and only shadow mode needs them, so
# the common "no rule matches" path must not pay for them.

HOOK_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HOOK_DIR)
WORKER = os.path.join(REPO_ROOT, "airlock", "worker.py")
BENCH_FORCE_VAR = "AIRLOCK_BENCH_FORCE_MODE"
LEGACY_BENCH_FORCE_VARS = ("PLUMBLINE_BENCH_FORCE_MODE", "JEV_GUARD_BENCH_FORCE_MODE")
DISABLE_VARS = ("AIRLOCK_DISABLE", "PLUMBLINE_DISABLE", "JEV_GUARD_DISABLE")
_VALID_MODES = ("shadow", "enforce", "off")

# This file is called `airlock.py` and the package is called `airlock`,
# so when Python runs it as a script sys.path[0] is hooks/ and a plain
# `import airlock` would find THIS file rather than the package. Dropping
# hooks/ and putting the repo root first makes that impossible. Nothing in
# this directory is ever imported.
for _p in (HOOK_DIR, ""):
    while _p in sys.path:
        sys.path.remove(_p)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _disable_files():
    """The kill-switch file under every config directory this project has ever
    used. A machine that has `~/.config/plumbline/disabled` or
    `~/.config/jev-guard/disabled` in place stays disabled after a rename;
    forgetting that would silently re-arm a guard someone turned off."""
    from airlock import paths
    out = [str(paths.config_dir() / "disabled")]
    for legacy_app in paths.LEGACY_APPS:
        legacy = os.path.expanduser("~/.config/%s/disabled" % legacy_app)
        if legacy not in out:
            out.append(legacy)
    return out


def _disabled():
    try:
        for var in DISABLE_VARS:
            if os.environ.get(var) == "1":
                return True
    except Exception:
        return True
    try:
        return any(os.path.exists(p) for p in _disable_files())
    except Exception:
        return True


def _resolve_mode():
    """Cheap, dependency-light mode lookup. Import is deferred so the common
    shadow/off path never has to pay for it if this ever grows dependencies;
    today airlock.mode is stdlib-only and effectively free."""
    try:
        from airlock.mode import resolve_mode
        return resolve_mode()
    except Exception:
        return "shadow"


def _spawn_shadow_worker(raw):
    """Original shadow-mode path: hand off to the detached worker and return
    immediately. Never raises."""
    import subprocess
    import tempfile

    from airlock import platform_compat

    path = None
    try:
        # mkstemp already creates the file 0600 on POSIX and inside the
        # per-user %TEMP% on Windows; restrict_path re-applies the mode on
        # POSIX and deliberately does nothing on Windows, where a POSIX mode
        # cannot express "owner only" (see airlock/platform_compat.py).
        fd, path = tempfile.mkstemp(prefix="airlock-", suffix=".json")
        platform_compat.restrict_path(path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(raw)
        # start_new_session=True on POSIX, DETACHED_PROCESS |
        # CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW on Windows. Either way
        # the worker outlives this process, which exits 0 immediately.
        subprocess.Popen(
            [sys.executable, WORKER, path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            **platform_compat.detached_popen_kwargs()
        )
    except Exception:
        if path:
            try:
                os.remove(path)
            except Exception:
                pass


def _read_stdin():
    """Read the hook payload as UTF-8, which is what Claude Code sends.

    Python decodes a piped stdin with the locale code page on native Windows
    (cp1252 and the like). A UTF-8 payload holding one character whose bytes
    that code page leaves undefined then raises, and the hook used to return
    without judging the call at all. Undecodable bytes become U+FFFD instead.
    """
    try:
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    return sys.stdin.read()


def main():
    try:
        raw = _read_stdin()
    except Exception:
        return

    try:
        data = json.loads(raw)
        tool_name = data.get("tool_name") or ""
        if not tool_name:
            return
    except Exception:
        return

    bench_force = os.environ.get(BENCH_FORCE_VAR)
    for _legacy in LEGACY_BENCH_FORCE_VARS:
        if bench_force:
            break
        bench_force = os.environ.get(_legacy)
    if bench_force in _VALID_MODES:
        mode = bench_force
    else:
        try:
            if _disabled():
                return
        except Exception:
            return
        mode = _resolve_mode()

    if mode == "off":
        return

    # All-tools registration: the rules table decides, in pure code and in
    # microseconds, whether any rule could possibly apply to this call. A call
    # no rule covers returns here -- no Jev request, no log row, no worker
    # subprocess -- so the added cost is Python start-up and nothing else.
    try:
        from airlock import rules as rules_mod
        ctx = rules_mod.build_ctx(data, tool_name)
        if not rules_mod.prefilter_matches(ctx):
            return
    except Exception:
        pass

    if mode == "enforce":
        try:
            from airlock import enforce
            enforce.handle(data, tool_name)
        except Exception:
            pass
        return

    # shadow (default, and the fallback for any unrecognised value)
    _spawn_shadow_worker(raw)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
