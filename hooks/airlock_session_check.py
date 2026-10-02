#!/usr/bin/env python3
"""SessionStart hook: tell the person, once, when the guard is not working.

WHY THIS EXISTS
===============

Airlock fails open by design, everywhere. That is the right default and it has
one consequence: a DEAD guard is silent. No key, TypeSafe unreachable, the
health timer stopped, the daemon down with a slow fallback -- every one of
those looks exactly like a quiet, well-behaved machine.

A server can be watched from outside: a push monitor alerts when the pushes
stop. A WORKSTATION cannot. Silence from a laptop almost always means the
laptop is off, so any monitor that alerts on silence is a monitor that cries
wolf every evening and gets muted within a week.

So the workstation answer is not a push. It is to tell the person at the one
moment they are certainly there and certainly care: when they start using
Claude Code. That is this hook.

WHAT IT PROMISES
================

  - It only READS local state. No network call, ever -- not even a cheap one.
  - A hard budget of 300 ms. Past it, it stops collecting and emits whatever
    it already has.
  - Fail-open discipline, identical to the guard's: any exception anywhere
    means exit 0 with nothing printed. A broken session check must never be
    the reason a session starts badly.
  - SILENCE WHEN HEALTHY. Nothing is printed on a working machine. A check
    that speaks when there is nothing to say is a check people learn to skip.

THE OUTPUT CONTRACT
===================

Quoting the hooks reference in the installed Claude Code CLI, under
"Hook JSON Output" -> "Fields":

    `systemMessage` - Display a message to the user (all hooks)

and, of `hookSpecificOutput` ("Event-specific output (must include
`hookEventName`)"):

    `additionalContext` - Text injected into model context

So the two audiences get different things, deliberately:

  - the USER gets `systemMessage`. That is the whole point: a person, at the
    moment they start work, told in plain words that the guard is not
    judging. Never more than three lines, and the second line is the one
    command that shows detail.
  - the MODEL gets one line of `hookSpecificOutput.additionalContext`, so it
    can answer "is airlock working?" without having to go and look.

WHAT IT WARNS ABOUT, AND WHAT IT DELIBERATELY DOES NOT
======================================================

One warning per session at most, the most serious one, in this order:

  1. the kill switch is present, or the mode is `off` -- informational, so
     at most once per DAY rather than the usual six hours. Somebody turned
     the guard off on purpose; the only failure mode worth catching is
     forgetting they did.
  2. no API key resolves: the guard is installed and judging nothing.
  3. the last health row is `down` or `degraded`, naming the check that
     failed, taken from the row itself rather than guessed.
  4. the health check has not run recently -- but ONLY when all three of
     these hold, because each one on its own produces a false alarm:
       * the last row is older than 15 minutes, AND
       * the machine has been up for more than 15 minutes (a fresh boot has
         not had time to run one, and the timer's own OnBootSec is 2 min),
         AND
       * a health timer is actually installed (a no-systemd install, or a
         Windows box without the scheduled task, has nothing to be stale).
     If uptime cannot be read at all, this warning is not raised -- an
     unknown uptime is not evidence of staleness.
  5. where there is NO health timer, the cheap local checks stand in for it:
     the key resolves, the mode, and the deployed release pointer resolving
     to a real hook. Never the network probe: that is the timer's job and it
     is not worth 300 ms of somebody's session start.
  6. the last tuning run is `could_not_run`, and only when tuning is
     installed.

DE-DUPLICATION
==============

The same warning is shown at most once every six hours per machine (24 hours
for the informational one), recorded in `session_check.json` under the state
directory, mode 600, written under the same whole-file lock
`airlock/state.py` uses so concurrent sessions cannot corrupt it. A warning
whose TEXT CHANGES -- a different failed check, a different reason -- is shown
immediately, because "the problem moved" is news even inside the window.
"""
import json
import os
import sys
import time

HOOK_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HOOK_DIR)

# Same sys.path surgery as hooks/airlock.py, and for the same reason: this
# file sits beside `airlock.py` in hooks/, so a bare `import airlock` run as a
# script would find that file rather than the package.
for _p in (HOOK_DIR, ""):
    while _p in sys.path:
        sys.path.remove(_p)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

#: Hard wall-clock budget. Nothing here may take longer than this.
BUDGET_S = 0.300
#: A health row older than this is stale...
STALE_AFTER_S = 15 * 60
#: ...but only on a machine that has been up at least this long.
MIN_UPTIME_S = 15 * 60
#: How often the same warning may be repeated.
REPEAT_AFTER_S = 6 * 3600
#: How often the informational one (off / kill switch) may be repeated.
INFO_REPEAT_AFTER_S = 24 * 3600
#: Forget a warning we have not seen for this long, to bound the state file.
FORGET_AFTER_S = 7 * 24 * 3600

STATE_FILE_NAME = "session_check.json"
HEALTH_LOG_NAME = "health.jsonl"
TUNE_LOG_NAME = "tune_log.jsonl"
TUNE_COULD_NOT_RUN = "could_not_run"

DISABLE_VARS = ("AIRLOCK_DISABLE", "PLUMBLINE_DISABLE", "JEV_GUARD_DISABLE")


class Warning_:
    """One thing to say, with the key that de-duplicates it.

    `key` names what is wrong, not the wording, so a warning whose detail
    changes (a different failed check) counts as a new warning and is shown
    straight away, while one whose numbers drift (minutes since the last
    health row, a latency in an error string) does not.
    """

    def __init__(self, key, headline, command, repeat_s=REPEAT_AFTER_S):
        self.key = key
        self.headline = headline
        self.command = command
        self.repeat_s = repeat_s

    def lines(self):
        out = [self.headline]
        if self.command:
            out.append("  detail: %s" % self.command)
        return out[:3]

    def system_message(self):
        return "\n".join(self.lines())

    def additional_context(self):
        return ("airlock session check: %s The user has been shown this at "
                "session start; %s prints the detail."
                % (self.headline, self.command or "install/doctor.sh"))


# --- reading local state ------------------------------------------------------

def read_uptime_seconds(system=None, proc_uptime="/proc/uptime", ticks=None,
                        sysctl=None):
    """Seconds since boot, PORTABLY, or None when it cannot be known.

    None is a real answer and the caller must treat it as "no evidence": the
    staleness warning is suppressed entirely rather than guessed at.

      Linux    /proc/uptime, first field
      Windows  GetTickCount64() via ctypes, in milliseconds
      other    `sysctl -n kern.boottime` (macOS/BSD), parsed for sec=<n>

    Every input is injectable so the whole matrix is exercised from Linux.
    """
    try:
        if system is None:
            import platform as _platform
            system = _platform.system()
        system = (system or "").lower()

        if system == "windows":
            if ticks is None:
                import ctypes
                ticks = ctypes.windll.kernel32.GetTickCount64()
            return float(ticks) / 1000.0

        if system == "linux":
            with open(proc_uptime, "r") as f:
                return float(f.read().split()[0])

        # macOS / BSD: kern.boottime prints e.g.
        #   { sec = 1758200000, usec = 123456 } Fri Sep 19 ...
        if sysctl is None:
            import subprocess
            out = subprocess.run(["sysctl", "-n", "kern.boottime"],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, timeout=1)
            if out.returncode != 0:
                return None
            sysctl = out.stdout.decode("utf-8", "replace")
        text = sysctl or ""
        marker = "sec ="
        if marker not in text:
            marker = "sec="
        if marker not in text:
            return None
        tail = text.split(marker, 1)[1]
        digits = ""
        for ch in tail.strip():
            if ch.isdigit():
                digits += ch
            else:
                break
        if not digits:
            return None
        return max(0.0, time.time() - float(digits))
    except Exception:
        return None


def last_json_line(path, tail_bytes=65536):
    """The last parseable JSON object in a .jsonl file, or None.

    Reads only the tail, so a health log that has grown for months costs one
    seek and one small read. A corrupt or half-written final line is stepped
    over rather than raising -- the whole file being unreadable is simply
    "no row", which is the fail-open answer.
    """
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - tail_bytes), os.SEEK_SET)
            chunk = f.read()
    except Exception:
        return None
    try:
        lines = [ln for ln in chunk.decode("utf-8", "replace").splitlines() if ln.strip()]
    except Exception:
        return None
    for line in reversed(lines):
        try:
            row = json.loads(line)
        except Exception:
            continue
        if isinstance(row, dict):
            return row
    return None


def parse_ts(ts):
    """An ISO-8601 timestamp to epoch seconds, or None."""
    if not ts:
        return None
    try:
        import datetime
        dt = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


def failed_checks(row):
    """Which checks failed, IN THE ROW'S OWN WORDS.

    Nothing here re-derives a verdict: the health check already decided, and
    saying something different at session start would make the two disagree
    on the same machine. This only reads the row.
    """
    out = []
    if not isinstance(row, dict):
        return out
    for name, label in (("daemon_ping", "daemon ping"),
                        ("daemon_ask", "a real judgement through the daemon"),
                        ("direct_ask", "a real judgement over HTTPS")):
        check = row.get(name)
        if isinstance(check, dict) and check.get("ok") is False:
            reason = str(check.get("error") or "").strip()
            out.append("%s failed%s" % (label, (" (%s)" % reason[:80]) if reason else ""))
    if row.get("key_loadable") is False:
        out.append("no API key resolves")
    last_hour = row.get("last_hour")
    if isinstance(last_hour, dict):
        rate = last_hour.get("fail_open_rate")
        if isinstance(rate, (int, float)) and rate > 0.20:
            out.append("fail-open rate %d%% in the last hour" % round(rate * 100))
    return out


def failed_check_names(row):
    """The same checks as failed_checks(), named without their reason text or
    the rate. This is what the de-dup key is built from: an error string that
    carries a latency, or a fail-open rate that moves by a point, is the same
    warning and must not count as news on every session start."""
    out = []
    if not isinstance(row, dict):
        return out
    for name in ("daemon_ping", "daemon_ask", "direct_ask"):
        check = row.get(name)
        if isinstance(check, dict) and check.get("ok") is False:
            out.append(name)
    if row.get("key_loadable") is False:
        out.append("key_loadable")
    last_hour = row.get("last_hour")
    if isinstance(last_hour, dict):
        rate = last_hour.get("fail_open_rate")
        if isinstance(rate, (int, float)) and rate > 0.20:
            out.append("fail_open_rate")
    return out


def kill_switch_path(paths_mod, environ=None):
    """The kill switch that is actually in force, or None.

    Checked exactly the way hooks/airlock.py checks it, INCLUDING both legacy
    config directories: a machine that turned the guard off under an older
    name is still off, and reporting otherwise would be a lie.
    """
    environ = os.environ if environ is None else environ
    for var in DISABLE_VARS:
        if environ.get(var) == "1":
            return "$%s=1" % var
    candidates = [str(paths_mod.config_dir() / "disabled")]
    for legacy_app in paths_mod.LEGACY_APPS:
        candidates.append(os.path.expanduser("~/.config/%s/disabled" % legacy_app))
    for path in candidates:
        try:
            if os.path.exists(path):
                return path
        except Exception:
            continue
    return None


def health_timer_installed(paths_mod, windows=None, unit_dir=None, task_query=None):
    """Is something actually scheduled to run the health check?

    Linux: the systemd user unit file exists. Windows: the Task Scheduler
    entry exists, which costs a `schtasks /Query` subprocess -- so it is only
    ever asked for once the cheap staleness arithmetic has already said the
    row is old.
    """
    try:
        from airlock.platform_compat import is_windows
        if is_windows(windows):
            if task_query is None:
                import subprocess
                out = subprocess.run(["schtasks", "/Query", "/TN", "airlock-health"],
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, timeout=2)
                return out.returncode == 0
            return bool(task_query())
        base = unit_dir or os.path.expanduser("~/.config/systemd/user")
        return os.path.exists(os.path.join(base, "airlock-health.timer"))
    except Exception:
        return False


def tuning_installed(paths_mod, unit_dir=None):
    """Tuning is opt-in, so its "could not run" is only news where it is on."""
    try:
        base = unit_dir or os.path.expanduser("~/.config/systemd/user")
        if os.path.exists(os.path.join(base, "airlock-tune.timer")):
            return True
        return os.path.exists(str(paths_mod.config_dir() / "tune.env"))
    except Exception:
        return False


def release_pointer_ok(paths_mod):
    """Does the deployed release pointer resolve to a real hook?

    True/False/None, where None means "nothing is deployed", which is a
    perfectly ordinary state for somebody running out of a checkout and is
    never warned about.
    """
    try:
        root = paths_mod.install_home()
        current = os.path.join(str(root), "current")
        target = current if os.path.isdir(current) else None
        if target is None:
            try:
                with open(os.path.join(str(root), "current.txt"), "r") as f:
                    recorded = f.read().strip()
                target = recorded if recorded and os.path.isdir(recorded) else None
            except Exception:
                target = None
        if target is None:
            if os.path.exists(current) or os.path.exists(os.path.join(str(root), "current.txt")):
                return False  # a pointer exists and does not resolve
            return None       # nothing deployed at all
        return os.path.isfile(os.path.join(target, "hooks", "airlock.py"))
    except Exception:
        return None


def doctor_command(paths_mod, windows=None, repo_root=REPO_ROOT):
    """The ONE command that shows detail, as an absolute path.

    The deployed release if there is one, because that is the copy actually
    running; otherwise this checkout.
    """
    try:
        from airlock.platform_compat import is_windows
        win = is_windows(windows)
    except Exception:
        win = False
    root = repo_root
    try:
        current = os.path.join(str(paths_mod.install_home()), "current")
        if os.path.isdir(current):
            root = current
        else:
            with open(os.path.join(str(paths_mod.install_home()), "current.txt")) as f:
                recorded = f.read().strip()
            if recorded and os.path.isdir(recorded):
                root = recorded
    except Exception:
        pass
    if win:
        return 'py -3 "%s"' % os.path.join(root, "install", "windows_doctor.py")
    return os.path.join(root, "install", "doctor.sh")


# --- collecting the facts -----------------------------------------------------

def collect_facts(deadline=None, environ=None, windows=None, now=None):
    """Every local fact the decision needs, gathered inside the budget.

    Returns a plain dict so `choose_warning` can be a pure function and the
    whole condition matrix can be tested without a machine in any particular
    state.
    """
    from airlock import mode as mode_mod
    from airlock import paths as paths_mod

    now = time.time() if now is None else now
    facts = {
        "mode": "shadow", "kill_switch": None, "key_ok": True,
        "health_row": None, "health_age_s": None, "uptime_s": None,
        "health_timer": False, "release_ok": None,
        "tuning_installed": False, "tune_category": None,
        "doctor": doctor_command(paths_mod, windows=windows),
    }

    def over():
        return deadline is not None and time.monotonic() > deadline

    try:
        facts["kill_switch"] = kill_switch_path(paths_mod, environ=environ)
    except Exception:
        pass
    try:
        facts["mode"] = mode_mod.resolve_mode()
    except Exception:
        facts["mode"] = "unknown"

    if over():
        return facts

    try:
        from airlock import keyfile
        facts["key_ok"] = bool(keyfile.get_api_key())
    except Exception:
        facts["key_ok"] = False

    if over():
        return facts

    state_dir = paths_mod.state_dir()
    row = last_json_line(os.path.join(str(state_dir), HEALTH_LOG_NAME))
    facts["health_row"] = row
    if isinstance(row, dict):
        ts = parse_ts(row.get("ts"))
        if ts is not None:
            facts["health_age_s"] = max(0.0, now - ts)

    if over():
        return facts

    # Staleness is the expensive branch (uptime, then possibly a subprocess on
    # Windows), so it is only entered once the cheap arithmetic says the row
    # really is old -- or missing entirely.
    stale = facts["health_age_s"] is None or facts["health_age_s"] > STALE_AFTER_S
    if stale:
        facts["uptime_s"] = read_uptime_seconds()
        facts["health_timer"] = health_timer_installed(paths_mod, windows=windows)
        if not facts["health_timer"]:
            facts["release_ok"] = release_pointer_ok(paths_mod)
    else:
        facts["health_timer"] = True

    if over():
        return facts

    try:
        facts["tuning_installed"] = tuning_installed(paths_mod)
        if facts["tuning_installed"]:
            tune_row = last_json_line(os.path.join(str(state_dir), TUNE_LOG_NAME))
            if isinstance(tune_row, dict):
                facts["tune_category"] = tune_row.get("category")
    except Exception:
        pass

    return facts


def choose_warning(facts):
    """The single most serious thing worth saying, or None for silence.

    One warning, never a list: a session start that opens with a wall of text
    is one the reader skips, and the doctor is one command away for the rest.
    """
    doctor = facts.get("doctor") or "install/doctor.sh"

    kill = facts.get("kill_switch")
    if kill:
        return Warning_(
            "off:killswitch:%s" % kill,
            "airlock is switched off by the kill switch (%s), so it is judging "
            "nothing." % kill,
            doctor, repeat_s=INFO_REPEAT_AFTER_S)

    if facts.get("mode") == "off":
        return Warning_(
            "off:mode",
            "airlock mode is `off`, so it is judging nothing.",
            doctor, repeat_s=INFO_REPEAT_AFTER_S)

    if not facts.get("key_ok"):
        return Warning_(
            "nokey",
            "airlock has no API key, so it is judging nothing (the code-only "
            "rules still fire).",
            doctor)

    row = facts.get("health_row")
    status = row.get("status") if isinstance(row, dict) else None
    if status in ("down", "degraded"):
        reasons = failed_checks(row)
        detail = "; ".join(reasons) if reasons else "no failing check named in the row"
        return Warning_(
            "health:%s:%s" % (status, ",".join(failed_check_names(row))),
            "airlock health is %s: %s." % (status, detail),
            doctor)

    age = facts.get("health_age_s")
    uptime = facts.get("uptime_s")
    if (age is None or age > STALE_AFTER_S):
        if facts.get("health_timer"):
            # Uptime unknown is NO evidence: say nothing rather than guess.
            if uptime is not None and uptime > MIN_UPTIME_S:
                if age is None:
                    when = "has never run"
                else:
                    when = "last ran %d minutes ago" % int(age // 60)
                # The key leaves the minutes out: they change on every
                # session start, so keying on them showed this every time.
                return Warning_(
                    "stale:never" if age is None else "stale:old",
                    "airlock's health check %s, so its health timer may have "
                    "stopped." % when,
                    doctor)
        elif facts.get("release_ok") is False:
            # No timer to be stale, so the local stand-in check speaks instead.
            return Warning_(
                "release",
                "airlock's deployed release pointer does not resolve to a hook, "
                "so the guard may not be running at all.",
                doctor)

    if facts.get("tuning_installed") and facts.get("tune_category") == TUNE_COULD_NOT_RUN:
        return Warning_(
            "tune:could_not_run",
            "airlock's last tuning run could not run at all, so tuning is "
            "changing nothing.",
            doctor)

    return None


# --- de-duplication -----------------------------------------------------------

def _state_path(paths_mod):
    return str(paths_mod.state_dir() / STATE_FILE_NAME)


def should_show(state, key, repeat_s, now):
    """Show it if it is DIFFERENT from last time, or if the window has passed.

    "Different" beats the window on purpose: a machine whose failing check
    changes from "daemon ping" to "no API key" has news, and making the
    person wait six hours to hear it would be the wrong trade.
    """
    if not isinstance(state, dict):
        return True
    if state.get("last_key") != key:
        return True
    shown = state.get("shown")
    if not isinstance(shown, dict):
        return True
    ts = shown.get(key)
    if not isinstance(ts, (int, float)) or ts > now:
        # A stamp from the future (the clock stepped back) proves nothing.
        return True
    return (now - ts) >= repeat_s


def _prune(state, now):
    shown = state.get("shown")
    if isinstance(shown, dict):
        for k in list(shown.keys()):
            ts = shown.get(k)
            if not isinstance(ts, (int, float)) or (now - ts) > FORGET_AFTER_S:
                del shown[k]
    return state


def check_and_record(paths_mod, key, repeat_s, now=None):
    """Atomically decide whether to show `key` and record that we did.

    Held under the SAME whole-file lock airlock/state.py uses, so two sessions
    starting at once cannot both read the old state, both decide to show, and
    then both write. Any failure at all means "show it": a de-duplicator that
    fails closed would swallow the one message this component exists to send.
    """
    from pathlib import Path

    from airlock import platform_compat, state as state_mod

    now = time.time() if now is None else now
    path = _state_path(paths_mod)
    try:
        fd = state_mod.open_locked(Path(path), platform_compat.LOCK_EXCLUSIVE)
    except Exception:
        return True

    try:
        state = state_mod.load(fd)
        show = should_show(state, key, repeat_s, now)
        if show:
            if not isinstance(state.get("shown"), dict):
                state["shown"] = {}
            state["shown"][key] = now
            state["last_key"] = key
            _prune(state, now)
            try:
                state_mod.save(fd, state)
            except Exception:
                pass
        return show
    finally:
        try:
            state_mod.close(fd)
        except Exception:
            pass
        try:
            platform_compat.restrict_path(path, 0o600)
        except Exception:
            pass


# --- entry point --------------------------------------------------------------

def build_output(warning):
    """The exact JSON object Claude Code reads. See the module docstring for
    the two quoted lines of the contract this implements."""
    return {
        "systemMessage": warning.system_message(),
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": warning.additional_context(),
        },
    }


def run(argv=None, stdin=None):
    """Returns the JSON string to print, or None for silence. Never raises."""
    start = time.monotonic()
    deadline = start + BUDGET_S
    try:
        from airlock import paths as paths_mod
        facts = collect_facts(deadline=deadline)
        warning = choose_warning(facts)
        if warning is None:
            return None
        if not check_and_record(paths_mod, warning.key, warning.repeat_s):
            return None
        return json.dumps(build_output(warning))
    except Exception:
        return None


def main():
    # Drain stdin if something is piping an event at us, so the writer never
    # sees an early EPIPE. The payload itself is not needed: this hook reports
    # on the machine, not on the session.
    try:
        if not sys.stdin.isatty():
            sys.stdin.read()
    except Exception:
        pass
    out = run()
    if out:
        sys.stdout.write(out + "\n")
    return 0


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
