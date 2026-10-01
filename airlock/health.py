#!/usr/bin/env python3
"""python3 -m airlock.health -- one-shot health check for airlock.

On Windows there is no daemon at all -- no AF_UNIX, so no socket to ping --
and the two daemon checks report `skipped` rather than `down`. In their place
one real Jev call goes out over the direct HTTPS path the Windows client
always uses, which is the thing actually worth proving there.

Checks, inside a 5s overall budget:
  - the daemon's Unix socket answers {"op": "ping"}   (POSIX only)
  - one real Jev call succeeds THROUGH THE DAEMON specifically (a tiny noul
    probe question, not client.ask()'s daemon-then-fallback path, so a
    dead daemon can't be masked by a silent fallback to a direct HTTPS call)
  - the API key is loadable (never printed, never logged)
  - the resolved mode (shadow/enforce/off)
  - from the last hour of ~/.local/state/airlock/shadow.jsonl: how many
    rows were actually judged (a real Jev call, not a Job-1 skip), how many
    fail-opened (an "error" field), the fail-open rate, how many looked like
    a deny, and p95 latency
  - the auto-tune loop's configured interval and how long since it last ran

Exit 0 healthy, 1 degraded, 2 down. Prints exactly one JSON line to stdout,
always -- even on a partial failure, best-effort fields are still reported.
Never raises past main(); any single check's own exception is caught and
turned into that check's failure, not a crash of the whole probe.
"""
import datetime
import json
import socket
import sys
import time

from . import keyfile, paths
from . import mode as mode_mod
from .client import MODEL, _DAEMON_TIMED_OUT, _ask_via_daemon, _daemon_socket_path
from .client import ask as client_ask
from .log import LOG_FILE
from .platform_compat import has_unix_sockets

BUDGET_S = 5.0
FAIL_OPEN_RATE_DEGRADED = 0.20

STATE_DIR = paths.state_dir()
TUNE_STATE_FILE = STATE_DIR / "tune_state.json"

# A minimal noul question: cheapest possible real Jev call, used only to
# prove the daemon-to-TypeSafe path actually works end to end.
_PROBE_QUESTIONS = {
    "health_probe": {
        "type": "noul",
        "instructions": (
            "This is an automated health check, not a real judgement task. "
            "Always answer false."
        ),
        "criteria": {
            "true": "Never applies to a health probe.",
            "false": "Always the correct answer for a health probe.",
        },
    }
}


def _now():
    return time.monotonic()


def check_daemon_ping(deadline):
    """Does the daemon's Unix socket answer {"op": "ping"}? Returns
    {"ok": bool, "latency_ms": int, "error": str (only when not ok)}."""
    remaining = max(0.1, deadline - _now())
    path = _daemon_socket_path()
    start = time.monotonic()
    sock = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(min(remaining, 2.0))
        sock.connect(path)
        sock.sendall((json.dumps({"op": "ping"}) + "\n").encode("utf-8"))
        f = sock.makefile("rb")
        line = f.readline()
        latency_ms = int((time.monotonic() - start) * 1000)
        if not line:
            return {"ok": False, "error": "empty response from daemon socket", "latency_ms": latency_ms}
        resp = json.loads(line.decode("utf-8"))
        ok = bool(resp.get("ok") and resp.get("pong"))
        return {"ok": ok, "latency_ms": latency_ms}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200], "latency_ms": int((time.monotonic() - start) * 1000)}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def check_daemon_ask(deadline):
    """One real Jev call through the daemon specifically (not client.ask()'s
    daemon-then-direct-HTTPS fallback -- a fallback here would silently mask
    a dead daemon as "healthy")."""
    remaining = max(0.2, deadline - _now())
    start = time.monotonic()
    try:
        body = {
            "state": {"probe": "automated airlock health check, not a real judgement"},
            "model": MODEL,
            "questions": _PROBE_QUESTIONS,
        }
        result = _ask_via_daemon(body, timeout_s=remaining)
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200], "latency_ms": int((time.monotonic() - start) * 1000)}
    wall_latency_ms = int((time.monotonic() - start) * 1000)
    if result is None:
        return {"ok": False, "error": "no daemon response (down, refused, or malformed)", "latency_ms": wall_latency_ms}
    if result is _DAEMON_TIMED_OUT:
        return {"ok": False, "error": "daemon timed out waiting for TypeSafe", "latency_ms": wall_latency_ms}
    _response, reported_latency_ms, _reused = result
    return {"ok": True, "latency_ms": reported_latency_ms or wall_latency_ms}


def check_key_loadable():
    """True/False only -- never the key itself."""
    try:
        return bool(keyfile.get_api_key())
    except Exception:
        return False


def check_mode():
    try:
        return mode_mod.resolve_mode()
    except Exception:
        return "unknown"


def _load_log_rows():
    rows = []
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return rows


def _parse_ts(ts):
    if not ts:
        return None
    try:
        return datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None


def _percentile(values, pct):
    if not values:
        return 0.0
    values = sorted(values)
    k = (len(values) - 1) * pct
    lo = int(k)
    hi = min(lo + 1, len(values) - 1)
    if lo == hi:
        return values[lo]
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def _row_was_judged(row):
    """A real Jev call happened for this row -- as opposed to a Job-1
    no-deny-possible skip, which never calls Jev and carries neither
    "answers" nor "latency_ms"."""
    return "answers" in row or ("latency_ms" in row and "error" not in row)


def summarize_last_hour(rows=None, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(hours=1)
    rows = _load_log_rows() if rows is None else rows

    recent = []
    for r in rows:
        t = _parse_ts(r.get("ts"))
        if t is not None and t >= cutoff:
            recent.append(r)

    total = len(recent)
    judged = sum(1 for r in recent if _row_was_judged(r))
    fail_open = sum(1 for r in recent if r.get("error"))
    denies = sum(1 for r in recent if r.get("would_deny") or r.get("enforced"))
    latencies = [r.get("latency_ms") for r in recent if isinstance(r.get("latency_ms"), (int, float))]
    fail_open_rate = round(fail_open / total, 3) if total else 0.0

    return {
        "total_rows": total,
        "judged": judged,
        "fail_open": fail_open,
        "fail_open_rate": fail_open_rate,
        "denies": denies,
        "p95_latency_ms": round(_percentile(latencies, 0.95), 1),
    }


def check_tune_state():
    try:
        data = json.loads(TUNE_STATE_FILE.read_text())
    except Exception:
        return {"interval_min": None, "last_run_age_s": None}
    interval_min = data.get("interval_min")
    last_run_epoch = data.get("last_run_epoch")
    age_s = None
    if last_run_epoch:
        try:
            age_s = int(time.time() - int(last_run_epoch))
        except Exception:
            age_s = None
    return {"interval_min": interval_min, "last_run_age_s": age_s}


def check_direct_ask(deadline):
    """One real Jev call over whatever transport client.ask() picks.

    This is the Windows stand-in for check_daemon_ask: there is no daemon to
    isolate there, so the honest thing to prove is that the direct HTTPS path
    the Windows client always takes actually reaches TypeSafe. Skipped, not
    failed, when there is no API key -- a keyless install is a supported,
    fail-open configuration."""
    remaining = max(0.2, deadline - _now())
    start = time.monotonic()
    if not check_key_loadable():
        return {"ok": None, "skipped": "no API key; the guard fails open and judges nothing",
                "latency_ms": None}
    try:
        body = {
            "state": {"probe": "automated airlock health check, not a real judgement"},
            "model": MODEL,
            "questions": _PROBE_QUESTIONS,
        }
        _response, latency_ms = client_ask(body, timeout_s=remaining)
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200],
                "latency_ms": int((time.monotonic() - start) * 1000)}
    return {"ok": True, "latency_ms": latency_ms or int((time.monotonic() - start) * 1000)}


def run_health_check(windows=None):
    """Run every check inside the overall budget and return (status,
    result_dict). Never raises -- every check catches its own exceptions."""
    start_wall = time.monotonic()
    deadline = start_wall + BUDGET_S
    daemon_supported = has_unix_sockets(windows)

    if daemon_supported:
        try:
            ping = check_daemon_ping(deadline)
        except Exception as exc:
            ping = {"ok": False, "error": str(exc)[:200], "latency_ms": None}

        if ping.get("ok"):
            try:
                ask = check_daemon_ask(deadline)
            except Exception as exc:
                ask = {"ok": False, "error": str(exc)[:200], "latency_ms": None}
        else:
            ask = {"ok": False, "error": "skipped: daemon ping failed", "latency_ms": None}
        direct = None
    else:
        skip = {"ok": None, "skipped": "no unix-socket daemon on this platform",
                "latency_ms": None}
        ping = dict(skip)
        ask = dict(skip)
        try:
            direct = check_direct_ask(deadline)
        except Exception as exc:
            direct = {"ok": False, "error": str(exc)[:200], "latency_ms": None}

    key_ok = check_key_loadable()
    mode_val = check_mode()
    last_hour = summarize_last_hour()
    tune_state = check_tune_state()

    if daemon_supported:
        if not ping.get("ok"):
            status = "down"
        elif not ask.get("ok") or not key_ok or last_hour["fail_open_rate"] > FAIL_OPEN_RATE_DEGRADED:
            status = "degraded"
        else:
            status = "healthy"
    else:
        # No daemon to be down: the hook itself is the service, and it is
        # proved by the doctor's real deny, not from here. A missing key or a
        # failed direct call is degraded, never down.
        if direct is not None and direct.get("ok") is False or not key_ok or last_hour["fail_open_rate"] > FAIL_OPEN_RATE_DEGRADED:
            status = "degraded"
        else:
            status = "healthy"

    result = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": status,
        "daemon_supported": daemon_supported,
        "daemon_ping": ping,
        "daemon_ask": ask,
        "key_loadable": key_ok,
        "mode": mode_val,
        "last_hour": last_hour,
        "tune_state": tune_state,
        "wall_s": round(time.monotonic() - start_wall, 3),
    }
    if direct is not None:
        result["direct_ask"] = direct
    return status, result


_EXIT_CODES = {"healthy": 0, "degraded": 1, "down": 2}


def main():
    try:
        status, result = run_health_check()
    except Exception as exc:
        # Should be unreachable (run_health_check swallows per-check
        # exceptions), but a monitoring script must never crash uncaught.
        result = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "down",
            "error": str(exc)[:200],
        }
        print(json.dumps(result, default=str))
        return 2

    print(json.dumps(result, default=str))
    return _EXIT_CODES.get(status, 2)


if __name__ == "__main__":
    sys.exit(main())
