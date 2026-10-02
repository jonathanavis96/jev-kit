"""Thin HTTP client for the TypeSafe /v1/systemone endpoint.

Standard library only (urllib), so the hook has no dependency to install.
Never puts the API key on a command line: it goes in an Authorization header
built in-process, never through a subprocess or shell.
"""
import json
import socket
import time
import urllib.error
import urllib.request
import uuid

from . import keyfile, paths
from .platform_compat import has_unix_sockets

API_URL = "https://api.typesafe.ai/v1/systemone"
MODEL = "jev-latest"
DEFAULT_TIMEOUT = 5

DAEMON_CONNECT_TIMEOUT = 0.2


def _daemon_socket_path():
    """$XDG_RUNTIME_DIR/airlock/airlock.sock, falling back to the old
    jev-guard socket ($XDG_RUNTIME_DIR/jev/jev.sock) when only that one is
    present -- a daemon started before the rename keeps serving hooks from a
    renamed release until someone restarts it. See airlock/paths.py."""
    return paths.runtime_socket()


class TypeSafeError(Exception):
    pass


# The daemon reached TypeSafe but the answer did not arrive within timeout_s.
# The budget is spent and the request was billed, so ask() raises rather than
# sending the same request again directly.
_DAEMON_TIMED_OUT = object()


def call_jev(api_key, state, questions, timeout=DEFAULT_TIMEOUT):
    """POST one evaluation request. Returns (response_dict, latency_ms).

    Raises TypeSafeError (or a urllib/socket error) on any failure; callers
    are expected to catch broadly and fail open.
    """
    body = json.dumps({"state": state, "model": MODEL, "questions": questions}).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=body,
        method="POST",
        headers={
            "Authorization": "Bearer %s" % api_key,
            "Content-Type": "application/json",
        },
    )
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        latency_ms = int((time.monotonic() - start) * 1000)
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        raise TypeSafeError("HTTP %s: %s" % (exc.code, detail)) from None
    latency_ms = int((time.monotonic() - start) * 1000)
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise TypeSafeError("bad JSON response: %s" % exc) from None
    if not isinstance(data, dict):
        raise TypeSafeError("response is not a JSON object: %s" % type(data).__name__)
    return data, latency_ms


def _ask_via_daemon(body, timeout_s, windows=None):
    """Try the warm daemon connection. Returns (response_dict, latency_ms) on
    success, or None on anything at all -- missing socket, refused
    connection, malformed reply, daemon-reported failure -- so the caller can
    fall back to a direct call without ever seeing an exception from here.

    On Windows this returns None immediately and costs nothing: there is no
    AF_UNIX there, the daemon is out of scope, and `ask()` goes straight to
    the direct HTTPS call (about 0.9 s cold rather than about 0.3 s warm).
    Checking up front rather than letting `socket.AF_UNIX` raise an
    AttributeError into the blanket except below means the skip is a
    deliberate, documented decision instead of a swallowed error."""
    if not has_unix_sockets(windows):
        return None
    path = _daemon_socket_path()
    sock = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(DAEMON_CONNECT_TIMEOUT)
        sock.connect(path)
        sock.settimeout(timeout_s + 0.5)
        req = {"id": uuid.uuid4().hex, "body": body, "timeout_s": timeout_s}
        sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
        f = sock.makefile("rb")
        try:
            line = f.readline()
        except socket.timeout:
            # The daemon has the request and has used up the whole budget on
            # it, so it may already be billed. A direct call now would bill
            # it again and double the wait the hook is already over.
            return _DAEMON_TIMED_OUT
        if not line:
            return None
        resp = json.loads(line.decode("utf-8"))
        if not resp.get("ok"):
            if resp.get("timed_out"):
                return _DAEMON_TIMED_OUT
            return None
        return resp.get("response"), resp.get("latency_ms", 0), resp.get("reused_connection", False)
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def ask(body, timeout_s=DEFAULT_TIMEOUT, windows=None):
    """Preferred entry point for every caller. Tries the warm daemon socket
    first (connect timeout 0.2s); if the socket is missing, refuses, or
    errors in any way, falls back to the direct HTTPS call (call_jev) so
    behaviour is unchanged when the daemon isn't running. The one exception
    is a daemon that reports TypeSafe itself timed out: that raises
    TypeSafeError, because a direct retry would double both the wait and the
    bill for a judgement the budget has already given up on. `body` is the exact
    TypeSafe request body: {"state":..., "model":..., "questions":...}.

    Returns (response_dict, latency_ms), same shape as call_jev. Never raises
    beyond what call_jev already raises on the fallback path -- the daemon
    path itself never propagates an exception.

    On Windows the daemon step is skipped outright (see _ask_via_daemon), so
    every judgement is the direct HTTPS call.
    """
    via_daemon = _ask_via_daemon(body, timeout_s, windows=windows)
    if via_daemon is _DAEMON_TIMED_OUT:
        raise TypeSafeError("timed out after %ss (via daemon)" % timeout_s)
    if via_daemon is not None:
        response, latency_ms, _reused = via_daemon
        return response, latency_ms

    api_key = keyfile.get_api_key()
    if not api_key:
        # Without this the request went out as "Bearer None", spent the budget
        # on a round trip and was logged as an HTTP 401 from TypeSafe.
        raise TypeSafeError("no API key (%s not found)" % keyfile.ENV_VAR)
    return call_jev(api_key, body.get("state"), body.get("questions"), timeout=timeout_s)
