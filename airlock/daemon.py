#!/usr/bin/env python3
"""Local daemon that keeps a warm HTTPS connection to TypeSafe.

Callers on this box pay ~0.3s per judgement (reused TLS connection) instead
of ~0.9s (fresh DNS + TCP + TLS every call). Standard library only.

Listens on a Unix domain socket at $XDG_RUNTIME_DIR/airlock/airlock.sock
(fallback /run/user/<uid>/airlock/airlock.sock), directory mode 700,
socket mode 600 -- no TCP listener, so only this user can ever reach it. The
daemon always binds the NEW name; only a client falls back to the old
jev-guard socket, so a machine mid-cutover never ends up with two daemons
fighting over one path (see airlock/paths.py).

Protocol: one JSON object per line in, one JSON object per line out.
  Request:  {"id": "...", "body": {"state":..., "model":..., "questions":...}, "timeout_s": 5}
  Response: {"id": "...", "ok": true, "status": 200, "response": {...},
             "latency_ms": N, "reused_connection": true|false}
         or {"id": "...", "ok": false, "error": "...", "timed_out": true|absent}
  Also: {"op": "ping"} -> {"ok": true, "pong": true}
        {"op": "stats"} -> {"ok": true, "stats": {...}}

The daemon adds the Authorization header itself from the key it loads at
startup (same lookup as airlock.keyfile: env var, else the key env
file). Callers never see or send the key, and it is never logged, printed, or
returned over the socket.

Connection handling: a small pool (default 2, env AIRLOCK_DAEMON_POOL) of
persistent http.client.HTTPSConnection objects forced to IPv4 (IPv6 to some
providers is flaky from this host), each guarded by its own lock. On a
dropped connection (RemoteDisconnected, BrokenPipe, ConnectionReset, or any
other connection-level OSError) the pool reconnects and retries once. No
keepalive pinging -- that would spend TypeSafe tokens for nothing. Instead
TCP keepalive is enabled on the sockets, and a connection the server has
quietly closed while idle is simply detected as broken and replaced lazily
on the next use.
"""
import http.client
import itertools
import json
import os
import signal
import socket
import sys
import threading
import time
import urllib.parse
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from airlock import keyfile, paths, redact
from airlock.client import API_URL

_URL = urllib.parse.urlsplit(API_URL)
HOST = _URL.hostname
PORT = _URL.port or 443
PATH = _URL.path or "/v1/systemone"

DEFAULT_POOL_SIZE = int(paths.env("AIRLOCK_DAEMON_POOL", "JEV_DAEMON_POOL", default="2") or "2")
LISTEN_BACKLOG = 16
CONNECT_TIMEOUT = 5

# Exceptions that mean "this connection is dead, reconnect and retry once".
_RETRYABLE = (
    http.client.RemoteDisconnected,
    http.client.CannotSendRequest,
    http.client.BadStatusLine,
    ConnectionError,  # covers BrokenPipeError, ConnectionResetError
    OSError,
)

# socket.timeout is an OSError, so it has to be caught before _RETRYABLE.
_TIMEOUTS = (socket.timeout, TimeoutError)


def _socket_dir_and_path():
    d = paths.runtime_socket_dir()
    return d, os.path.join(d, "%s.sock" % paths.APP)


def _create_connection_ipv4(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
    """Like socket.create_connection, but restricted to AF_INET. IPv6 to some
    providers is flaky from this host, so every daemon connection forces v4."""
    host, port = address
    err = None
    for res in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM):
        af, socktype, proto, _canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if source_address:
                sock.bind(source_address)
            sock.connect(sa)
            return sock
        except OSError as exc:
            err = exc
            if sock is not None:
                sock.close()
    if err is not None:
        raise err
    raise OSError("getaddrinfo returned an empty list for %r" % (address,))


def new_https_connection(timeout_s):
    """Factory for one persistent, IPv4-forced HTTPS connection. Not connected
    until the first request -- http.client lazily connects on .request()."""
    conn = http.client.HTTPSConnection(HOST, PORT, timeout=timeout_s)
    conn._create_connection = _create_connection_ipv4
    return conn


class _Slot:
    __slots__ = ("conn", "lock")

    def __init__(self):
        self.lock = threading.Lock()
        self.conn = None


class ConnectionPool:
    """A small round-robin pool of persistent HTTPS connections, each guarded
    by its own lock so a busy connection blocks a new caller rather than two
    threads sharing one socket. `connection_factory` is injectable for tests."""

    def __init__(self, size=DEFAULT_POOL_SIZE, connection_factory=new_https_connection):
        size = max(1, int(size))
        self.slots = [_Slot() for _ in range(size)]
        self._factory = connection_factory
        self._rr = itertools.count()
        self._rr_lock = threading.Lock()

    def _pick(self):
        with self._rr_lock:
            i = next(self._rr)
        return self.slots[i % len(self.slots)]

    @staticmethod
    def _do(conn, path, body_bytes, headers, timeout_s):
        try:
            if getattr(conn, "sock", None) is not None:
                conn.sock.settimeout(timeout_s)
        except Exception:
            pass
        conn.request("POST", path, body=body_bytes, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        return resp.status, raw

    def request(self, path, body_bytes, headers, timeout_s):
        """Returns (status, raw_bytes, reused_connection_bool). Reconnects and
        retries exactly once if the connection turns out to be dead."""
        slot = self._pick()
        with slot.lock:
            reused = slot.conn is not None
            if slot.conn is None:
                slot.conn = self._factory(timeout_s)
            try:
                status, raw = self._do(slot.conn, path, body_bytes, headers, timeout_s)
                return status, raw, reused
            except _TIMEOUTS:
                # A timeout is a slow answer, not a dead connection: the POST
                # was already sent, so a retry would bill the same judgement
                # twice and double the wait. Drop the half-used connection
                # and let the caller fail open.
                try:
                    slot.conn.close()
                except Exception:
                    pass
                slot.conn = None
                raise
            except _RETRYABLE:
                try:
                    slot.conn.close()
                except Exception:
                    pass
                slot.conn = self._factory(timeout_s)
                status, raw = self._do(slot.conn, path, body_bytes, headers, timeout_s)
                return status, raw, False


class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self.start = time.monotonic()
        self.requests = 0
        self.errors = 0
        self.reused = 0
        self._latencies = deque(maxlen=2000)
        self.tokens_in = 0
        self.tokens_out = 0

    def record(self, latency_ms, reused, ok, tokens_in=0, tokens_out=0):
        with self._lock:
            self.requests += 1
            if not ok:
                self.errors += 1
            if reused:
                self.reused += 1
            self._latencies.append(latency_ms)
            self.tokens_in += tokens_in or 0
            self.tokens_out += tokens_out or 0

    def snapshot(self):
        with self._lock:
            lat = sorted(self._latencies)
            n = len(lat)
            mean = round(sum(lat) / n, 1) if n else 0
            p95 = lat[int(0.95 * (n - 1))] if n else 0
            reuse_rate = round(self.reused / self.requests, 3) if self.requests else 0.0
            return {
                "uptime_s": round(time.monotonic() - self.start, 1),
                "requests": self.requests,
                "errors": self.errors,
                "reuse_rate": reuse_rate,
                "latency_ms_mean": mean,
                "latency_ms_p95": p95,
                "tokens_in": self.tokens_in,
                "tokens_out": self.tokens_out,
            }


def _log(id_, status, latency_ms, reused, tokens_in, tokens_out):
    # stderr only, journald captures it. Never log the request body or the key.
    sys.stderr.write(
        "id=%s status=%s latency_ms=%s reused=%s tokens_in=%s tokens_out=%s\n"
        % (id_, status, latency_ms, reused, tokens_in, tokens_out)
    )
    sys.stderr.flush()


def _handle_ask(req, api_key, pool, stats):
    id_ = req.get("id")
    body = req.get("body") or {}
    timeout_s = req.get("timeout_s") or 5
    payload = json.dumps(body).encode("utf-8")
    headers = {
        "Authorization": "Bearer %s" % api_key,
        "Content-Type": "application/json",
    }
    start = time.monotonic()
    try:
        status, raw, reused = pool.request(PATH, payload, headers, timeout_s)
    except Exception as exc:
        latency_ms = int((time.monotonic() - start) * 1000)
        stats.record(latency_ms, False, ok=False)
        _log(id_, "error", latency_ms, False, 0, 0)
        reply = {"id": id_, "ok": False, "error": redact.redact(str(exc))[:300]}
        if isinstance(exc, _TIMEOUTS):
            # Tells the client the budget is already spent, so it must not
            # spend it a second time on a direct call.
            reply["timed_out"] = True
        return reply

    latency_ms = int((time.monotonic() - start) * 1000)

    if 200 <= status < 300:
        try:
            response = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            stats.record(latency_ms, reused, ok=False)
            _log(id_, status, latency_ms, reused, 0, 0)
            return {"id": id_, "ok": False, "error": "bad JSON response: %s" % exc}
        usage = response.get("usage") or {}
        tin = usage.get("input_tokens") or 0
        tout = usage.get("output_tokens") or 0
        stats.record(latency_ms, reused, ok=True, tokens_in=tin, tokens_out=tout)
        _log(id_, status, latency_ms, reused, tin, tout)
        return {
            "id": id_,
            "ok": True,
            "status": status,
            "response": response,
            "latency_ms": latency_ms,
            "reused_connection": reused,
        }

    detail = redact.redact(raw.decode("utf-8", "replace"))[:300]
    stats.record(latency_ms, reused, ok=False)
    _log(id_, status, latency_ms, reused, 0, 0)
    return {"id": id_, "ok": False, "error": "HTTP %s: %s" % (status, detail)}


def _handle_conn(conn, api_key, pool, stats):
    try:
        f = conn.makefile("rwb")
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return
    try:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            try:
                req = json.loads(line.decode("utf-8"))
            except Exception:
                _write(f, {"ok": False, "error": "bad json"})
                continue

            op = req.get("op")
            if op == "ping":
                _write(f, {"ok": True, "pong": True})
                continue
            if op == "stats":
                _write(f, {"ok": True, "stats": stats.snapshot()})
                continue

            try:
                resp = _handle_ask(req, api_key, pool, stats)
            except Exception as exc:
                resp = {"id": req.get("id"), "ok": False, "error": redact.redact(str(exc))[:300]}
            _write(f, resp)
    except Exception:
        pass
    finally:
        try:
            f.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


def _write(f, obj):
    try:
        f.write((json.dumps(obj) + "\n").encode("utf-8"))
        f.flush()
    except Exception:
        pass


def _bind_socket(sock_dir, sock_path):
    os.makedirs(sock_dir, mode=0o700, exist_ok=True)
    os.chmod(sock_dir, 0o700)

    if os.path.exists(sock_path):
        # Is something already listening? If so, refuse to steal the socket.
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(0.2)
        try:
            probe.connect(sock_path)
            probe.close()
            raise SystemExit("airlock daemon already running at %s" % sock_path)
        except (TimeoutError, ConnectionRefusedError, FileNotFoundError, OSError):
            pass
        finally:
            try:
                probe.close()
            except Exception:
                pass
        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    os.chmod(sock_path, 0o600)
    server.listen(LISTEN_BACKLOG)
    return server


def serve_forever(server, api_key, pool_size=DEFAULT_POOL_SIZE, connection_factory=new_https_connection):
    pool = ConnectionPool(size=pool_size, connection_factory=connection_factory)
    stats = Stats()

    stop = threading.Event()

    def _sigterm(_signum, _frame):
        stop.set()
        try:
            server.close()
        except Exception:
            pass

    signal.signal(signal.SIGTERM, _sigterm)
    signal.signal(signal.SIGINT, _sigterm)

    sys.stderr.write("airlock daemon listening, pool_size=%d\n" % len(pool.slots))
    sys.stderr.flush()

    while not stop.is_set():
        try:
            conn, _addr = server.accept()
        except OSError:
            break
        t = threading.Thread(target=_handle_conn, args=(conn, api_key, pool, stats), daemon=True)
        t.start()


def main():
    # The daemon is POSIX-only and deliberately out of scope on Windows:
    # it listens on a Unix domain socket, which Windows does not have, and a
    # localhost TCP listener is precisely the design this project refuses.
    # Windows clients fall back to the direct HTTPS call (airlock/client.py),
    # about 0.9 s cold against about 0.3 s warm. Saying so and exiting beats
    # failing somewhere further down with an AttributeError on AF_UNIX.
    from .platform_compat import has_unix_sockets
    if not has_unix_sockets():
        sys.stderr.write(
            "airlock daemon: this platform has no Unix domain sockets, so the warm\n"
            "connection daemon does not run here. Nothing to do: the client already\n"
            "falls back to a direct HTTPS call per judgement (about 0.9s).\n")
        sys.exit(0)

    api_key = keyfile.get_api_key()
    if not api_key:
        sys.stderr.write("airlock daemon: no TYPESAFE_API_KEY found, exiting\n")
        sys.exit(1)

    sock_dir, sock_path = _socket_dir_and_path()
    server = _bind_socket(sock_dir, sock_path)
    try:
        serve_forever(server, api_key)
    finally:
        try:
            server.close()
        except Exception:
            pass
        try:
            os.unlink(sock_path)
        except Exception:
            pass


if __name__ == "__main__":
    main()
