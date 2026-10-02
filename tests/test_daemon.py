
import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import http.client
import json
import os
import socket
import stat
import tempfile
import threading
import time
import unittest

from tests import posix_only
from unittest import mock

from airlock import daemon


class _FakeResponse:
    def __init__(self, status, payload):
        self.status = status
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._raw


class _FakeConnection:
    """Stands in for http.client.HTTPSConnection in pool tests. `script` is a
    list of callables invoked in order, one per .request()+.getresponse()
    cycle, so a test can make the Nth call raise to exercise retry-once."""

    def __init__(self, script):
        self.script = list(script)
        self.sock = mock.Mock()
        self.closed = False
        self.requests = 0

    def request(self, method, path, body=None, headers=None):
        self.requests += 1
        self._next = self.script.pop(0)

    def getresponse(self):
        result = self._next()
        if isinstance(result, Exception):
            raise result
        return result

    def close(self):
        self.closed = True


@posix_only("the daemon binds a Unix domain socket; it does not run on Windows at all")
class TestConnectionPool(unittest.TestCase):
    def test_reuses_connection_across_requests(self):
        conn = _FakeConnection([
            lambda: _FakeResponse(200, {"ok": 1}),
            lambda: _FakeResponse(200, {"ok": 2}),
        ])
        made = []

        def factory(timeout_s):
            made.append(1)
            return conn

        pool = daemon.ConnectionPool(size=1, connection_factory=factory)
        status1, raw1, reused1 = pool.request("/v1/systemone", b"{}", {}, 5)
        status2, raw2, reused2 = pool.request("/v1/systemone", b"{}", {}, 5)

        self.assertEqual(len(made), 1)  # only connected once
        self.assertFalse(reused1)
        self.assertTrue(reused2)
        self.assertEqual(status1, 200)
        self.assertEqual(status2, 200)

    def test_retries_once_on_dropped_connection(self):
        dead_conn = _FakeConnection([
            lambda: (_ for _ in ()).throw(http.client.RemoteDisconnected("gone")),
        ])
        fresh_conn = _FakeConnection([
            lambda: _FakeResponse(200, {"ok": 1}),
        ])
        connections = [dead_conn, fresh_conn]

        def factory(timeout_s):
            return connections.pop(0)

        pool = daemon.ConnectionPool(size=1, connection_factory=factory)
        status, raw, reused = pool.request("/v1/systemone", b"{}", {}, 5)

        self.assertEqual(status, 200)
        self.assertFalse(reused)  # had to reconnect, so not a reuse
        self.assertTrue(dead_conn.closed)

    def test_a_timeout_is_not_retried(self):
        """A read timeout means the API is slow, not that the socket died.
        Retrying doubles the wait past the hook's own socket timeout and
        pays for the judgement twice. The slow connection is dropped so the
        next request starts clean."""
        slow_conn = _FakeConnection([
            lambda: (_ for _ in ()).throw(TimeoutError("timed out")),
        ])
        made = []

        def factory(timeout_s):
            made.append(1)
            return slow_conn

        pool = daemon.ConnectionPool(size=1, connection_factory=factory)
        with self.assertRaises(TimeoutError):
            pool.request("/v1/systemone", b"{}", {}, 5)
        self.assertEqual(len(made), 1)
        self.assertTrue(slow_conn.closed)
        self.assertIsNone(pool.slots[0].conn)

    def test_raises_if_retry_also_fails(self):
        dead_conn = _FakeConnection([
            lambda: (_ for _ in ()).throw(ConnectionResetError("gone")),
        ])
        also_dead_conn = _FakeConnection([
            lambda: (_ for _ in ()).throw(ConnectionResetError("still gone")),
        ])
        connections = [dead_conn, also_dead_conn]

        def factory(timeout_s):
            return connections.pop(0)

        pool = daemon.ConnectionPool(size=1, connection_factory=factory)
        with self.assertRaises(ConnectionResetError):
            pool.request("/v1/systemone", b"{}", {}, 5)

    def test_timeout_is_not_retried(self):
        # A read timeout means TypeSafe is slow, not that the connection died.
        # The POST already went out, so a retry would bill it twice.
        slow_conn = _FakeConnection([
            lambda: (_ for _ in ()).throw(socket.timeout("timed out")),
        ])
        made = [slow_conn]

        def factory(timeout_s):
            return made.pop(0)

        pool = daemon.ConnectionPool(size=1, connection_factory=factory)
        with self.assertRaises(socket.timeout):
            pool.request("/v1/systemone", b"{}", {}, 5)
        self.assertEqual(slow_conn.requests, 1)
        self.assertTrue(slow_conn.closed)
        self.assertIsNone(pool.slots[0].conn)

    def test_timeout_reply_is_flagged(self):
        class _SlowPool:
            def request(self, *a, **k):
                raise socket.timeout("timed out")

        with mock.patch.object(daemon, "_log"):
            reply = daemon._handle_ask({"id": "x", "body": {}}, "k", _SlowPool(), daemon.Stats())
        self.assertFalse(reply["ok"])
        self.assertTrue(reply.get("timed_out"))

    def test_busy_slot_does_not_block_a_free_one(self):
        # The round-robin pick is busy; the other connection is idle and
        # must be used rather than queueing behind the slow judgement.
        conn_b = _FakeConnection([lambda: _FakeResponse(200, {})])
        pool = daemon.ConnectionPool(size=2, connection_factory=lambda t: conn_b)
        pool.slots[0].lock.acquire()
        try:
            status, _raw, _reused = pool.request("/v1/systemone", b"{}", {}, 5)
        finally:
            pool.slots[0].lock.release()
        self.assertEqual(status, 200)
        self.assertEqual(conn_b.requests, 1)

    def test_waiting_for_a_slot_is_bounded_by_the_budget(self):
        # Every slot busy: give up as a timeout within the caller's budget
        # instead of sending the request after the client has gone direct.
        made = []
        pool = daemon.ConnectionPool(size=1, connection_factory=lambda t: made.append(t))
        pool.slots[0].lock.acquire()
        try:
            start = time.monotonic()
            with self.assertRaises(TimeoutError):
                pool.request("/v1/systemone", b"{}", {}, 0.2)
            self.assertLess(time.monotonic() - start, 2)
        finally:
            pool.slots[0].lock.release()
        self.assertEqual(made, [])

    def test_retry_uses_what_is_left_of_the_budget(self):
        timeouts = []
        dead_conn = _FakeConnection([
            lambda: (_ for _ in ()).throw(ConnectionResetError("gone")),
        ])
        fresh_conn = _FakeConnection([lambda: _FakeResponse(200, {})])
        connections = [dead_conn, fresh_conn]

        def factory(timeout_s):
            timeouts.append(timeout_s)
            return connections.pop(0)

        pool = daemon.ConnectionPool(size=1, connection_factory=factory)
        with mock.patch.object(daemon.time, "monotonic", side_effect=[100.0, 100.0, 103.0]):
            pool.request("/v1/systemone", b"{}", {}, 5)
        self.assertEqual(timeouts, [5.0, 2.0])

    def test_failed_retry_leaves_no_connection_behind(self):
        connections = [
            _FakeConnection([lambda: (_ for _ in ()).throw(ConnectionResetError("gone"))]),
            _FakeConnection([lambda: (_ for _ in ()).throw(socket.timeout("slow"))]),
        ]
        pool = daemon.ConnectionPool(size=1, connection_factory=lambda t: connections.pop(0))
        with self.assertRaises(socket.timeout):
            pool.request("/v1/systemone", b"{}", {}, 5)
        self.assertIsNone(pool.slots[0].conn)
        self.assertFalse(pool.slots[0].lock.locked())

    def test_round_robins_across_pool_slots(self):
        conn_a = _FakeConnection([lambda: _FakeResponse(200, {})])
        conn_b = _FakeConnection([lambda: _FakeResponse(200, {})])
        connections = [conn_a, conn_b]

        def factory(timeout_s):
            return connections.pop(0)

        pool = daemon.ConnectionPool(size=2, connection_factory=factory)
        pool.request("/v1/systemone", b"{}", {}, 5)
        pool.request("/v1/systemone", b"{}", {}, 5)

        self.assertEqual(conn_a.requests, 1)
        self.assertEqual(conn_b.requests, 1)


@posix_only("the daemon binds a Unix domain socket; it does not run on Windows at all")
class TestStats(unittest.TestCase):
    def test_arithmetic(self):
        s = daemon.Stats()
        s.record(100, reused=False, ok=True, tokens_in=50, tokens_out=10)
        s.record(200, reused=True, ok=True, tokens_in=60, tokens_out=20)
        s.record(300, reused=True, ok=False, tokens_in=0, tokens_out=0)
        snap = s.snapshot()
        self.assertEqual(snap["requests"], 3)
        self.assertEqual(snap["errors"], 1)
        self.assertAlmostEqual(snap["reuse_rate"], 2 / 3, places=3)
        self.assertAlmostEqual(snap["latency_ms_mean"], 200.0, places=1)
        self.assertIn(snap["latency_ms_p95"], (200, 300))
        self.assertEqual(snap["tokens_in"], 110)
        self.assertEqual(snap["tokens_out"], 30)

    def test_empty_stats_do_not_divide_by_zero(self):
        snap = daemon.Stats().snapshot()
        self.assertEqual(snap["requests"], 0)
        self.assertEqual(snap["reuse_rate"], 0.0)
        self.assertEqual(snap["latency_ms_mean"], 0)


def _line(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))


def _read_line(f):
    return json.loads(f.readline().decode("utf-8"))


@posix_only("the daemon binds a Unix domain socket; it does not run on Windows at all")
class TestProtocolRoundTrip(unittest.TestCase):
    """Starts the real daemon connection-handling loop over a temp Unix
    socket, with the outbound HTTPS call faked, and drives it as a client
    would through the raw socket protocol."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sock_path = os.path.join(self.tmpdir.name, "jev.sock")
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.sock_path)
        self.server.listen(4)
        os.chmod(self.sock_path, 0o600)

        self.pool = daemon.ConnectionPool(
            size=1,
            connection_factory=lambda timeout_s: _FakeConnection([
                lambda: _FakeResponse(200, {
                    "model": "jev-1.13.0",
                    "answers": {"task_kind": {"choice": "lookup"}},
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                }),
            ] * 10),
        )
        self.stats = daemon.Stats()
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._stop = False
        self._accept_thread.start()

    def _accept_loop(self):
        while not self._stop:
            try:
                self.server.settimeout(0.5)
                conn, _addr = self.server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            daemon._handle_conn(conn, "sekrit-key-never-leaked", self.pool, self.stats)

    def tearDown(self):
        self._stop = True
        try:
            self.server.close()
        except Exception:
            pass
        self.tmpdir.cleanup()

    def _connect(self):
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.settimeout(2)
        c.connect(self.sock_path)
        return c

    def test_ping(self):
        c = self._connect()
        f = c.makefile("rwb")
        _line(c, {"op": "ping"})
        resp = _read_line(f)
        self.assertEqual(resp, {"ok": True, "pong": True})
        c.close()

    def test_ask_round_trip(self):
        c = self._connect()
        f = c.makefile("rwb")
        _line(c, {"id": "abc123", "body": {"state": {}, "model": "jev-latest", "questions": {}}, "timeout_s": 5})
        resp = _read_line(f)
        self.assertTrue(resp["ok"])
        self.assertEqual(resp["id"], "abc123")
        self.assertEqual(resp["status"], 200)
        self.assertEqual(resp["response"]["answers"]["task_kind"]["choice"], "lookup")
        self.assertIn("latency_ms", resp)
        self.assertIn("reused_connection", resp)
        c.close()

    def test_stats_op(self):
        # Two ops on the same connection -- the daemon serves multiple
        # requests per client connection, one JSON line at a time.
        c = self._connect()
        f = c.makefile("rwb")
        _line(c, {"id": "x", "body": {"state": {}, "model": "jev-latest", "questions": {}}, "timeout_s": 5})
        _read_line(f)

        _line(c, {"op": "stats"})
        resp = _read_line(f)
        self.assertTrue(resp["ok"])
        self.assertGreaterEqual(resp["stats"]["requests"], 1)
        f.close()
        c.close()

    def test_key_never_appears_on_the_wire(self):
        c = self._connect()
        f = c.makefile("rwb")
        _line(c, {"id": "x", "body": {"state": {}, "model": "jev-latest", "questions": {}}, "timeout_s": 5})
        raw_line = f.readline()
        self.assertNotIn(b"sekrit-key-never-leaked", raw_line)
        c.close()

    def test_bad_json_gets_an_error_reply_not_a_crash(self):
        c = self._connect()
        f = c.makefile("rwb")
        c.sendall(b"not json at all\n")
        resp = _read_line(f)
        self.assertFalse(resp["ok"])
        c.close()


@posix_only("the daemon binds a Unix domain socket; it does not run on Windows at all")
class TestSocketAndDirModes(unittest.TestCase):
    def test_bind_socket_sets_modes(self):
        with tempfile.TemporaryDirectory() as base:
            runtime = os.path.join(base, "runtime")
            sock_dir = os.path.join(runtime, "jev")
            sock_path = os.path.join(sock_dir, "jev.sock")
            server = daemon._bind_socket(sock_dir, sock_path)
            try:
                dir_mode = stat.S_IMODE(os.stat(sock_dir).st_mode)
                sock_mode = stat.S_IMODE(os.stat(sock_path).st_mode)
                self.assertEqual(dir_mode, 0o700)
                self.assertEqual(sock_mode, 0o600)
            finally:
                server.close()
                os.unlink(sock_path)

    def test_socket_path_uses_xdg_runtime_dir(self):
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/tmp/fake-runtime"}):
            d, p = daemon._socket_dir_and_path()
            self.assertEqual(d, "/tmp/fake-runtime/airlock")
            self.assertEqual(p, "/tmp/fake-runtime/airlock/airlock.sock")

    def test_socket_path_falls_back_to_run_user_uid(self):
        env = dict(os.environ)
        env.pop("XDG_RUNTIME_DIR", None)
        with mock.patch.dict(os.environ, env, clear=True):
            d, p = daemon._socket_dir_and_path()
            self.assertEqual(d, "/run/user/%d/airlock" % os.getuid())


@posix_only("the daemon binds a Unix domain socket; it does not run on Windows at all")
class TestKeyNeverLogged(unittest.TestCase):
    def test_log_line_never_contains_the_key(self):
        import io

        buf = io.StringIO()
        with mock.patch("sys.stderr", buf):
            daemon._log("id1", 200, 123, True, 10, 5)
        self.assertNotIn("Bearer", buf.getvalue())
        self.assertNotIn("sekrit", buf.getvalue())

    def test_error_replies_are_redacted(self):
        pool = mock.Mock()
        pool.request.side_effect = RuntimeError("token apikey_ABCDEFGHIJ1234567890 leaked")
        stats = daemon.Stats()
        resp = daemon._handle_ask(
            {"id": "x", "body": {"state": {}, "model": "m", "questions": {}}, "timeout_s": 5},
            "sekrit-key",
            pool,
            stats,
        )
        self.assertFalse(resp["ok"])
        self.assertNotIn("apikey_ABCDEFGHIJ1234567890", resp["error"])
        self.assertNotIn("sekrit-key", resp["error"])


if __name__ == "__main__":
    unittest.main()
