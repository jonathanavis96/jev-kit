
import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import json
import os
import socket
import tempfile
import unittest

from tests import posix_only
from unittest import mock

from airlock import client


class _FakeResponse:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestClient(unittest.TestCase):
    def test_call_jev_parses_response(self):
        fake = {
            "model": "jev-1.13.0",
            "answers": {
                "task_kind": {
                    "type": "choice",
                    "choice": "lookup",
                    "confidence": 0.95,
                    "probabilities": {"lookup": 0.95},
                }
            },
            "usage": {"input_tokens": 100, "output_tokens": 20},
        }
        with mock.patch("urllib.request.urlopen", return_value=_FakeResponse(fake)):
            result, latency_ms = client.call_jev("fake-key", {"x": 1}, {"q": {}}, timeout=5)
        self.assertEqual(result["model"], "jev-1.13.0")
        self.assertEqual(result["answers"]["task_kind"]["choice"], "lookup")
        self.assertGreaterEqual(latency_ms, 0)

    def test_non_object_json_is_a_typesafe_error(self):
        """Valid JSON that is not an object (null, a list) is as unusable as
        bad JSON; callers would otherwise hit AttributeError on .get()."""
        for payload in (None, [1, 2], "x"):
            with mock.patch("urllib.request.urlopen", return_value=_FakeResponse(payload)):
                with self.assertRaises(client.TypeSafeError):
                    client.call_jev("fake-key", {"x": 1}, {"q": {}}, timeout=5)

    def test_timeout_raises(self):
        with mock.patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            with self.assertRaises(TimeoutError):
                client.call_jev("fake-key", {"x": 1}, {"q": {}}, timeout=5)

    def test_never_puts_key_on_a_command_line(self):
        # call_jev must build the request purely in-process (urllib), never by
        # shelling out to curl/wget with the key as an argument.
        import inspect

        src = inspect.getsource(client)
        self.assertNotIn("import subprocess", src)
        self.assertNotIn("os.system", src)
        self.assertNotIn("subprocess.run", src)
        self.assertNotIn("subprocess.Popen", src)


@posix_only("the warm daemon listens on a Unix domain socket; Windows has\n            none, and airlock/client.py skips it there -- see\n            tests/test_windows_platform.py:TestUnixSockets")
class TestAskFallback(unittest.TestCase):
    """ask() must degrade to the direct call whenever the daemon socket is
    missing, refuses, or errors -- never raise anything the daemon path
    itself introduces."""

    def test_falls_back_when_socket_missing(self):
        with tempfile.TemporaryDirectory() as d:
            missing_sock = os.path.join(d, "does", "not", "exist", "jev.sock")
            fake = ({"model": "jev-1.13.0", "answers": {}, "usage": {}}, 900)
            with mock.patch.object(client, "_daemon_socket_path", return_value=missing_sock), \
                 mock.patch.object(client, "call_jev", return_value=fake) as call_jev, \
                 mock.patch.object(client.keyfile, "get_api_key", return_value="fake-key"):
                result, latency_ms = client.ask({"state": {"x": 1}, "model": client.MODEL, "questions": {}})
        call_jev.assert_called_once()
        self.assertEqual(result["model"], "jev-1.13.0")
        self.assertEqual(latency_ms, 900)

    def test_no_api_key_raises_without_a_network_call(self):
        with tempfile.TemporaryDirectory() as d:
            missing_sock = os.path.join(d, "missing.sock")
            with mock.patch.object(client, "_daemon_socket_path", return_value=missing_sock), \
                 mock.patch.object(client, "call_jev") as call_jev, \
                 mock.patch.object(client.keyfile, "get_api_key", return_value=None):
                with self.assertRaises(client.TypeSafeError) as cm:
                    client.ask({"state": {}, "model": client.MODEL, "questions": {}})
        call_jev.assert_not_called()
        self.assertIn("no API key", str(cm.exception))

    def test_falls_back_when_daemon_refuses_connection(self):
        with tempfile.TemporaryDirectory() as d:
            sock_path = os.path.join(d, "jev.sock")
            # A path that exists but nothing is listening on -> ECONNREFUSED,
            # simulated here by simply never creating a listener.
            fake = ({"model": "jev-1.13.0", "answers": {}, "usage": {}}, 900)
            with mock.patch.object(client, "_daemon_socket_path", return_value=sock_path), \
                 mock.patch.object(client, "call_jev", return_value=fake) as call_jev, \
                 mock.patch.object(client.keyfile, "get_api_key", return_value="fake-key"):
                result, latency_ms = client.ask({"state": {}, "model": client.MODEL, "questions": {}})
        call_jev.assert_called_once()
        self.assertEqual(latency_ms, 900)

    def test_uses_daemon_response_when_available(self):
        with tempfile.TemporaryDirectory() as d:
            sock_path = os.path.join(d, "jev.sock")
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(sock_path)
            server.listen(1)

            def _respond():
                conn, _addr = server.accept()
                f = conn.makefile("rwb")
                line = f.readline()
                req = json.loads(line.decode("utf-8"))
                resp = {
                    "id": req["id"],
                    "ok": True,
                    "status": 200,
                    "response": {"model": "jev-1.13.0", "answers": {}, "usage": {}},
                    "latency_ms": 42,
                    "reused_connection": True,
                }
                f.write((json.dumps(resp) + "\n").encode("utf-8"))
                f.flush()
                f.close()
                conn.close()

            import threading

            t = threading.Thread(target=_respond)
            t.start()
            try:
                with mock.patch.object(client, "_daemon_socket_path", return_value=sock_path), \
                     mock.patch.object(client, "call_jev") as call_jev:
                    result, latency_ms = client.ask({"state": {}, "model": client.MODEL, "questions": {}})
            finally:
                t.join(timeout=2)
                server.close()

        call_jev.assert_not_called()
        self.assertEqual(latency_ms, 42)
        self.assertEqual(result["model"], "jev-1.13.0")

    def test_daemon_timeout_raises_instead_of_resending(self):
        # The daemon already spent the budget waiting on TypeSafe. Sending the
        # same request again directly doubles the wait and the bill.
        reply = {"id": "x", "ok": False, "error": "timed out", "timed_out": True}
        with mock.patch.object(client.socket, "socket") as sock_cls, \
             mock.patch.object(client, "call_jev") as call_jev:
            sock = sock_cls.return_value
            sock.makefile.return_value.readline.return_value = (json.dumps(reply) + "\n").encode()
            with self.assertRaises(client.TypeSafeError):
                client.ask({"state": {}, "model": client.MODEL, "questions": {}}, timeout_s=1.5)
        call_jev.assert_not_called()

    def test_daemon_read_timeout_raises_instead_of_resending(self):
        # The daemon took the request and the client gave up waiting: the
        # budget is spent and the request may be billed, so no direct call.
        with mock.patch.object(client.socket, "socket") as sock_cls, \
             mock.patch.object(client, "call_jev") as call_jev:
            sock = sock_cls.return_value
            sock.makefile.return_value.readline.side_effect = socket.timeout("timed out")
            with self.assertRaises(client.TypeSafeError):
                client.ask({"state": {}, "model": client.MODEL, "questions": {}}, timeout_s=1.5)
        call_jev.assert_not_called()

    def test_never_puts_key_on_a_command_line_in_ask_or_daemon_path(self):
        import inspect

        src = inspect.getsource(client)
        self.assertNotIn("import subprocess", src)
        self.assertNotIn("os.system", src)


if __name__ == "__main__":
    unittest.main()
