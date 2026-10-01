
import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import datetime
import unittest
from unittest import mock

from airlock import client, health


def _iso(minutes_ago):
    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=minutes_ago)).isoformat()


class TestSummarizeLastHour(unittest.TestCase):
    def test_counts_only_last_hour(self):
        rows = [
            {"ts": _iso(5), "answers": {}, "latency_ms": 100},
            {"ts": _iso(90), "answers": {}, "latency_ms": 100},  # older than 1h, excluded
        ]
        summary = health.summarize_last_hour(rows=rows)
        self.assertEqual(summary["total_rows"], 1)
        self.assertEqual(summary["judged"], 1)

    def test_skipped_rows_not_counted_as_judged(self):
        rows = [
            {"ts": _iso(1), "skipped": "no_deny_possible", "would_deny": False},
            {"ts": _iso(1), "answers": {}, "latency_ms": 50, "would_deny": False},
        ]
        summary = health.summarize_last_hour(rows=rows)
        self.assertEqual(summary["total_rows"], 2)
        self.assertEqual(summary["judged"], 1)

    def test_fail_open_and_denies(self):
        rows = [
            {"ts": _iso(1), "error": "timeout"},
            {"ts": _iso(1), "would_deny": True, "answers": {}, "latency_ms": 10},
            {"ts": _iso(1), "enforced": True, "answers": {}, "latency_ms": 10},
        ]
        summary = health.summarize_last_hour(rows=rows)
        self.assertEqual(summary["fail_open"], 1)
        self.assertAlmostEqual(summary["fail_open_rate"], 1 / 3, places=2)
        self.assertEqual(summary["denies"], 2)

    def test_p95_latency(self):
        rows = [{"ts": _iso(1), "answers": {}, "latency_ms": n} for n in range(1, 11)]
        summary = health.summarize_last_hour(rows=rows)
        self.assertGreater(summary["p95_latency_ms"], 0)

    def test_no_rows(self):
        summary = health.summarize_last_hour(rows=[])
        self.assertEqual(summary["total_rows"], 0)
        self.assertEqual(summary["fail_open_rate"], 0.0)


class TestHealthWithoutADaemon(unittest.TestCase):
    """The Windows branch: there is no daemon, so its absence must not be
    reported as an outage. A machine with no warm connection is a supported
    configuration, not a broken one."""

    def _run(self, key_ok=True, fail_open_rate=0.0, direct=None):
        direct = direct if direct is not None else {"ok": True, "latency_ms": 900}
        with mock.patch("airlock.health.has_unix_sockets", return_value=False), \
             mock.patch("airlock.health.check_direct_ask", return_value=direct), \
             mock.patch("airlock.health.check_key_loadable", return_value=key_ok), \
             mock.patch("airlock.health.check_mode", return_value="shadow"), \
             mock.patch("airlock.health.summarize_last_hour", return_value={
                 "total_rows": 10, "judged": 5, "fail_open": 0,
                 "fail_open_rate": fail_open_rate, "denies": 0,
                 "p95_latency_ms": 900.0}), \
             mock.patch("airlock.health.check_tune_state",
                        return_value={"interval_min": None, "last_run_age_s": None}):
            return health.run_health_check()

    def test_a_missing_daemon_is_skipped_not_down(self):
        status, result = self._run()
        self.assertEqual(status, "healthy")
        self.assertFalse(result["daemon_supported"])
        self.assertIn("skipped", result["daemon_ping"])
        self.assertIn("skipped", result["daemon_ask"])

    def test_the_daemon_socket_is_never_touched(self):
        with mock.patch("airlock.health.check_daemon_ping") as ping, \
             mock.patch("airlock.health.check_daemon_ask") as ask:
            self._run()
            ping.assert_not_called()
            ask.assert_not_called()

    def test_a_direct_call_takes_the_daemon_probe_s_place(self):
        _status, result = self._run()
        self.assertTrue(result["direct_ask"]["ok"])
        self.assertEqual(result["direct_ask"]["latency_ms"], 900)

    def test_a_failing_direct_call_is_degraded(self):
        status, _result = self._run(direct={"ok": False, "error": "timed out"})
        self.assertEqual(status, "degraded")

    def test_no_api_key_is_degraded_never_down(self):
        """A keyless install still fails open and still runs the code-only
        rules; it is not an outage."""
        status, _result = self._run(key_ok=False)
        self.assertEqual(status, "degraded")

    def test_a_high_fail_open_rate_is_still_degraded(self):
        status, _result = self._run(fail_open_rate=0.9)
        self.assertEqual(status, "degraded")

    def test_a_keyless_direct_probe_is_skipped_rather_than_failed(self):
        with mock.patch("airlock.health.check_key_loadable", return_value=False):
            result = health.check_direct_ask(deadline=health._now() + 5)
        self.assertIsNone(result["ok"])
        self.assertIn("no API key", result["skipped"])


class TestRunHealthCheck(unittest.TestCase):
    """Every test here is about the DAEMON branch -- ping, then ask, then the
    status it produces -- so the platform is pinned to POSIX rather than read
    off the host. On Windows there is no daemon and run_health_check takes the
    other branch entirely: the daemon checks report `skipped` instead of
    `down`, and a direct HTTPS probe takes their place. That branch has its
    own tests below."""

    def _run_with_daemon(self):
        """Force the daemon branch.

        `windows=False` is not enough on a Windows host: has_unix_sockets()
        then reports what the interpreter actually has, and a Windows CPython
        genuinely has no AF_UNIX. These tests are about the code that runs
        WHEN there is a daemon, so the capability itself is what gets pinned.
        """
        with mock.patch("airlock.health.has_unix_sockets", return_value=True):
            return health.run_health_check()

    def _patch_common(self, ping_ok, ask_result, key_ok=True, mode_val="shadow", fail_open_rate=0.0):
        return [
            mock.patch("airlock.health.check_daemon_ping", return_value={"ok": ping_ok, "latency_ms": 5}),
            mock.patch("airlock.health.check_daemon_ask", return_value=ask_result),
            mock.patch("airlock.health.check_key_loadable", return_value=key_ok),
            mock.patch("airlock.health.check_mode", return_value=mode_val),
            mock.patch("airlock.health.summarize_last_hour", return_value={
                "total_rows": 10, "judged": 5, "fail_open": 0, "fail_open_rate": fail_open_rate,
                "denies": 0, "p95_latency_ms": 100.0,
            }),
            mock.patch("airlock.health.check_tune_state", return_value={"interval_min": 30, "last_run_age_s": 60}),
        ]

    def test_healthy_when_everything_passes(self):
        patches = self._patch_common(True, {"ok": True, "latency_ms": 300})
        for p in patches:
            p.start()
        try:
            status, result = self._run_with_daemon()
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(status, "healthy")
        self.assertEqual(result["status"], "healthy")

    def test_down_when_ping_fails(self):
        patches = self._patch_common(False, {"ok": False, "error": "skipped: daemon ping failed"})
        for p in patches:
            p.start()
        try:
            status, result = self._run_with_daemon()
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(status, "down")

    def test_ask_not_called_when_ping_fails(self):
        with mock.patch("airlock.health.check_daemon_ping", return_value={"ok": False, "latency_ms": None}), \
             mock.patch("airlock.health.check_daemon_ask") as ask, \
             mock.patch("airlock.health.check_key_loadable", return_value=True), \
             mock.patch("airlock.health.check_mode", return_value="shadow"), \
             mock.patch("airlock.health.summarize_last_hour", return_value={
                 "total_rows": 0, "judged": 0, "fail_open": 0, "fail_open_rate": 0.0,
                 "denies": 0, "p95_latency_ms": 0.0,
             }), \
             mock.patch("airlock.health.check_tune_state", return_value={"interval_min": 30, "last_run_age_s": None}):
            status, result = self._run_with_daemon()
            ask.assert_not_called()
            self.assertEqual(status, "down")

    def test_degraded_when_ask_fails(self):
        patches = self._patch_common(True, {"ok": False, "error": "daemon rejected"})
        for p in patches:
            p.start()
        try:
            status, result = self._run_with_daemon()
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(status, "degraded")

    def test_degraded_when_key_not_loadable(self):
        patches = self._patch_common(True, {"ok": True, "latency_ms": 300}, key_ok=False)
        for p in patches:
            p.start()
        try:
            status, result = self._run_with_daemon()
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(status, "degraded")

    def test_degraded_when_fail_open_rate_high(self):
        patches = self._patch_common(True, {"ok": True, "latency_ms": 300}, fail_open_rate=0.5)
        for p in patches:
            p.start()
        try:
            status, result = self._run_with_daemon()
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(status, "degraded")

    def test_healthy_at_fail_open_rate_boundary(self):
        patches = self._patch_common(True, {"ok": True, "latency_ms": 300}, fail_open_rate=0.20)
        for p in patches:
            p.start()
        try:
            status, result = self._run_with_daemon()
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(status, "healthy")


class TestMainExitCodes(unittest.TestCase):
    def test_exit_codes_mapping(self):
        self.assertEqual(health._EXIT_CODES["healthy"], 0)
        self.assertEqual(health._EXIT_CODES["degraded"], 1)
        self.assertEqual(health._EXIT_CODES["down"], 2)

    def test_main_prints_one_json_line_and_returns_matching_code(self):
        with mock.patch("airlock.health.run_health_check", return_value=("degraded", {"status": "degraded"})), \
             mock.patch("builtins.print") as p:
            rc = health.main()
            self.assertEqual(rc, 1)
            p.assert_called_once()

    def test_main_never_raises_even_if_run_health_check_blows_up(self):
        with mock.patch("airlock.health.run_health_check", side_effect=RuntimeError("boom")), \
             mock.patch("builtins.print") as p:
            rc = health.main()
            self.assertEqual(rc, 2)
            p.assert_called_once()


class TestKeyLoadableNeverPrints(unittest.TestCase):
    def test_returns_bool_not_key(self):
        with mock.patch("airlock.keyfile.get_api_key", return_value="apikey_SUPERSECRET"):
            result = health.check_key_loadable()
            self.assertIs(result, True)

    def test_false_when_no_key(self):
        with mock.patch("airlock.keyfile.get_api_key", return_value=None):
            self.assertIs(health.check_key_loadable(), False)


class TestCheckDaemonAskTimeout(unittest.TestCase):
    def test_daemon_timeout_is_a_failed_check_not_a_crash(self):
        with mock.patch.object(health, "_ask_via_daemon", return_value=client._DAEMON_TIMED_OUT):
            result = health.check_daemon_ask(health._now() + 5)
        self.assertFalse(result["ok"])
        self.assertIn("timed out", result["error"])


if __name__ == "__main__":
    unittest.main()
