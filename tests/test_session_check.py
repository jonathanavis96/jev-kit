"""hooks/airlock_session_check.py: the SessionStart check.

The thing this component exists for is one sentence long: the guard fails
open, so a dead guard is silent, and on a workstation nothing outside the
machine can notice. Everything tested here is a way that promise can be
broken.

Two failure directions, and they are NOT symmetric:

  - saying NOTHING when the guard is dead is the failure this component was
    written to prevent, so every condition has a test that it speaks;
  - saying something when nothing is wrong is how a check gets ignored, so
    the silent-when-healthy case, the fresh-boot case and the no-timer case
    each have a test that it stays quiet.

Fail-open discipline gets its own tests: a corrupt health log, an unreadable
state file and a missing uptime source must all end in "exit 0, print
nothing" rather than an exception.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import tests

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOK = REPO_ROOT / "hooks" / "airlock_session_check.py"

sys.path.insert(0, str(REPO_ROOT / "hooks"))
import airlock_session_check as sc


def facts(**over):
    """A HEALTHY machine, with only what a test cares about overridden."""
    base = {
        "mode": "shadow", "kill_switch": None, "key_ok": True,
        "health_row": {"status": "healthy", "ts": "2026-09-19T12:00:00+00:00"},
        "health_age_s": 60.0, "uptime_s": 86400.0, "health_timer": True,
        "release_ok": True, "tuning_installed": False, "tune_category": None,
        "doctor": "/opt/airlock/current/install/doctor.sh",
    }
    base.update(over)
    return base


class TestSilentWhenHealthy(unittest.TestCase):
    def test_a_healthy_machine_says_nothing(self):
        self.assertIsNone(sc.choose_warning(facts()))

    def test_enforce_mode_is_not_a_problem(self):
        self.assertIsNone(sc.choose_warning(facts(mode="enforce")))

    def test_a_degraded_looking_row_that_says_healthy_is_believed(self):
        # The row is the authority. Re-deriving a verdict here would let the
        # session check and health.jsonl disagree about the same run.
        row = {"status": "healthy", "daemon_ping": {"ok": True},
               "ts": "2026-09-19T12:00:00+00:00"}
        self.assertIsNone(sc.choose_warning(facts(health_row=row)))


class TestEveryCondition(unittest.TestCase):
    def test_kill_switch_file(self):
        w = sc.choose_warning(facts(kill_switch="/x/.config/airlock/disabled"))
        self.assertIsNotNone(w)
        self.assertIn("kill switch", w.headline)
        self.assertIn("/x/.config/airlock/disabled", w.headline)
        self.assertEqual(w.repeat_s, sc.INFO_REPEAT_AFTER_S)

    def test_kill_switch_env(self):
        w = sc.choose_warning(facts(kill_switch="$AIRLOCK_DISABLE=1"))
        self.assertIn("AIRLOCK_DISABLE", w.headline)

    def test_mode_off(self):
        w = sc.choose_warning(facts(mode="off"))
        self.assertIn("`off`", w.headline)
        self.assertEqual(w.repeat_s, sc.INFO_REPEAT_AFTER_S)

    def test_no_key(self):
        w = sc.choose_warning(facts(key_ok=False))
        self.assertIn("no API key", w.headline)
        self.assertEqual(w.repeat_s, sc.REPEAT_AFTER_S)

    def test_the_kill_switch_outranks_the_missing_key(self):
        # A guard that is switched off is not judging for a reason somebody
        # chose; reporting the key first would bury that.
        w = sc.choose_warning(facts(kill_switch="/x/disabled", key_ok=False))
        self.assertIn("kill switch", w.headline)

    def test_unhealthy_row_names_the_failing_check(self):
        row = {"status": "down",
               "daemon_ping": {"ok": False, "error": "connection refused"},
               "ts": "2026-09-19T12:00:00+00:00"}
        w = sc.choose_warning(facts(health_row=row))
        self.assertIn("down", w.headline)
        self.assertIn("daemon ping failed", w.headline)
        self.assertIn("connection refused", w.headline)

    def test_degraded_row_names_the_failing_check(self):
        row = {"status": "degraded", "key_loadable": False,
               "ts": "2026-09-19T12:00:00+00:00"}
        w = sc.choose_warning(facts(health_row=row))
        self.assertIn("degraded", w.headline)
        self.assertIn("no API key resolves", w.headline)

    def test_degraded_row_reports_a_high_fail_open_rate(self):
        row = {"status": "degraded", "last_hour": {"fail_open_rate": 0.44},
               "ts": "2026-09-19T12:00:00+00:00"}
        w = sc.choose_warning(facts(health_row=row))
        self.assertIn("44%", w.headline)

    def test_degraded_row_with_no_named_check_still_speaks(self):
        row = {"status": "degraded", "ts": "2026-09-19T12:00:00+00:00"}
        w = sc.choose_warning(facts(health_row=row))
        self.assertIn("no failing check named", w.headline)

    def test_tuning_could_not_run(self):
        w = sc.choose_warning(facts(tuning_installed=True,
                                    tune_category="could_not_run"))
        self.assertIn("tuning", w.headline)

    def test_tuning_could_not_run_is_silent_when_tuning_is_not_installed(self):
        self.assertIsNone(sc.choose_warning(
            facts(tuning_installed=False, tune_category="could_not_run")))

    def test_a_healthy_tuning_category_is_silent(self):
        self.assertIsNone(sc.choose_warning(
            facts(tuning_installed=True, tune_category="ran_committed")))


class TestStalenessAndTheUptimeGuard(unittest.TestCase):
    """Three conditions, all required. Each one on its own is a false alarm."""

    def test_stale_row_on_a_long_lived_machine_warns(self):
        w = sc.choose_warning(facts(health_age_s=3000.0, uptime_s=86400.0,
                                    health_timer=True))
        self.assertIn("50 minutes ago", w.headline)
        self.assertIn("health timer", w.headline)

    def test_a_missing_row_on_a_long_lived_machine_warns(self):
        w = sc.choose_warning(facts(health_row=None, health_age_s=None,
                                    uptime_s=86400.0, health_timer=True))
        self.assertIn("has never run", w.headline)

    def test_a_fresh_boot_is_silent(self):
        # OnBootSec is 2 minutes; a machine up for 5 has not had time yet.
        self.assertIsNone(sc.choose_warning(
            facts(health_age_s=None, uptime_s=300.0, health_timer=True)))

    def test_uptime_exactly_at_the_threshold_is_silent(self):
        self.assertIsNone(sc.choose_warning(
            facts(health_age_s=3000.0, uptime_s=float(sc.MIN_UPTIME_S),
                  health_timer=True)))

    def test_unknown_uptime_never_raises_the_staleness_warning(self):
        # An unreadable uptime is NO evidence, in either direction.
        self.assertIsNone(sc.choose_warning(
            facts(health_age_s=99999.0, uptime_s=None, health_timer=True)))

    def test_no_timer_means_nothing_can_be_stale(self):
        self.assertIsNone(sc.choose_warning(
            facts(health_age_s=99999.0, uptime_s=86400.0, health_timer=False,
                  release_ok=True)))

    def test_no_timer_falls_back_to_the_local_release_check(self):
        w = sc.choose_warning(facts(health_age_s=None, uptime_s=86400.0,
                                    health_timer=False, release_ok=False))
        self.assertIn("release pointer", w.headline)

    def test_no_timer_and_nothing_deployed_is_silent(self):
        # Running out of a checkout is an ordinary state, not a fault.
        self.assertIsNone(sc.choose_warning(
            facts(health_age_s=None, uptime_s=86400.0, health_timer=False,
                  release_ok=None)))


class TestUptimeInjection(unittest.TestCase):
    def test_linux_reads_proc_uptime(self):
        tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".uptime")
        tmp.write("12345.67 98765.43\n")
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        self.assertAlmostEqual(
            sc.read_uptime_seconds(system="Linux", proc_uptime=tmp.name),
            12345.67, places=2)

    def test_linux_with_no_proc_uptime_is_unknown(self):
        self.assertIsNone(sc.read_uptime_seconds(
            system="Linux", proc_uptime="/nonexistent/uptime"))

    def test_windows_uses_the_injected_tick_count(self):
        # GetTickCount64 is in milliseconds.
        self.assertAlmostEqual(
            sc.read_uptime_seconds(system="Windows", ticks=1800000), 1800.0)

    def test_macos_parses_kern_boottime(self):
        boot = int(time.time()) - 7200
        text = "{ sec = %d, usec = 1 } Fri Sep 19 00:00:00 2026\n" % boot
        got = sc.read_uptime_seconds(system="Darwin", sysctl=text)
        self.assertIsNotNone(got)
        self.assertAlmostEqual(got, 7200.0, delta=5)

    def test_unparseable_sysctl_is_unknown(self):
        self.assertIsNone(sc.read_uptime_seconds(system="Darwin",
                                                 sysctl="nothing useful here"))


class TestFailOpenOnBadInput(unittest.TestCase):
    def test_a_corrupt_health_log_is_no_row_rather_than_a_crash(self):
        tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl")
        tmp.write("{not json at all\n\x00\x01 garbage\nstill not json\n")
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        self.assertIsNone(sc.last_json_line(tmp.name))

    def test_a_half_written_last_line_falls_back_to_the_previous_one(self):
        tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl")
        tmp.write('{"status": "healthy", "ts": "2026-09-19T12:00:00Z"}\n')
        tmp.write('{"status": "deg')
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        row = sc.last_json_line(tmp.name)
        self.assertEqual(row["status"], "healthy")

    def test_a_missing_health_log_is_no_row(self):
        self.assertIsNone(sc.last_json_line("/nonexistent/health.jsonl"))

    def test_an_unparseable_timestamp_is_no_timestamp(self):
        self.assertIsNone(sc.parse_ts("not a date"))
        self.assertIsNone(sc.parse_ts(None))

    def test_failed_checks_tolerates_a_non_dict_row(self):
        self.assertEqual(sc.failed_checks("nonsense"), [])


class TestDeduplication(unittest.TestCase):
    def test_a_repeat_inside_the_window_is_suppressed(self):
        now = 1_000_000.0
        state = {"last_key": "nokey", "shown": {"nokey": now - 60}}
        self.assertFalse(sc.should_show(state, "nokey", sc.REPEAT_AFTER_S, now))

    def test_a_repeat_after_the_window_is_shown_again(self):
        now = 1_000_000.0
        state = {"last_key": "nokey", "shown": {"nokey": now - sc.REPEAT_AFTER_S - 1}}
        self.assertTrue(sc.should_show(state, "nokey", sc.REPEAT_AFTER_S, now))

    def test_a_timestamp_in_the_future_does_not_suppress(self):
        """After the clock steps back, a 'shown' stamp ahead of now would
        silence the warning until the clock caught up; it is shown instead."""
        now = 1_000_000.0
        state = {"last_key": "nokey", "shown": {"nokey": now + 3600}}
        self.assertTrue(sc.should_show(state, "nokey", sc.REPEAT_AFTER_S, now))

    def test_a_CHANGED_problem_is_shown_immediately(self):
        now = 1_000_000.0
        state = {"last_key": "health:down:daemon ping failed",
                 "shown": {"health:down:daemon ping failed": now - 60}}
        self.assertTrue(sc.should_show(
            state, "health:down:no API key resolves", sc.REPEAT_AFTER_S, now))

    def _shown_again(self, first, second):
        now = 1_000_000.0
        state = {"last_key": first.key, "shown": {first.key: now - 180}}
        return sc.should_show(state, second.key, second.repeat_s, now)

    def test_a_stale_warning_three_minutes_older_is_not_news(self):
        # The headline counts minutes; the key must not, or every session
        # start inside the window shows it again.
        first = sc.choose_warning(facts(health_age_s=3000.0, uptime_s=86400.0,
                                        health_timer=True))
        second = sc.choose_warning(facts(health_age_s=3180.0, uptime_s=86400.0,
                                         health_timer=True))
        self.assertNotEqual(first.headline, second.headline)
        self.assertFalse(self._shown_again(first, second))

    def test_a_health_reason_whose_numbers_drift_is_not_news(self):
        def row(ms, rate):
            return {"status": "degraded",
                    "daemon_ask": {"ok": False, "error": "timed out after %dms" % ms},
                    "last_hour": {"fail_open_rate": rate}}
        first = sc.choose_warning(facts(health_row=row(1510, 0.31)))
        second = sc.choose_warning(facts(health_row=row(1544, 0.34)))
        self.assertFalse(self._shown_again(first, second))
        third = sc.choose_warning(facts(health_row={
            "status": "degraded", "direct_ask": {"ok": False}}))
        self.assertTrue(self._shown_again(first, third))

    def test_an_empty_or_corrupt_state_shows_it(self):
        for state in ({}, None, "garbage", {"shown": "not a dict"}):
            self.assertTrue(sc.should_show(state, "k", sc.REPEAT_AFTER_S, 1.0))

    def test_the_informational_window_is_a_day(self):
        now = 1_000_000.0
        state = {"last_key": "off:mode", "shown": {"off:mode": now - 7 * 3600}}
        # Past the six-hour window, still inside the informational one.
        self.assertTrue(sc.should_show(state, "off:mode", sc.REPEAT_AFTER_S, now))
        self.assertFalse(sc.should_show(state, "off:mode",
                                        sc.INFO_REPEAT_AFTER_S, now))

    def test_stale_entries_are_pruned(self):
        now = 1_000_000.0
        state = {"shown": {"old": now - sc.FORGET_AFTER_S - 1, "new": now - 10}}
        sc._prune(state, now)
        self.assertNotIn("old", state["shown"])
        self.assertIn("new", state["shown"])


class HookRunMixin:
    """Run the REAL hook process against a throwaway HOME."""

    def _home(self):
        home = tempfile.mkdtemp(prefix="airlock-sc-")
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        os.makedirs(os.path.join(home, ".config", "airlock"), exist_ok=True)
        os.makedirs(os.path.join(home, ".local", "state", "airlock"), exist_ok=True)
        return home

    def _env(self, home, **extra):
        env = dict(os.environ)
        for var in ("TYPESAFE_API_KEY", "AIRLOCK_KEY_FILE", "JEVKIT_KEY_FILE",
                    "PLUMBLINE_KEY_FILE", "JEV_GUARD_KEY_FILE",
                    "JEVKIT_CONFIG_DIR", "AIRLOCK_MODE", "PLUMBLINE_MODE",
                    "JEV_GUARD_MODE", "AIRLOCK_DISABLE"):
            env.pop(var, None)
        env.update({
            "HOME": home,
            "AIRLOCK_CONFIG_DIR": os.path.join(home, ".config", "airlock"),
            "AIRLOCK_STATE_DIR": os.path.join(home, ".local", "state", "airlock"),
            "AIRLOCK_HOME": os.path.join(home, ".local", "share", "airlock"),
        })
        env.update(extra)
        return env

    def _run(self, home, **extra):
        proc = subprocess.run(
            [sys.executable, str(HOOK)],
            input='{"session_id":"t","hook_event_name":"SessionStart","source":"startup"}',
            text=True, capture_output=True, timeout=30, env=self._env(home, **extra))
        return proc


class TestTheRealProcess(HookRunMixin, unittest.TestCase):
    def test_it_always_exits_zero(self):
        self.assertEqual(self._run(self._home()).returncode, 0)

    def test_a_garbage_payload_still_exits_zero_silently(self):
        home = self._home()
        proc = subprocess.run([sys.executable, str(HOOK)], input="not json",
                              text=True, capture_output=True, timeout=30,
                              env=self._env(home))
        self.assertEqual(proc.returncode, 0)

    def test_the_output_is_a_valid_sessionstart_hook_result(self):
        # No key in a throwaway HOME, so it has something to say.
        proc = self._run(self._home())
        data = json.loads(proc.stdout)
        self.assertTrue(data["systemMessage"])
        self.assertEqual(data["hookSpecificOutput"]["hookEventName"], "SessionStart")
        self.assertIsInstance(data["hookSpecificOutput"]["additionalContext"], str)

    def test_the_message_is_never_more_than_three_lines(self):
        proc = self._run(self._home())
        data = json.loads(proc.stdout)
        self.assertLessEqual(len(data["systemMessage"].splitlines()), 3)

    def test_the_second_run_is_silent_because_of_de_duplication(self):
        home = self._home()
        first = self._run(home)
        self.assertTrue(first.stdout.strip())
        second = self._run(home)
        self.assertEqual(second.stdout.strip(), "")

    def test_a_changed_problem_speaks_again_immediately(self):
        home = self._home()
        self.assertTrue(self._run(home).stdout.strip())      # no key
        # Now switch the guard off entirely: a DIFFERENT problem.
        Path(home, ".config", "airlock", "disabled").write_text("")
        out = self._run(home).stdout.strip()
        self.assertTrue(out)
        self.assertIn("kill switch", json.loads(out)["systemMessage"])

    def test_the_kill_switch_message_names_the_switch(self):
        home = self._home()
        Path(home, ".config", "airlock", "disabled").write_text("")
        data = json.loads(self._run(home).stdout)
        self.assertIn("kill switch", data["systemMessage"])

    def test_mode_off_is_reported(self):
        home = self._home()
        Path(home, ".config", "airlock", "mode").write_text("off\n")
        data = json.loads(self._run(home, AIRLOCK_MODE="off").stdout)
        self.assertIn("`off`", data["systemMessage"])

    def test_an_unhealthy_row_is_reported(self):
        home = self._home()
        # Give it a key so the key warning does not win first.
        key = Path(home, ".config", "airlock", "env")
        key.write_text("TYPESAFE_API_KEY=apikey_notarealkey\n")
        row = {"status": "down", "ts": _now_iso(),
               "daemon_ping": {"ok": False, "error": "connection refused"}}
        Path(home, ".local", "state", "airlock", "health.jsonl").write_text(
            json.dumps(row) + "\n")
        data = json.loads(self._run(home).stdout)
        self.assertIn("daemon ping failed", data["systemMessage"])

    def test_a_healthy_row_with_a_key_is_completely_silent(self):
        home = self._home()
        Path(home, ".config", "airlock", "env").write_text(
            "TYPESAFE_API_KEY=apikey_notarealkey\n")
        Path(home, ".local", "state", "airlock", "health.jsonl").write_text(
            json.dumps({"status": "healthy", "ts": _now_iso()}) + "\n")
        proc = self._run(home)
        self.assertEqual(proc.stdout.strip(), "")
        self.assertEqual(proc.returncode, 0)

    def test_a_corrupt_health_log_does_not_crash_the_hook(self):
        home = self._home()
        Path(home, ".config", "airlock", "env").write_text(
            "TYPESAFE_API_KEY=apikey_notarealkey\n")
        Path(home, ".local", "state", "airlock", "health.jsonl").write_bytes(
            b"\x00\xff not json\n{ broken")
        proc = self._run(home)
        self.assertEqual(proc.returncode, 0)

    def test_it_never_prints_the_key(self):
        home = self._home()
        Path(home, ".config", "airlock", "env").write_text(
            "TYPESAFE_API_KEY=apikey_notarealkey\n")
        proc = self._run(home)
        self.assertNotIn("apikey_notarealkey", proc.stdout)
        self.assertNotIn("apikey_notarealkey", proc.stderr)


class TestTimeBudget(HookRunMixin, unittest.TestCase):
    def test_the_collection_stops_at_the_deadline(self):
        # A deadline already in the past: collect_facts must return promptly
        # with whatever defaults it has, not run every check anyway.
        started = time.monotonic()
        got = sc.collect_facts(deadline=time.monotonic() - 1.0)
        self.assertLess(time.monotonic() - started, sc.BUDGET_S)
        self.assertIn("mode", got)

    def test_the_whole_process_stays_well_inside_a_second(self):
        home = self._home()
        started = time.monotonic()
        self._run(home)
        elapsed = time.monotonic() - started
        # Interpreter start-up here is about 25 ms and the hook's own budget
        # is 300 ms. A second is a ceiling with room for a loaded CI box, and
        # it still catches anything that has started blocking on the network.
        self.assertLess(elapsed, 1.0, "session check took %.0f ms" % (elapsed * 1000))


class TestStateFileIsPrivate(unittest.TestCase):
    @tests.posix_only("file modes; Windows uses the per-user LOCALAPPDATA ACL")
    def test_the_state_file_is_mode_600(self):
        from airlock import paths
        sc.check_and_record(paths, "test-key", sc.REPEAT_AFTER_S)
        path = Path(sc._state_path(paths))
        self.assertTrue(path.exists())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_concurrent_calls_do_not_corrupt_it(self):
        from airlock import paths
        path = Path(sc._state_path(paths))
        if path.exists():
            path.unlink()
        # Same key from several "sessions": exactly one may show it.
        shown = [sc.check_and_record(paths, "concurrent-key", sc.REPEAT_AFTER_S)
                 for _ in range(5)]
        self.assertEqual(shown.count(True), 1)
        json.loads(path.read_text())  # still valid JSON


class TestWindowsByInjection(unittest.TestCase):
    """Windows is exercised from Linux, the way the rest of the suite does it."""

    def test_the_doctor_command_is_the_windows_one(self):
        from airlock import paths
        cmd = sc.doctor_command(paths, windows=True)
        self.assertIn("windows_doctor.py", cmd)
        self.assertTrue(cmd.startswith("py -3 "))

    def test_the_doctor_command_is_the_posix_one(self):
        from airlock import paths
        cmd = sc.doctor_command(paths, windows=False)
        self.assertTrue(cmd.endswith("doctor.sh"))

    def test_the_health_timer_check_uses_task_scheduler_on_windows(self):
        from airlock import paths
        self.assertTrue(sc.health_timer_installed(
            paths, windows=True, task_query=lambda: True))
        self.assertFalse(sc.health_timer_installed(
            paths, windows=True, task_query=lambda: False))

    def test_a_schtasks_failure_is_no_timer_rather_than_a_crash(self):
        from airlock import paths

        def boom():
            raise OSError("schtasks is not a thing here")

        self.assertFalse(sc.health_timer_installed(
            paths, windows=True, task_query=boom))

    def test_the_systemd_unit_decides_on_posix(self):
        from airlock import paths
        unit_dir = tempfile.mkdtemp(prefix="airlock-units-")
        self.addCleanup(lambda: __import__("shutil").rmtree(unit_dir, ignore_errors=True))
        self.assertFalse(sc.health_timer_installed(
            paths, windows=False, unit_dir=unit_dir))
        Path(unit_dir, "airlock-health.timer").write_text("")
        self.assertTrue(sc.health_timer_installed(
            paths, windows=False, unit_dir=unit_dir))


def _now_iso():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


if __name__ == "__main__":
    unittest.main()
