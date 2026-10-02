
import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock

from airlock import enforce
from airlock import policy as _policy_mod

# These tests assert the guard's behaviour, not what this machine happens to
# have installed. The live guard detects its replacement commands, so a runner
# without a plocate database would see every deny-path test fail for a reason
# that has nothing to do with the code under test (Codex P1, PR #1). Pin the
# detection for the file; the tests that check detection itself live in
# tests/test_wsl_filesearch.py.
_AVAIL = mock.patch.object(_policy_mod, "detect_availability",
                           lambda *a, **k: ("home", True))


def setUpModule():
    _AVAIL.start()


def tearDownModule():
    _AVAIL.stop()



def _bash_data(command, description="", session_id="s1"):
    return {
        "session_id": session_id,
        "cwd": "/tmp",
        "tool_name": "Bash",
        "tool_input": {"command": command, "description": description},
    }


def _agent_data(subagent_type, description="", prompt="", session_id="s1"):
    return {
        "session_id": session_id,
        "cwd": "/tmp",
        "tool_name": "Agent",
        "tool_input": {"subagent_type": subagent_type, "description": description, "prompt": prompt},
    }


class EnforceTestBase(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        state_dir = Path(self._tmpdir.name) / "airlock"
        self._patches = [
            mock.patch("airlock.state.STATE_DIR", state_dir),
            mock.patch("airlock.state.STATE_FILE", state_dir / "loop_state.json"),
            mock.patch("airlock.log.LOG_DIR", state_dir),
            mock.patch("airlock.log.LOG_FILE", state_dir / "shadow.jsonl"),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)
        self._logged = []
        log_patch = mock.patch("airlock.enforce.log.append", side_effect=self._logged.append)
        log_patch.start()
        self.addCleanup(log_patch.stop)

    def _stdout(self):
        buf = StringIO()
        patch = mock.patch("sys.stdout", buf)
        patch.start()
        self.addCleanup(patch.stop)
        return buf


class TestDenyJsonShape(EnforceTestBase):
    def test_bash_deny_shape_and_exit_semantics(self):
        fake_answer = (
            {
                "model": "jev-1.13.0",
                "answers": {
                    "search_intent": {
                        "type": "choice",
                        "choice": "filename_search",
                        "confidence": 0.95,
                        "probabilities": {"filename_search": 0.95, "not_a_search": 0.05},
                    }
                },
                "usage": {},
            },
            50,
        )
        buf = self._stdout()
        with mock.patch("airlock.keyfile.get_api_key", return_value="key"), \
             mock.patch("airlock.client.ask", return_value=fake_answer):
            denied = enforce.handle(_bash_data("find / -name '*.xlsm'"), "Bash")
        self.assertTrue(denied)
        payload = json.loads(buf.getvalue())
        out = payload["hookSpecificOutput"]
        self.assertEqual(out["hookEventName"], "PreToolUse")
        self.assertEqual(out["permissionDecision"], "deny")
        # The indexed tool the deny points at is per-platform: plocate on
        # Linux, es.exe on Windows. The shape of the deny is not.
        from airlock import policy as _policy
        # The live guard detects what this machine has, so compare against
        # the same detected values rather than the assumed defaults.
        _db, _es = _policy.detect_availability()
        self.assertIn(_policy.filename_search_suggestion(
            db_kind=_db, has_es=_es).splitlines()[0],
            out["permissionDecisionReason"])
        entry = self._logged[-1]
        self.assertTrue(entry["enforced"])
        self.assertEqual(entry["mode"], "enforce")

    def test_agent_deny_shape(self):
        fake_answer = (
            {
                "model": "jev-1.13.0",
                "answers": {
                    "task_kind": {
                        "type": "choice",
                        "choice": "lookup",
                        "confidence": 0.95,
                        "probabilities": {"lookup": 0.95, "unclear": 0.05},
                    },
                    "states_prior_failed_attempts": {"type": "noul", "noul": 0.9},
                },
                "usage": {},
            },
            50,
        )
        buf = self._stdout()
        with mock.patch("airlock.keyfile.get_api_key", return_value="key"), \
             mock.patch("airlock.client.ask", return_value=fake_answer):
            denied = enforce.handle(_agent_data("fable", "d", "p"), "Agent")
        self.assertTrue(denied)
        out = json.loads(buf.getvalue())["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("airlock-ok", out["permissionDecisionReason"])


class TestFailOpen(EnforceTestBase):
    def test_timeout_allows_and_logs_error(self):
        buf = self._stdout()
        with mock.patch("airlock.keyfile.get_api_key", return_value="key"), \
             mock.patch("airlock.client.ask", side_effect=TimeoutError("timed out")):
            denied = enforce.handle(_bash_data("find / -name '*.xlsm'"), "Bash")
        self.assertFalse(denied)
        self.assertEqual(buf.getvalue(), "")
        entry = self._logged[-1]
        self.assertIn("error", entry)
        self.assertFalse(entry["enforced"])

    def test_daemon_down_direct_call_exception_allows(self):
        buf = self._stdout()
        with mock.patch("airlock.keyfile.get_api_key", return_value="key"), \
             mock.patch("airlock.client.ask", side_effect=ConnectionRefusedError("no daemon")):
            denied = enforce.handle(_agent_data("fable", "d", "p"), "Agent")
        self.assertFalse(denied)
        self.assertEqual(buf.getvalue(), "")

    def test_malformed_answer_allows(self):
        buf = self._stdout()
        with mock.patch("airlock.keyfile.get_api_key", return_value="key"), \
             mock.patch("airlock.client.ask", return_value=({"answers": None}, 10)):
            denied = enforce.handle(_bash_data("find / -name '*.xlsm'"), "Bash")
        self.assertFalse(denied)
        self.assertEqual(buf.getvalue(), "")

    def test_one_rule_raising_does_not_skip_the_rest(self):
        # R1 asks Jev; a `probabilities` list makes compute_margin raise. That
        # used to escape to handle(), drop R7's warn and log nothing at all.
        bad = ({"answers": {"prints_a_secret": {
            "choice": "yes", "confidence": 0.99, "probabilities": ["yes", "no"]}}}, 10)
        buf = self._stdout()
        with mock.patch("airlock.keyfile.get_api_key", return_value="key"), \
             mock.patch("airlock.client.ask", return_value=bad):
            denied = enforce.handle(_bash_data("cat secrets.txt; rm -rf *"), "Bash")
        self.assertFalse(denied)
        self.assertIn("R7-destructive", buf.getvalue())
        rows = {e.get("rule_id"): e for e in self._logged}
        self.assertIn("error", rows["R1-secret-exposure"])
        self.assertFalse(rows["R1-secret-exposure"]["enforced"])
        self.assertIn("R7-destructive", rows)

    def test_generic_exception_in_compute_allows(self):
        buf = self._stdout()
        with mock.patch("airlock.guards.compute_tier_entry", side_effect=RuntimeError("boom")):
            denied = enforce.handle(_agent_data("fable", "d", "p"), "Agent")
        self.assertFalse(denied)
        self.assertEqual(buf.getvalue(), "")
        self.assertIn("error", self._logged[-1])

    def test_budget_exceeded_allows_even_with_deny_verdict(self):
        fake_answer = (
            {
                "model": "jev-1.13.0",
                "answers": {
                    "search_intent": {
                        "type": "choice",
                        "choice": "filename_search",
                        "confidence": 0.95,
                        "probabilities": {"filename_search": 0.95, "not_a_search": 0.05},
                    }
                },
                "usage": {},
            },
            50,
        )

        def slow_ask(*a, **kw):
            return fake_answer

        buf = self._stdout()
        times = iter([0.0, 5.0])  # start, elapsed check -> 5000ms > any sane budget
        with mock.patch("airlock.keyfile.get_api_key", return_value="key"), \
             mock.patch("airlock.client.ask", side_effect=slow_ask), \
             mock.patch("time.monotonic", side_effect=lambda: next(times)):
            denied = enforce.handle(_bash_data("find / -name '*.xlsm'"), "Bash")
        self.assertFalse(denied)
        self.assertEqual(buf.getvalue(), "")
        self.assertIn("error", self._logged[-1])


class TestOverride(EnforceTestBase):
    def test_override_stamp_on_bash_description_allows_without_judging(self):
        buf = self._stdout()
        with mock.patch("airlock.client.ask") as ask:
            denied = enforce.handle(
                _bash_data("find / -name '*.xlsm'", description="[jev-ok: already scoped]"),
                "Bash",
            )
        self.assertFalse(denied)
        ask.assert_not_called()
        self.assertEqual(buf.getvalue(), "")
        entry = self._logged[-1]
        self.assertTrue(entry["override"])
        self.assertEqual(entry["override_reason"], "already scoped")

    def test_override_stamp_on_agent_prompt_allows(self):
        # Captures stdout so the hook's JSON does not reach the test output;
        # this test asserts on the return value, not on what was printed.
        self._stdout()
        with mock.patch("airlock.client.ask") as ask:
            denied = enforce.handle(
                _agent_data("fable", "d", "prior attempts failed [jev-ok: two failed workers already]"),
                "Agent",
            )
        self.assertFalse(denied)
        ask.assert_not_called()
        entry = self._logged[-1]
        self.assertTrue(entry["override"])


class TestLoopProtection(EnforceTestBase):
    def _deny_once(self):
        fake_answer = (
            {
                "model": "jev-1.13.0",
                "answers": {
                    "search_intent": {
                        "type": "choice",
                        "choice": "filename_search",
                        "confidence": 0.95,
                        "probabilities": {"filename_search": 0.95, "not_a_search": 0.05},
                    }
                },
                "usage": {},
            },
            50,
        )
        with mock.patch("airlock.keyfile.get_api_key", return_value="key"), \
             mock.patch("airlock.client.ask", return_value=fake_answer):
            return enforce.handle(_bash_data("find / -name '*.xlsm'"), "Bash")

    def test_repeat_within_window_is_allowed(self):
        buf = self._stdout()
        first = self._deny_once()
        self.assertTrue(first)
        buf.truncate(0)
        buf.seek(0)
        second = self._deny_once()
        self.assertFalse(second)
        self.assertEqual(buf.getvalue(), "")
        entry = self._logged[-1]
        self.assertTrue(entry["loop_allow"])
        self.assertFalse(entry["enforced"])

    def test_different_session_still_denied(self):
        self._stdout()
        self._deny_once()
        fake_answer = (
            {
                "model": "jev-1.13.0",
                "answers": {
                    "search_intent": {
                        "type": "choice",
                        "choice": "filename_search",
                        "confidence": 0.95,
                        "probabilities": {"filename_search": 0.95, "not_a_search": 0.05},
                    }
                },
                "usage": {},
            },
            50,
        )
        with mock.patch("airlock.keyfile.get_api_key", return_value="key"), \
             mock.patch("airlock.client.ask", return_value=fake_answer):
            denied = enforce.handle(_bash_data("find / -name '*.xlsm'", session_id="s2"), "Bash")
        self.assertTrue(denied)


if __name__ == "__main__":
    unittest.main()


class InputSummaryCapsTest(unittest.TestCase):
    """The log row is cut shorter than what Jev sees. Both come from one
    function so they cannot drift in shape, and the caps are the only
    difference (jev-kit PR #5)."""

    def _ctx(self):
        # Plain words: the redactor folds any long run without spaces (a
        # token, a deep path) into a placeholder, which is not what is
        # measured here.
        long_cmd = " ".join(["echo", "hello"] * 120)
        return {
            "tool_name": "Bash",
            "command": long_cmd,
            "tool_input": {"command": long_cmd, "description": " ".join(["some words here"] * 40)},
        }

    def test_jev_summary_keeps_the_300_char_view(self):
        s = enforce._input_summary(self._ctx())
        self.assertEqual(len(s["command"]), enforce.JEV_SUMMARY_CAP)
        self.assertEqual(len(s["description"]), enforce.JEV_SUMMARY_CAP)

    def test_log_summary_is_shorter(self):
        s = enforce._log_input_summary(self._ctx())
        self.assertEqual(len(s["command"]), enforce.LOG_COMMAND_CAP)
        self.assertEqual(len(s["description"]), enforce.LOG_FIELD_CAP)
        self.assertLess(enforce.LOG_COMMAND_CAP, enforce.JEV_SUMMARY_CAP)
        self.assertLess(enforce.LOG_FIELD_CAP, enforce.JEV_SUMMARY_CAP)


class BashDenyReasonFreshnessTests(unittest.TestCase):
    """A suggestion that runs plocate/locate warns that the index is a
    snapshot; one that only mentions plocate in prose does not."""

    def _reason(self, suggestion):
        return enforce._bash_deny_reason({"suggestion": suggestion, "scope": "broad"})

    def test_plocate_suggestion_carries_freshness_note(self):
        reason = self._reason(_policy_mod.PLOCATE_SUGGESTION)
        self.assertIn(enforce.PLOCATE_FRESHNESS_NOTE, reason)
        self.assertIn("[airlock-ok: <reason>]", reason)

    def test_system_locate_suggestion_carries_freshness_note(self):
        reason = self._reason(_policy_mod.plocate_command("system-locate"))
        self.assertIn(enforce.PLOCATE_FRESHNESS_NOTE, reason)

    def test_mixed_suggestion_carries_freshness_note(self):
        self.assertIn(enforce.PLOCATE_FRESHNESS_NOTE,
                      self._reason(_policy_mod.ES_WSL_MIXED_SUGGESTION))

    def test_note_names_no_schedule(self):
        # A --no-systemd install or the system database is not rebuilt hourly.
        self.assertNotIn("hour", enforce.PLOCATE_FRESHNESS_NOTE)

    def test_wsl_everything_only_suggestion_has_no_note(self):
        # Its prose mentions "the plocate index" but it runs only es.
        self.assertIn("plocate", _policy_mod.ES_WSL_SUGGESTION)
        self.assertNotIn(enforce.PLOCATE_FRESHNESS_NOTE,
                         self._reason(_policy_mod.ES_WSL_SUGGESTION))

    def test_everything_suggestion_has_no_note(self):
        self.assertNotIn(enforce.PLOCATE_FRESHNESS_NOTE,
                         self._reason(_policy_mod.ES_SUGGESTION))

    def test_graphify_suggestion_has_no_note(self):
        self.assertNotIn(enforce.PLOCATE_FRESHNESS_NOTE,
                         self._reason(_policy_mod.GRAPHIFY_SUGGESTION))

    def test_missing_suggestion_has_no_note(self):
        self.assertNotIn(enforce.PLOCATE_FRESHNESS_NOTE,
                         enforce._bash_deny_reason({}))
