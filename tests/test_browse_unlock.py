import tests  # noqa: F401 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from tests import posix_only

from airlock import browse_state
from airlock import enforce

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK_PATH = os.path.join(REPO_ROOT, "hooks", "airlock_browse_unlock.py")

_spec = importlib.util.spec_from_file_location("airlock_browse_unlock_hook", HOOK_PATH)
assert _spec is not None and _spec.loader is not None
hook = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hook)

BROWSE_TOOL = "mcp__browse__browse"


def blocked_response(goal_url="https://en.wikipedia.org/wiki/Photosynthesis"):
    """The real success-shaped response, as a transcript on this box records
    it: a LIST of content blocks whose text is browse/server.py's JSON."""
    body = {"final_url": goal_url, "title": "Photosynthesis", "status": "blocked",
            "steps": 6, "elapsed_ms": 41234, "text": "..."}
    return [{"type": "text", "text": json.dumps(body)}]


def done_response():
    body = {"final_url": "https://example.com", "title": "Example Domain",
            "status": "done", "steps": 2, "elapsed_ms": 3100,
            "text": "Example Domain"}
    return [{"type": "text", "text": json.dumps(body)}]


def payload(response, session_id="sess-browse", goal="click through to X"):
    return {"session_id": session_id, "cwd": "/tmp",
            "hook_event_name": "PostToolUse", "tool_name": BROWSE_TOOL,
            "tool_input": {"goal": goal, "start_url": "https://example.com"},
            "tool_response": response}


def failure_payload(error="browse failed: ValueError: Stopped at the 60-action demo budget",
                    session_id="sess-browse", goal="click through to X",
                    is_interrupt=False, event="PostToolUseFailure"):
    """What Claude Code sends when the `browse` call itself raised: no
    `tool_response`, an `error` string and `is_interrupt` instead."""
    p = {"session_id": session_id, "cwd": "/tmp", "tool_name": BROWSE_TOOL,
         "tool_input": {"goal": goal, "start_url": "https://example.com"},
         "error": error, "is_interrupt": is_interrupt}
    if event:
        p["hook_event_name"] = event
    return p


class BrowseStateCase(unittest.TestCase):
    """Every test gets its own state file, the way tests/test_state.py does."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        state_dir = Path(self._tmpdir.name) / "airlock"
        for p in (mock.patch.object(browse_state, "STATE_DIR", state_dir),
                  mock.patch.object(browse_state, "STATE_FILE",
                                    state_dir / "browse_unlock.json")):
            p.start()
            self.addCleanup(p.stop)


class TestBrowseState(BrowseStateCase):
    def test_nothing_recorded_means_locked(self):
        self.assertFalse(browse_state.unlocked("s1"))
        self.assertIsNone(browse_state.recent_give_up("s1"))

    def test_a_blocked_row_unlocks_that_session(self):
        self.assertTrue(browse_state.record_gave_up("s1", "blocked", goal="hop to X"))
        row = browse_state.recent_give_up("s1")
        self.assertEqual(row["status"], "blocked")
        self.assertEqual(row["goal"], "hop to X")
        self.assertTrue(browse_state.unlocked("s1"))

    def test_an_error_row_unlocks_too(self):
        """A broken `browse` must not strand a session with no browser."""
        self.assertTrue(browse_state.record_gave_up("s1", "error", goal="anything"))
        self.assertTrue(browse_state.unlocked("s1"))

    def test_a_status_that_is_not_giving_up_records_nothing(self):
        for status in ("done", "", None, "partial"):
            self.assertFalse(browse_state.record_gave_up("s1", status))
        self.assertFalse(browse_state.unlocked("s1"))

    def test_another_session_is_not_unlocked(self):
        browse_state.record_gave_up("s1", "blocked")
        self.assertFalse(browse_state.unlocked("s2"))

    def test_the_row_expires_after_thirty_minutes(self):
        browse_state.record_gave_up("s1", "blocked")
        self.assertEqual(browse_state.UNLOCK_WINDOW_S, 1800)
        with mock.patch("time.time", return_value=time.time() + 1801):
            self.assertFalse(browse_state.unlocked("s1"))

    def test_expired_rows_are_pruned_on_the_next_write(self):
        browse_state.record_gave_up("old", "blocked")
        with mock.patch("time.time", return_value=time.time() + 1801):
            browse_state.record_gave_up("new", "blocked")
            data = json.loads(browse_state.STATE_FILE.read_text())
        self.assertEqual(list(data), ["new"])

    def test_an_unreadable_file_reads_as_locked(self):
        browse_state.record_gave_up("s1", "blocked")
        with mock.patch.object(browse_state, "_open_locked",
                               side_effect=OSError("no")):
            self.assertFalse(browse_state.unlocked("s1"))
            self.assertFalse(browse_state.record_gave_up("s2", "blocked"))

    def test_a_row_stamped_in_the_future_does_not_unlock(self):
        """A clock stepped backwards (or a hand-edited ts) must not leave the
        door open forever: a negative age reads as stale."""
        browse_state.record_gave_up("s1", "blocked")
        with mock.patch("time.time", return_value=time.time() - 7200):
            self.assertFalse(browse_state.unlocked("s1"))

    def test_corrupt_json_reads_as_locked_and_never_raises(self):
        browse_state.STATE_DIR.mkdir(parents=True, exist_ok=True)
        browse_state.STATE_FILE.write_text("{not json")
        self.assertFalse(browse_state.unlocked("s1"))

    @posix_only("a POSIX mode; on Windows privacy comes from the\n"
                "            %LOCALAPPDATA% ACL instead -- see\n"
                "            tests/test_windows_platform.py:TestPermissions")
    def test_file_mode_is_owner_only(self):
        browse_state.record_gave_up("s1", "blocked")
        self.assertEqual(browse_state.STATE_FILE.stat().st_mode & 0o777, 0o600)
        self.assertEqual(browse_state.STATE_DIR.stat().st_mode & 0o777, 0o700)


class TestHookParsing(unittest.TestCase):
    """The hook reads a PostToolUse payload. Every response shape a real
    transcript on this box carries is handled, and anything else is ignored."""

    def test_a_blocked_result_in_the_content_list_shape(self):
        found = hook.outcome(payload(blocked_response()))
        self.assertEqual(found[0], "blocked")
        self.assertEqual(found[1], "click through to X")
        self.assertEqual(found[2], "https://en.wikipedia.org/wiki/Photosynthesis")

    def test_a_blocked_result_in_the_call_tool_result_shape(self):
        resp = {"content": blocked_response(), "isError": False}
        self.assertEqual(hook.outcome(payload(resp))[0], "blocked")

    def test_a_blocked_result_already_decoded(self):
        resp = {"final_url": "https://x", "status": "blocked", "steps": 3}
        self.assertEqual(hook.outcome(payload(resp))[0], "blocked")

    def test_a_done_result_records_nothing(self):
        self.assertIsNone(hook.outcome(payload(done_response())))
        self.assertIsNone(hook.outcome(payload({"content": done_response()})))

    def test_an_error_string_counts_as_a_failure(self):
        """The real shape of a failed MCP call in a transcript here."""
        text = ("Error: browse failed: a Chromium this server did not start is "
                "already running (pid 2956854) and nothing answers at BU_CDP_URL")
        self.assertEqual(hook.outcome(payload(text))[0], "error")

    def test_an_iserror_flag_counts_as_a_failure(self):
        resp = {"content": [{"type": "text", "text": "the server went away"}],
                "isError": True}
        self.assertEqual(hook.outcome(payload(resp))[0], "error")

    def test_an_unparseable_response_records_nothing_and_never_raises(self):
        for response in (None, 17, [], [{"type": "image"}], {}, "",
                         {"content": 3}, ["not a block"], "plain prose"):
            self.assertIsNone(hook.outcome(payload(response)), repr(response))

    def test_a_malformed_payload_records_nothing_and_never_raises(self):
        for bad in (None, [], "", 3, {"tool_name": None}, {"tool_input": 5}):
            self.assertIsNone(hook.outcome(bad), repr(bad))

    def test_only_the_browse_tool_is_watched(self):
        for tool in ("Bash", "mcp__playwright__browser_navigate",
                     "mcp__github__browse_repo", "browse", "mcp__browse",
                     "mcp__playwright-ads__browser_click"):
            p = payload(blocked_response())
            p["tool_name"] = tool
            self.assertIsNone(hook.outcome(p), tool)

    def test_a_post_tool_use_failure_counts_as_a_failure(self):
        """The shape that was missed: a `browse` call that raised arrives on
        PostToolUseFailure, with no `tool_response` to read."""
        self.assertEqual(hook.outcome(failure_payload()),
                         ("error", "click through to X", "https://example.com"))

    def test_a_failure_without_an_event_name_still_counts(self):
        self.assertEqual(hook.outcome(failure_payload(event=None))[0], "error")

    def test_a_failure_with_any_error_text_counts(self):
        for error in ("", "the server went away", "Exit code 1"):
            self.assertEqual(hook.outcome(failure_payload(error=error))[0],
                             "error", error)

    def test_an_interrupt_records_nothing(self):
        """Esc from the user says nothing about whether `browse` could do it."""
        self.assertIsNone(hook.outcome(failure_payload(is_interrupt=True)))

    def test_a_failure_of_another_tool_records_nothing(self):
        p = failure_payload()
        p["tool_name"] = "mcp__playwright__browser_navigate"
        self.assertIsNone(hook.outcome(p))

    def test_a_post_tool_use_payload_with_an_error_key_is_read_normally(self):
        """The event name wins over the shape: a PostToolUse `done` result is
        still a success even if some host also carries an `error` field."""
        p = payload(done_response())
        p["error"] = "irrelevant"
        self.assertIsNone(hook.outcome(p))

    def test_a_differently_named_browse_server_still_counts(self):
        p = payload(blocked_response())
        p["tool_name"] = "mcp__jev-browse__browse"
        self.assertEqual(hook.outcome(p)[0], "blocked")


class TestHookEndToEnd(unittest.TestCase):
    """The installed entry point, driven exactly as Claude Code drives it:
    one JSON payload on stdin, nothing expected on stdout, exit 0."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.home = self._tmpdir.name
        self.state_dir = os.path.join(self.home, ".local", "state", "airlock")

    def run_hook(self, payload_obj):
        env = dict(os.environ)
        env["HOME"] = self.home
        env["AIRLOCK_STATE_DIR"] = self.state_dir
        env["AIRLOCK_CONFIG_DIR"] = os.path.join(self.home, ".config", "airlock")
        proc = subprocess.run(
            [sys.executable, HOOK_PATH],
            input=json.dumps(payload_obj) if not isinstance(payload_obj, str) else payload_obj,
            capture_output=True, text=True, env=env, timeout=30)
        return proc

    def rows(self):
        path = os.path.join(self.state_dir, "browse_unlock.json")
        if not os.path.isfile(path):
            return {}
        with open(path) as f:
            return json.load(f)

    def test_a_blocked_call_writes_the_row_and_says_nothing(self):
        proc = self.run_hook(payload(blocked_response(), session_id="live-1"))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "")
        rows = self.rows()
        self.assertIn("live-1", rows)
        self.assertEqual(rows["live-1"]["status"], "blocked")
        self.assertEqual(rows["live-1"]["goal"], "click through to X")

    def test_a_done_call_writes_nothing(self):
        proc = self.run_hook(payload(done_response(), session_id="live-2"))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(self.rows(), {})

    def test_rubbish_on_stdin_exits_zero_and_writes_nothing(self):
        for raw in ("", "not json at all", "[1,2,3]", "null"):
            proc = self.run_hook(raw)
            self.assertEqual(proc.returncode, 0, raw)
            self.assertEqual(proc.stderr, "", raw)
        self.assertEqual(self.rows(), {})

    def test_a_failed_call_writes_an_error_row_and_says_nothing(self):
        proc = self.run_hook(failure_payload(session_id="live-4"))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "")
        self.assertEqual(self.rows()["live-4"]["status"], "error")

    def test_another_tool_is_ignored(self):
        p = payload(blocked_response(), session_id="live-3")
        p["tool_name"] = "Bash"
        self.assertEqual(self.run_hook(p).returncode, 0)
        self.assertEqual(self.rows(), {})


class TestR11Unlocked(BrowseStateCase):
    """R11 in the enforce path, with and without a `browse` failure behind it.

    Everything else about the rule stays strict: these tests assert the deny
    is still there when no row exists, and tests/test_rules.py asserts the
    stamp and the repeat still do nothing."""

    TOOL = "mcp__plugin_playwright_playwright__browser_navigate"
    SESSION = "sess-unlock"

    def setUp(self):
        super(TestR11Unlocked, self).setUp()
        self.logged = []
        for p in (mock.patch("airlock.log.append", side_effect=self.logged.append),
                  mock.patch("airlock.rules.load_action_overrides", return_value={}),
                  mock.patch("airlock.state.was_recently_denied", return_value=False),
                  mock.patch("airlock.state.record_denial")):
            p.start()
            self.addCleanup(p.stop)

    def _payload(self, session_id=None, **ti):
        return {"session_id": session_id or self.SESSION, "cwd": "/tmp",
                "tool_name": self.TOOL,
                "tool_input": ti or {"url": "https://example.com"}}

    def _run(self, payload_obj, mode="enforce"):
        with mock.patch("airlock.client.ask",
                        side_effect=AssertionError("R11 must never call Jev")), \
             mock.patch.object(enforce, "emit_deny") as deny, \
             mock.patch.object(enforce, "emit_warn") as warn:
            denied = enforce.handle(payload_obj, self.TOOL, mode)
        return denied, deny, warn

    def test_no_record_still_denies(self):
        denied, deny, warn = self._run(self._payload())
        self.assertTrue(denied)
        deny.assert_called_once()
        warn.assert_not_called()
        self.assertNotIn("unlocked_by", self.logged[-1])

    def test_a_blocked_browse_turns_the_deny_into_a_warn(self):
        browse_state.record_gave_up(self.SESSION, "blocked",
                                    goal="Photosynthesis to Chlorophyll by links")
        denied, deny, warn = self._run(self._payload())
        self.assertFalse(denied)
        deny.assert_not_called()
        warn.assert_called_once()
        text = warn.call_args[0][0][0]
        self.assertIn("R11-browse-via-jev", text)
        self.assertIn("blocked", text)
        self.assertIn("Photosynthesis to Chlorophyll", text)
        self.assertIn("30 minutes", text)
        row = self.logged[-1]
        self.assertEqual(row["unlocked_by"], "browse_blocked")
        self.assertEqual(row["browse_status"], "blocked")
        self.assertEqual(row["action"], "warn")
        self.assertFalse(row["enforced"])
        self.assertTrue(row["warned"])

    def test_the_notice_is_said_once_per_unlock_window(self):
        browse_state.record_gave_up(self.SESSION, "error", goal="open a page")
        denied, _, warn = self._run(self._payload())
        self.assertFalse(denied)
        warn.assert_called_once()
        self.assertTrue(self.logged[-1]["announced"])
        for _ in range(3):
            denied, deny, warn = self._run(self._payload())
            self.assertFalse(denied)
            deny.assert_not_called()
            warn.assert_not_called()
            self.assertFalse(self.logged[-1]["announced"])
            self.assertEqual(self.logged[-1]["unlocked_by"], "browse_blocked")
        # A fresh `browse` failure opens a new window, which announces again.
        browse_state.record_gave_up(self.SESSION, "blocked", goal="another goal")
        _, _, warn = self._run(self._payload())
        warn.assert_called_once()

    def test_a_browse_error_unlocks_as_well(self):
        browse_state.record_gave_up(self.SESSION, "error", goal="open a page")
        denied, deny, warn = self._run(self._payload())
        self.assertFalse(denied)
        warn.assert_called_once()
        self.assertIn("errored", warn.call_args[0][0][0])
        self.assertEqual(self.logged[-1]["browse_status"], "error")

    def test_an_expired_record_denies_again(self):
        browse_state.record_gave_up(self.SESSION, "blocked")
        with mock.patch("time.time", return_value=time.time() + 1801):
            denied, deny, _ = self._run(self._payload())
        self.assertTrue(denied)
        deny.assert_called_once()
        self.assertNotIn("unlocked_by", self.logged[-1])

    def test_a_different_session_is_not_unlocked(self):
        browse_state.record_gave_up("somebody-else", "blocked")
        denied, deny, _ = self._run(self._payload())
        self.assertTrue(denied)
        deny.assert_called_once()

    def test_a_stamp_is_still_refused_once_unlocked(self):
        """The unlock is not a licence: the call is allowed because `browse`
        failed, and the row says so rather than crediting a stamp."""
        browse_state.record_gave_up(self.SESSION, "blocked")
        denied, _deny, _warn = self._run(self._payload(
            url="https://x", element="a link [airlock-ok: I want playwright]"))
        self.assertFalse(denied)
        row = self.logged[-1]
        self.assertEqual(row["unlocked_by"], "browse_blocked")
        self.assertNotIn("override", row)

    def test_a_broken_state_file_leaves_the_rule_strict(self):
        browse_state.record_gave_up(self.SESSION, "blocked")
        with mock.patch.object(browse_state, "recent_give_up",
                               side_effect=OSError("boom")):
            denied, deny, _ = self._run(self._payload())
        self.assertTrue(denied)
        deny.assert_called_once()

    def test_shadow_mode_records_the_unlock_rather_than_a_would_be_deny(self):
        browse_state.record_gave_up(self.SESSION, "blocked")
        denied, deny, _ = self._run(self._payload(), mode="shadow")
        self.assertFalse(denied)
        deny.assert_not_called()
        row = self.logged[-1]
        self.assertEqual(row["unlocked_by"], "browse_blocked")
        self.assertNotIn("would_enforce", row)

    def test_the_hook_and_the_rule_meet_end_to_end(self):
        """The whole path in one test: the PostToolUse payload goes in, and
        the next Playwright call in that session comes back allowed."""
        found = hook.outcome(payload(blocked_response(), session_id=self.SESSION))
        self.assertIsNotNone(found)
        status, goal, url = found
        browse_state.record_gave_up(self.SESSION, status, goal=goal, url=url)
        denied, deny, warn = self._run(self._payload())
        self.assertFalse(denied)
        deny.assert_not_called()
        warn.assert_called_once()

    def test_a_failed_browse_call_unlocks_end_to_end(self):
        """The same path from a PostToolUseFailure payload, the shape a
        `browse` call that raised actually produces."""
        found = hook.outcome(failure_payload(session_id=self.SESSION))
        self.assertIsNotNone(found)
        status, goal, url = found
        browse_state.record_gave_up(self.SESSION, status, goal=goal, url=url)
        denied, deny, warn = self._run(self._payload())
        self.assertFalse(denied)
        deny.assert_not_called()
        warn.assert_called_once()


if __name__ == "__main__":
    unittest.main()
