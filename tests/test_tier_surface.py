"""The two non-blocking outcomes of the Agent tier guard: the warn that
surfaces a one-rung overshoot, and the opt-in rewrite that edits
subagent_type down a rung.

Everything here goes through enforce.handle() with a faked Jev answer, so the
tests exercise the real hook output shape rather than the policy table alone.
"""
import json
import os
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock

from airlock import enforce, guards, policy, tiers


def _hso(out):
    return ((out or {}).get("hookSpecificOutput")) or {}


def _agent_data(subagent_type, description="", prompt="", session_id="s1", extra=None):
    ti = {"subagent_type": subagent_type, "description": description, "prompt": prompt}
    if extra:
        ti.update(extra)
    return {
        "session_id": session_id,
        "cwd": "/tmp",
        "tool_name": "Agent",
        "tool_input": ti,
    }


def _answer(choice="scoped_implementation", confidence=1.0, top=1.0, runner_up=0.0,
            prior_failed=0.0):
    return (
        {
            "model": "jev-1.13.0",
            "answers": {
                "task_kind": {
                    "type": "choice",
                    "choice": choice,
                    "confidence": confidence,
                    "probabilities": {choice: top, "unclear": runner_up},
                },
                "states_prior_failed_attempts": {"type": "noul", "noul": prior_failed},
            },
            "usage": {},
        },
        50,
    )


class TierSurfaceBase(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        state_dir = Path(self._tmpdir.name) / "airlock"
        for p in (
            mock.patch("airlock.state.STATE_DIR", state_dir),
            mock.patch("airlock.state.STATE_FILE", state_dir / "loop_state.json"),
            mock.patch("airlock.log.LOG_DIR", state_dir),
            mock.patch("airlock.log.LOG_FILE", state_dir / "shadow.jsonl"),
        ):
            p.start()
            self.addCleanup(p.stop)
        self._logged = []
        lp = mock.patch("airlock.enforce.log.append", side_effect=self._logged.append)
        lp.start()
        self.addCleanup(lp.stop)
        # Rewrite mode is OFF unless a test turns it on, whatever this machine
        # happens to have configured.
        rp = mock.patch("airlock.policy.rewrite_enabled", return_value=False)
        self._rewrite_patch = rp
        rp.start()
        self.addCleanup(rp.stop)
        tiers.reset_cache()
        self.addCleanup(tiers.reset_cache)

    def _stdout(self):
        buf = StringIO()
        p = mock.patch("sys.stdout", buf)
        p.start()
        self.addCleanup(p.stop)
        return buf

    def _run(self, data, answer=None, side_effect=None):
        buf = self._stdout()
        ask_kwargs = {"side_effect": side_effect} if side_effect else {"return_value": answer}
        with mock.patch("airlock.keyfile.get_api_key", return_value="key"), \
             mock.patch("airlock.client.ask", **ask_kwargs):
            denied = enforce.handle(data, "Agent")
        raw = buf.getvalue()
        return denied, (json.loads(raw) if raw.strip() else None)


class TestWarnShape(TierSurfaceBase):
    def test_one_rung_overshoot_warns_and_never_blocks(self):
        denied, out = self._run(
            _agent_data("workerO", "add a flag", "Add a --json flag; the shape is already defined."),
            _answer("scoped_implementation"),
        )
        self.assertFalse(denied)
        self.assertIsNotNone(out)
        hso = _hso(out)
        self.assertEqual(hso["hookEventName"], "PreToolUse")
        # A warn allows: no permissionDecision of deny/ask anywhere.
        self.assertNotEqual(hso.get("permissionDecision"), "deny")
        self.assertNotEqual(hso.get("permissionDecision"), "ask")
        text = hso["additionalContext"]
        self.assertIn("workerO", text)          # what was chosen
        self.assertIn("workerS", text)          # what is adequate, and the exact type
        self.assertIn("subagent_type=workerS", text)
        self.assertIn("nothing was blocked", text)
        self.assertEqual(len(text.strip().split("\n")), 2)
        entry = self._logged[-1]
        self.assertEqual(entry["surfaced"], "warn")
        self.assertFalse(entry["enforced"])

    def test_two_rung_overshoot_still_blocks(self):
        denied, out = self._run(
            _agent_data("claude", "find it", "Where is AIRLOCK_DISABLE checked?"),
            _answer("lookup", prior_failed=0.9),
        )
        self.assertTrue(denied)
        self.assertEqual(_hso(out)["permissionDecision"], "deny")
        self.assertIsNone(self._logged[-1].get("surfaced"))


class TestSilenceBelowTheBars(TierSurfaceBase):
    def test_low_confidence_says_nothing(self):
        denied, out = self._run(
            _agent_data("workerO", "d", "p"),
            _answer("scoped_implementation", confidence=0.7, top=0.7, runner_up=0.3),
        )
        self.assertFalse(denied)
        self.assertIsNone(out)
        self.assertIsNone(self._logged[-1].get("surfaced"))

    def test_low_margin_says_nothing(self):
        denied, out = self._run(
            _agent_data("workerO", "d", "p"),
            _answer("scoped_implementation", confidence=0.9, top=0.5, runner_up=0.45),
        )
        self.assertFalse(denied)
        self.assertIsNone(out)

    def test_unclear_task_kind_says_nothing(self):
        denied, out = self._run(_agent_data("workerO", "d", "p"), _answer("unclear"))
        self.assertFalse(denied)
        self.assertIsNone(out)

    def test_correct_rung_says_nothing(self):
        denied, out = self._run(_agent_data("workerO", "d", "p"), _answer("judgement"))
        self.assertFalse(denied)
        self.assertIsNone(out)


class TestRewriteOffByDefault(TierSurfaceBase):
    def test_no_flag_file_and_no_env_means_off(self):
        self._rewrite_patch.stop()
        with tempfile.TemporaryDirectory() as d:
            env = {k: v for k, v in os.environ.items() if k != policy.REWRITE_ENV}
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch("airlock.paths.config_dir", return_value=Path(d)):
                self.assertFalse(policy.rewrite_enabled())
        self._rewrite_patch.start()

    def test_flag_file_turns_it_on(self):
        self._rewrite_patch.stop()
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / policy.REWRITE_FLAG_FILE).write_text("")
            env = {k: v for k, v in os.environ.items() if k != policy.REWRITE_ENV}
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch("airlock.paths.config_dir", return_value=Path(d)):
                self.assertTrue(policy.rewrite_enabled())
        self._rewrite_patch.start()

    def test_env_var_turns_it_on(self):
        self._rewrite_patch.stop()
        with mock.patch.dict(os.environ, {policy.REWRITE_ENV: "1"}):
            self.assertTrue(policy.rewrite_enabled())
        self._rewrite_patch.start()

    def test_default_run_only_warns(self):
        denied, out = self._run(_agent_data("workerO", "d", "Add a --json flag."),
                                _answer("scoped_implementation"))
        self.assertFalse(denied)
        self.assertNotIn("updatedInput", _hso(out))
        self.assertEqual(self._logged[-1]["surfaced"], "warn")


class RewriteOnBase(TierSurfaceBase):
    def setUp(self):
        super().setUp()
        self._rewrite_patch.stop()
        p = mock.patch("airlock.policy.rewrite_enabled", return_value=True)
        p.start()
        self.addCleanup(p.stop)


class TestRewriteShape(RewriteOnBase):
    def test_rewrites_subagent_type_and_preserves_every_other_field(self):
        # No `model` here: a set model is what the dispatch is judged by, and a
        # rewrite could not change it (tests/test_tier_model.py).
        extra = {"name": "flagger", "run_in_background": True, "isolation": "worktree"}
        data = _agent_data("workerO", "add a flag", "Add a --json flag.", extra=extra)
        original = json.loads(json.dumps(data["tool_input"]))
        denied, out = self._run(data, _answer("scoped_implementation"))
        self.assertTrue(denied)  # stdout was written; the rule loop stops
        hso = _hso(out)
        self.assertEqual(hso["permissionDecision"], "allow")
        updated = hso["updatedInput"]
        self.assertEqual(updated["subagent_type"], "workerS")
        for k, v in original.items():
            if k == "subagent_type":
                continue
            self.assertEqual(updated[k], v, k)
        self.assertEqual(set(updated), set(original))
        self.assertIn("workerO", hso["additionalContext"])
        self.assertIn("workerS", hso["additionalContext"])
        self.assertIn("[airlock-ok:", hso["additionalContext"])
        entry = self._logged[-1]
        self.assertEqual(entry["surfaced"], "rewrite")
        self.assertEqual(entry["rewrote_from"], "workerO")
        self.assertEqual(entry["rewrote_to"], "workerS")
        self.assertFalse(entry["enforced"])

    def test_rewrite_replaces_a_two_rung_block(self):
        denied, out = self._run(
            _agent_data("claude", "find it", "Where is AIRLOCK_DISABLE checked?"),
            _answer("lookup", prior_failed=0.9),
        )
        self.assertTrue(denied)
        hso = _hso(out)
        self.assertEqual(hso["permissionDecision"], "allow")
        self.assertEqual(hso["updatedInput"]["subagent_type"], "scout-find")

    def test_below_the_stricter_bar_warns_instead_of_rewriting(self):
        # Clears the warn bar (0.8 / 0.4) but not the rewrite bar (0.9 / 0.5).
        denied, out = self._run(
            _agent_data("workerO", "d", "p"),
            _answer("scoped_implementation", confidence=0.85, top=0.6, runner_up=0.15),
        )
        self.assertFalse(denied)
        self.assertNotIn("updatedInput", _hso(out))
        self.assertEqual(self._logged[-1]["surfaced"], "warn")


class TestNeverUpward(RewriteOnBase):
    def test_under_tiered_dispatch_is_never_rewritten_or_warned(self):
        denied, out = self._run(
            _agent_data("scout", "d", "Diagnose why the daemon deadlocks."),
            _answer("hard_problem", prior_failed=0.9),
        )
        self.assertFalse(denied)
        self.assertIsNone(out)
        entry = self._logged[-1]
        self.assertTrue(entry["under_tiered"])
        self.assertIsNone(entry.get("surfaced"))

    def test_policy_refuses_any_target_that_is_not_cheaper(self):
        entry = {
            "chosen_type": "scout-find", "rung_diff": 1, "task_kind": "judgement",
            "task_kind_confidence": 1.0, "margin": 1.0, "suggestion": "workerO",
        }
        self.assertIsNone(policy.tier_rewrite_target(entry))


class TestFableIsNeverRewritten(RewriteOnBase):
    def test_fable_with_stated_prior_failure_is_blocked_not_rewritten(self):
        """The human has given the reason the ladder asks for. Rewriting that
        away would ignore it, so the two-rung block stands instead."""
        denied, out = self._run(
            _agent_data("fable", "hard one",
                        "Two attempts failed: worker, then Opus. Root cause still unknown."),
            _answer("judgement", prior_failed=0.95),
        )
        self.assertTrue(denied)
        self.assertEqual(_hso(out).get("permissionDecision"), "deny")
        self.assertIsNone(self._logged[-1].get("surfaced"))

    def test_fable_with_unclear_task_kind_still_blocks(self):
        denied, out = self._run(
            _agent_data("fable", "d", "Just do this refactor."),
            _answer("unclear", prior_failed=0.0),
        )
        self.assertTrue(denied)
        self.assertEqual(_hso(out).get("permissionDecision"), "deny")
        self.assertIn("prior failed", _hso(out)["permissionDecisionReason"])


class TestOverrideStampWins(RewriteOnBase):
    def test_stamp_in_description_prevents_rewrite(self):
        denied, out = self._run(
            _agent_data("workerO", "add a flag [airlock-ok: I want the extra judgement]",
                        "Add a --json flag."),
            _answer("scoped_implementation"),
        )
        self.assertFalse(denied)
        self.assertIsNone(out)
        self.assertTrue(self._logged[-1]["override"])

    def test_stamp_in_prompt_prevents_rewrite(self):
        denied, out = self._run(
            _agent_data("workerO", "add a flag", "Add a --json flag. [jev-ok: deliberate]"),
            _answer("scoped_implementation"),
        )
        self.assertFalse(denied)
        self.assertIsNone(out)


class TestFailOpen(TierSurfaceBase):
    def test_jev_error_surfaces_nothing(self):
        denied, out = self._run(_agent_data("workerO", "d", "p"),
                                side_effect=ConnectionRefusedError("no daemon"))
        self.assertFalse(denied)
        self.assertIsNone(out)

    def test_exception_inside_the_surface_path_never_blocks(self):
        with mock.patch("airlock.enforce._agent_warn_text", side_effect=RuntimeError("boom")):
            denied, out = self._run(_agent_data("workerO", "d", "Add a --json flag."),
                                    _answer("scoped_implementation"))
        self.assertFalse(denied)
        self.assertIsNone(out)

    def test_exception_inside_the_rewrite_path_never_blocks(self):
        with mock.patch("airlock.policy.rewrite_enabled", return_value=True), \
             mock.patch("airlock.enforce.emit_rewrite", side_effect=RuntimeError("boom")):
            denied, out = self._run(_agent_data("workerO", "d", "Add a --json flag."),
                                    _answer("scoped_implementation"))
        self.assertFalse(denied)
        self.assertIsNone(out)


class TestLogFieldsFilled(TierSurfaceBase):
    """The live log's Agent rows carried `chosen: null, adequate: null,
    detail: null`, so a row could not say what it had judged."""

    def _entry(self, data, answer=None, side_effect=None):
        ask_kwargs = {"side_effect": side_effect} if side_effect else {"return_value": answer}
        with mock.patch("airlock.keyfile.get_api_key", return_value="key"), \
             mock.patch("airlock.client.ask", **ask_kwargs):
            return guards.compute_tier_entry(data)

    def _assert_filled(self, entry):
        for field in ("chosen", "adequate", "detail"):
            self.assertIsNotNone(entry.get(field), field)
            self.assertNotEqual(entry.get(field), "", field)

    def test_judged_row(self):
        entry = self._entry(_agent_data("workerO", "d", "p"), _answer("scoped_implementation"))
        self._assert_filled(entry)
        self.assertEqual(entry["chosen"], "workerO")
        self.assertEqual(entry["adequate"], "workerS")
        self.assertIn("scoped_implementation", entry["detail"])

    def test_skipped_row(self):
        with mock.patch("airlock.policy.sample_rate", return_value=0.0):
            entry = self._entry(_agent_data("scout-find", "d", "p"), _answer("lookup"))
        self.assertEqual(entry["skipped"], "no_deny_possible")
        self._assert_filled(entry)
        self.assertEqual(entry["chosen"], "scout-find")
        self.assertEqual(entry["adequate"], guards.NOT_JUDGED)

    def test_error_row(self):
        entry = self._entry(_agent_data("workerO", "d", "p"),
                            side_effect=TimeoutError("timed out"))
        self.assertIn("error", entry)
        self._assert_filled(entry)
        self.assertEqual(entry["adequate"], guards.NOT_JUDGED)


class TestLadderConfig(unittest.TestCase):
    def setUp(self):
        tiers.reset_cache()
        self.addCleanup(tiers.reset_cache)

    def _write(self, content):
        d = tempfile.mkdtemp()
        p = Path(d) / "tiers.json"
        p.write_text(content if isinstance(content, str) else json.dumps(content))
        return str(p)

    def test_default_ladder_when_no_config(self):
        self.assertEqual(tiers.rung_names("/nonexistent/tiers.json"),
                         [r[0] for r in tiers.DEFAULT_LADDER])

    def test_machine_ladder_renames_the_rungs(self):
        path = self._write([["finder"], ["tinker"], ["builder", "worker"], ["thinker"]])
        self.assertEqual(tiers.rung_for_agent_type("worker", path), "builder")
        self.assertEqual(tiers.dispatch_name_for_rung("builder", path), "builder")
        # Unknown types land one rung below the top, as before.
        self.assertEqual(tiers.rung_for_agent_type("mystery", path), "builder")

    def test_malformed_config_falls_back_whole(self):
        for bad in ("not json at all", "[]", '[["a"], []]', '[["a"], ["a"]]', '[["a"]]',
                    '[["a"], [1]]', '{"ladder": "nope"}'):
            path = self._write(bad)
            tiers.reset_cache()
            self.assertEqual(tiers.load_ladder(path), [list(r) for r in tiers.DEFAULT_LADDER], bad)

    def test_director_rung_is_never_a_rewrite_target(self):
        self.assertEqual(tiers.dispatch_name_for_rung("director"), "claude")
        self.assertFalse(tiers.is_known_agent_type("not-a-real-agent"))

    def test_unknown_target_is_refused(self):
        entry = {
            "chosen_type": "claude", "rung_diff": 2, "task_kind": "lookup",
            "task_kind_confidence": 1.0, "margin": 1.0, "suggestion": "no-such-rung",
        }
        self.assertIsNone(policy.tier_rewrite_target(entry))


if __name__ == "__main__":
    unittest.main()
