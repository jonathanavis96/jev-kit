"""R8-tier-guard ranks a dispatch by the model it runs on when `model` is set.

Issue #39: one role agent can be sent out on different models, so its type says
nothing about what it costs.
"""

import tests  # noqa: F401, I001 -- MUST be the first import (see tests/test_rules.py).

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from airlock import guards, policy, tiers


def verdict(chosen, model, task_kind="scoped_implementation", prior_failed=0.0):
    return policy.evaluate_tier(
        task_kind=task_kind, task_kind_confidence=0.95, task_kind_margin=0.8,
        states_prior_failed_attempts=prior_failed,
        chosen_type=tiers.effective_type(chosen, model))


class ModelRung(unittest.TestCase):
    def setUp(self):
        tiers.reset_cache()
        self.addCleanup(tiers.reset_cache)

    def test_the_model_picks_the_rung(self):
        self.assertEqual(tiers.effective_type("developer", "haiku"), "scout")
        self.assertEqual(tiers.effective_type("developer", "sonnet"), "workerS")
        self.assertEqual(tiers.effective_type("developer", "opus"), "workerO")
        self.assertEqual(tiers.effective_type("developer", "fable"), "fable")

    def test_a_full_model_id_counts(self):
        self.assertEqual(tiers.effective_type("developer", "claude-sonnet-5-5"), "workerS")

    def test_no_model_leaves_the_type_alone(self):
        for model in ("", None, "  "):
            self.assertEqual(tiers.effective_type("developer", model), "developer")

    def test_an_unknown_model_leaves_the_type_alone(self):
        self.assertEqual(tiers.effective_type("workerS", "inherit"), "workerS")

    def test_a_machine_ladder_may_name_models_as_rung_members(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "tiers.json")
            with open(path, "w") as f:
                json.dump([["cheap", "haiku"], ["mid", "sonnet"], ["top", "opus"]], f)
            self.assertEqual(tiers.effective_type("x", "sonnet", path=path), "mid")
            self.assertEqual(tiers.effective_type("x", "opus", path=path), "top")

    def test_a_ladder_without_the_rung_falls_back_to_the_type(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "tiers.json")
            with open(path, "w") as f:
                json.dump([["cheap"], ["top"]], f)
            self.assertEqual(tiers.effective_type("cheap", "sonnet", path=path), "cheap")


class LadderWithRenamedRungs(unittest.TestCase):
    """A machine ladder may lead a rung with another name: this is the shape of
    a real ~/.config/airlock/tiers.json, where workerS is not the first name."""

    LADDER = [["scout-find"], ["scout", "workerH"],
              ["workerSM", "workerSL", "workerSH", "workerS", "worker"],
              ["workerOL", "workerOM", "workerOH", "workerO"],
              ["director", "claude", "general-purpose", "Plan", "Explore"],
              ["fable", "workerFM", "workerFL", "workerFH"]]

    def setUp(self):
        tiers.reset_cache()
        self.addCleanup(tiers.reset_cache)
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.path = os.path.join(d.name, "tiers.json")
        with open(self.path, "w") as f:
            json.dump({"ladder": self.LADDER}, f)

    def test_the_model_finds_its_rung_by_membership(self):
        for model, rung in (("haiku", "scout"), ("sonnet", "workerSM"), ("opus", "workerOL"),
                            ("fable", "fable"), ("claude-sonnet-5-5", "workerSM"),
                            ("claude-opus-5-5", "workerOL"), ("claude-haiku-5-5", "scout")):
            self.assertEqual(tiers.rung_for_model(model, path=self.path), rung, model)

    def test_a_dispatch_is_judged_by_the_model_on_this_ladder(self):
        with mock.patch.object(tiers.paths, "config_file", return_value=self.path):
            self.assertEqual(verdict("developer", None)["chosen_rung"], "director")
            self.assertEqual(verdict("developer", "sonnet")["chosen_rung"], "workerSM")
            self.assertEqual(verdict("scout", None)["chosen_rung"], "scout")
            self.assertEqual(verdict("scout", "opus")["chosen_rung"], "workerOL")

    def test_the_rung_changes_what_is_enforced_on_this_ladder(self):
        def blocked(chosen, model):
            v = verdict(chosen, model, task_kind="lookup")
            return policy.enforce_deny_tier(policy.tier_entry_fields(
                v, "lookup", 0.95, 0.8, 0.0, tiers.effective_type(chosen, model), chosen_model=model))

        with mock.patch.object(tiers.paths, "config_file", return_value=self.path):
            self.assertTrue(blocked("developer", None))
            self.assertFalse(blocked("developer", "haiku"))
            self.assertFalse(blocked("scout", None))
            self.assertTrue(blocked("scout", "opus"))


class IssueExamples(unittest.TestCase):
    def setUp(self):
        tiers.reset_cache()
        self.addCleanup(tiers.reset_cache)

    def test_a_role_agent_on_sonnet_is_not_over_tiered(self):
        self.assertTrue(verdict("developer", None)["would_deny"])
        v = verdict("developer", "sonnet")
        self.assertEqual(v["chosen_rung"], "workerS")
        self.assertFalse(v["would_deny"])

    def test_fable_as_a_model_needs_a_stated_failure(self):
        self.assertFalse(verdict("general-purpose", None, task_kind="hard_problem")["would_deny"])
        self.assertTrue(verdict("general-purpose", "fable", task_kind="hard_problem")["would_deny"])
        self.assertFalse(verdict("general-purpose", "fable", task_kind="hard_problem",
                                 prior_failed=1.0)["would_deny"])
        entry = policy.tier_entry_fields(
            verdict("general-purpose", "fable", task_kind="hard_problem"), "hard_problem", 0.95, 0.8,
            0.0, tiers.effective_type("general-purpose", "fable"), chosen_model="fable")
        self.assertTrue(policy.enforce_deny_tier(entry))

    def test_a_fable_type_held_to_sonnet_is_not_fable(self):
        self.assertFalse(verdict("fable", "sonnet")["would_deny"])

    def test_the_cheapest_type_on_a_dearer_model_is_judged(self):
        self.assertFalse(policy.deny_possible_agent(tiers.effective_type("scout-find", None)))
        self.assertTrue(policy.deny_possible_agent(tiers.effective_type("scout-find", "opus")))

    def test_a_rewrite_never_touches_a_dispatch_with_a_model(self):
        # Changing subagent_type leaves `model` in force, so it would save nothing.
        entry = policy.tier_entry_fields(
            verdict("workerO", None, task_kind="lookup"), "lookup", 0.95, 0.8, 0.0, "workerO")
        self.assertEqual(policy.tier_rewrite_target(entry), "scout-find")
        entry["chosen_model"] = "opus"
        self.assertIsNone(policy.tier_rewrite_target(entry))


class GuardEntry(unittest.TestCase):
    def setUp(self):
        tiers.reset_cache()
        self.addCleanup(tiers.reset_cache)

    def _entry(self, **tool_input):
        answers = {"answers": {"task_kind": {"choice": "scoped_implementation", "confidence": 0.95,
                                             "probabilities": {"scoped_implementation": 0.95, "judgement": 0.05}},
                               "states_prior_failed_attempts": {"noul": 0.0}}}
        tool_input.setdefault("description", "d")
        tool_input.setdefault("prompt", "p")
        with mock.patch("airlock.guards.keyfile.get_api_key", return_value="k"), \
                mock.patch("airlock.guards.client.ask", return_value=(answers, 1)):
            return guards.compute_tier_entry({"tool_input": tool_input, "session_id": "s", "cwd": "/tmp"})

    def test_issue_example_through_the_guard(self):
        entry = self._entry(subagent_type="developer", model="sonnet")
        self.assertFalse(entry["would_deny"])
        self.assertEqual(entry["chosen"], "developer")
        self.assertEqual(entry["chosen_model"], "sonnet")
        self.assertTrue(self._entry(subagent_type="developer")["would_deny"])

    def test_fable_model_blocks_through_the_guard(self):
        entry = self._entry(subagent_type="general-purpose", model="fable")
        self.assertTrue(policy.enforce_deny_tier(entry))


if __name__ == "__main__":
    unittest.main()
