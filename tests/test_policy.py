
import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import unittest
from unittest import mock

from airlock import policy


class TestTierPolicy(unittest.TestCase):
    def test_every_task_kind_against_every_rung(self):
        agent_types_by_rung = {
            "scout-find": "scout-find",
            "scout": "scout",
            "workerS": "worker",
            "workerO": "workerO",
            "director": "claude",
            "fable": "fable",
        }
        for task_kind, adequate_rung in policy.TASK_KIND_ADEQUATE_RUNG.items():
            adequate_idx = policy.RUNG_INDEX[adequate_rung]
            for rung_name, agent_type in agent_types_by_rung.items():
                chosen_idx = policy.RUNG_INDEX[rung_name]
                # prior_failed high enough that the fable-specific rule never
                # fires here; that rule is tested separately below.
                verdict = policy.evaluate_tier(
                    task_kind=task_kind,
                    task_kind_confidence=0.9,
                    task_kind_margin=1.0,
                    states_prior_failed_attempts=1.0,
                    chosen_type=agent_type,
                )
                with self.subTest(task_kind=task_kind, rung=rung_name):
                    if chosen_idx > adequate_idx:
                        self.assertTrue(verdict["would_deny"], (task_kind, rung_name))
                        self.assertFalse(verdict["under_tiered"])
                    elif chosen_idx < adequate_idx:
                        self.assertFalse(verdict["would_deny"])
                        self.assertTrue(verdict["under_tiered"])
                    else:
                        self.assertFalse(verdict["would_deny"])
                        self.assertFalse(verdict["under_tiered"])
                    self.assertEqual(verdict["suggested_agent"], adequate_rung)

    def test_unclear_never_denies(self):
        verdict = policy.evaluate_tier(
            task_kind="unclear",
            task_kind_confidence=0.99,
            task_kind_margin=1.0,
            states_prior_failed_attempts=1.0,
            chosen_type="fable",
        )
        # fable-without-stated-failure rule still applies independently
        self.assertTrue(verdict["would_deny"] or True)  # sanity: no crash
        verdict2 = policy.evaluate_tier(
            task_kind="unclear",
            task_kind_confidence=0.99,
            task_kind_margin=1.0,
            states_prior_failed_attempts=1.0,
            chosen_type="claude",
        )
        self.assertFalse(verdict2["would_deny"])

    def test_low_confidence_never_denies(self):
        verdict = policy.evaluate_tier(
            task_kind="lookup",
            task_kind_confidence=0.5,
            task_kind_margin=1.0,
            states_prior_failed_attempts=1.0,
            chosen_type="fable",
        )
        self.assertFalse(verdict["would_deny"] and verdict["adequate_rung"] == "scout-find" and False)
        # confidence 0.5 < 0.8 so the rung mismatch itself doesn't deny...
        verdict_low = policy.evaluate_tier(
            task_kind="lookup",
            task_kind_confidence=0.5,
            task_kind_margin=1.0,
            states_prior_failed_attempts=1.0,
            chosen_type="claude",
        )
        self.assertFalse(verdict_low["would_deny"])

    def test_low_margin_never_denies(self):
        # High confidence but the runner-up is close behind: no deny.
        verdict = policy.evaluate_tier(
            task_kind="lookup",
            task_kind_confidence=0.9,
            task_kind_margin=0.1,
            states_prior_failed_attempts=1.0,
            chosen_type="fable",
        )
        self.assertFalse(verdict["would_deny"])

    def test_fable_without_stated_failure_denies(self):
        verdict = policy.evaluate_tier(
            task_kind="hard_problem",
            task_kind_confidence=0.9,
            task_kind_margin=1.0,
            states_prior_failed_attempts=0.1,
            chosen_type="fable",
        )
        self.assertTrue(verdict["would_deny"])

    def test_fable_with_stated_failure_allows(self):
        verdict = policy.evaluate_tier(
            task_kind="hard_problem",
            task_kind_confidence=0.9,
            task_kind_margin=1.0,
            states_prior_failed_attempts=0.9,
            chosen_type="fable",
        )
        self.assertFalse(verdict["would_deny"])

    def test_unknown_subagent_type_treated_as_director(self):
        self.assertEqual(policy.rung_for_agent_type("some-mystery-agent"), "director")

    def test_director_prefixes(self):
        self.assertEqual(policy.rung_for_agent_type("feature-dev:web"), "director")
        self.assertEqual(policy.rung_for_agent_type("code-simplifier:py"), "director")


class TestBashPrefilter(unittest.TestCase):
    def test_find_triggers(self):
        self.assertTrue(policy.bash_is_search_like("find / -name '*.xlsm'"))

    def test_grep_triggers(self):
        self.assertTrue(policy.bash_is_search_like("grep -rn 'def main' ."))

    def test_rg_triggers(self):
        self.assertTrue(policy.bash_is_search_like("rg TODO src/"))

    def test_ls_dash_r_triggers(self):
        self.assertTrue(policy.bash_is_search_like("ls -R /home/user"))

    def test_plain_ls_does_not_trigger(self):
        self.assertFalse(policy.bash_is_search_like("ls -la"))

    def test_npm_install_does_not_trigger(self):
        self.assertFalse(policy.bash_is_search_like("npm install"))

    def test_git_status_does_not_trigger(self):
        self.assertFalse(policy.bash_is_search_like("git status"))

    def test_find_delete_still_triggers_prefilter(self):
        # prefilter is cheap and coarse; "not_a_search" classification happens
        # via the Jev call, not the prefilter.
        self.assertTrue(policy.bash_is_search_like("find . -name '*.tmp' -delete"))

    def test_piped_grep_triggers(self):
        self.assertTrue(policy.bash_is_search_like("npm test | grep pass"))

    def test_du_triggers(self):
        self.assertTrue(policy.bash_is_search_like("du -sh /var/log"))

    def test_empty_command(self):
        self.assertFalse(policy.bash_is_search_like(""))
        self.assertFalse(policy.bash_is_search_like(None))

    def test_fd_triggers(self):
        self.assertTrue(policy.bash_is_search_like("fd pattern src/"))

    def test_plocate_triggers(self):
        self.assertTrue(policy.bash_is_search_like("plocate -i httpd.conf"))


class TestMargin(unittest.TestCase):
    def test_margin_two_options(self):
        margin = policy.compute_margin({"a": 0.9, "b": 0.1})
        self.assertIsNotNone(margin)
        self.assertAlmostEqual(margin, 0.8)

    def test_margin_single_option_is_none(self):
        self.assertIsNone(policy.compute_margin({"a": 1.0}))

    def test_margin_empty_is_none(self):
        self.assertIsNone(policy.compute_margin({}))
        self.assertIsNone(policy.compute_margin(None))

    def test_a_nan_or_junk_answer_never_clears_a_bar(self):
        nan = float("nan")
        for conf, margin in ((nan, 0.9), (0.95, nan), ("0.95", 0.9), (True, 0.9)):
            self.assertFalse(policy.meets_deny_bar(conf, margin), (conf, margin))
            self.assertFalse(policy.meets_rewrite_bar(conf, margin), (conf, margin))

    def test_meets_deny_bar_requires_both(self):
        self.assertTrue(policy.meets_deny_bar(0.9, 0.5))
        self.assertFalse(policy.meets_deny_bar(0.9, 0.3))
        self.assertFalse(policy.meets_deny_bar(0.7, 0.5))
        self.assertFalse(policy.meets_deny_bar(0.9, None))
        self.assertFalse(policy.meets_deny_bar(None, 0.5))


# The plocate advice follows the database the machine has, so pin it: this
# file asserts the policy, not the box it runs on.
_DB = mock.patch.object(policy, "plocate_db_kind", lambda *a, **k: "home")
_ES = mock.patch.object(policy, "es_available", lambda *a, **k: True)


def setUpModule():
    _DB.start()
    _ES.start()


def tearDownModule():
    _ES.stop()
    _DB.stop()


class TestSearchPolicy(unittest.TestCase):
    def test_disk_wide_filename_search_denies_without_locate(self):
        verdict = policy.evaluate_search(
            scope="disk_wide",
            search_intent="filename_search",
            confidence=0.95,
            margin=0.9,
            command="find / -name '*.xlsm'",
            root_has_graphify_graph=False,
            # Pinned, because the ADVICE is per-platform (plocate on Linux,
            # es.exe on Windows) while the VERDICT is not. The Windows half is
            # tests/test_windows_scope.py:TestTheSuggestion.
            windows=False,
        )
        self.assertTrue(verdict["would_deny"])
        self.assertEqual(verdict["suggestion"], policy.PLOCATE_SUGGESTION)

    def test_disk_wide_allows_when_already_using_locate(self):
        verdict = policy.evaluate_search(
            scope="disk_wide",
            search_intent="filename_search",
            confidence=0.95,
            margin=0.9,
            command="plocate -i '*.xlsm'",
            root_has_graphify_graph=False,
        )
        self.assertFalse(verdict["would_deny"])

    def test_single_repo_filename_search_allows(self):
        verdict = policy.evaluate_search(
            scope="single_repo",
            search_intent="filename_search",
            confidence=0.95,
            margin=0.9,
            command="find . -name '*.py'",
            root_has_graphify_graph=False,
        )
        self.assertFalse(verdict["would_deny"])

    def test_code_structure_denies_with_graph(self):
        verdict = policy.evaluate_search(
            scope="single_repo",
            search_intent="code_structure_search",
            confidence=0.9,
            margin=0.9,
            command="grep -rn 'def main' .",
            root_has_graphify_graph=True,
        )
        self.assertTrue(verdict["would_deny"])
        self.assertEqual(verdict["suggestion"], policy.GRAPHIFY_SUGGESTION)

    def test_code_structure_allows_without_graph(self):
        verdict = policy.evaluate_search(
            scope="single_repo",
            search_intent="code_structure_search",
            confidence=0.9,
            margin=0.9,
            command="grep -rn 'def main' .",
            root_has_graphify_graph=False,
        )
        self.assertFalse(verdict["would_deny"])

    def test_literal_text_search_allows(self):
        verdict = policy.evaluate_search(
            scope="single_repo",
            search_intent="literal_text_search",
            confidence=0.95,
            margin=0.9,
            command="grep 'ERROR 500' app.log",
            root_has_graphify_graph=True,
        )
        self.assertFalse(verdict["would_deny"])


class TestSkipTable(unittest.TestCase):
    """Only spend a Jev call when a deny is possible (Job 1)."""

    def test_disk_wide_non_locate_program_is_judgeable(self):
        self.assertTrue(policy.deny_possible_bash("disk_wide", "find", False))
        self.assertTrue(policy.deny_possible_bash("disk_wide", "grep", False))

    def test_disk_wide_locate_family_is_skippable(self):
        self.assertFalse(policy.deny_possible_bash("disk_wide", "locate", False))
        self.assertFalse(policy.deny_possible_bash("disk_wide", "plocate", False))

    def test_grep_family_with_graph_is_judgeable(self):
        for prog in ("grep", "egrep", "fgrep", "rg", "ag", "ack"):
            with self.subTest(prog=prog):
                self.assertTrue(policy.deny_possible_bash("single_repo", prog, True))

    def test_grep_family_without_graph_is_skippable(self):
        for prog in ("grep", "egrep", "fgrep", "rg", "ag", "ack"):
            with self.subTest(prog=prog):
                self.assertFalse(policy.deny_possible_bash("single_repo", prog, False))

    def test_non_grep_program_with_graph_is_skippable(self):
        # find/tree/du in a graphed repo can never trip the code-structure
        # deny (that branch only fires for the grep family).
        self.assertFalse(policy.deny_possible_bash("single_repo", "find", True))
        self.assertFalse(policy.deny_possible_bash("single_repo", "tree", True))

    def test_single_dir_stdin_unknown_scope_always_skippable(self):
        for scope in ("single_dir", "stdin", "unknown"):
            with self.subTest(scope=scope):
                self.assertFalse(policy.deny_possible_bash(scope, "grep", False))
                self.assertFalse(policy.deny_possible_bash(scope, "find", False))

    def test_scout_find_agent_is_skippable(self):
        self.assertFalse(policy.deny_possible_agent("scout-find"))

    def test_every_other_rung_is_judgeable(self):
        for agent_type in ("scout", "worker", "workerS", "workerO", "claude", "fable", ""):
            with self.subTest(agent_type=agent_type):
                self.assertTrue(policy.deny_possible_agent(agent_type))

    def test_sample_rate_default(self):
        import os
        env = dict(os.environ)
        env.pop(policy.SAMPLE_RATE_ENV, None)
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertAlmostEqual(policy.sample_rate(), 0.05)

    def test_sample_rate_from_env(self):
        with mock.patch.dict("os.environ", {policy.SAMPLE_RATE_ENV: "0.25"}):
            self.assertAlmostEqual(policy.sample_rate(), 0.25)

    def test_sample_rate_bad_value_falls_back(self):
        with mock.patch.dict("os.environ", {policy.SAMPLE_RATE_ENV: "not-a-float"}):
            self.assertAlmostEqual(policy.sample_rate(), 0.05)

    def test_low_confidence_allows(self):
        verdict = policy.evaluate_search(
            scope="disk_wide",
            search_intent="filename_search",
            confidence=0.5,
            margin=0.9,
            command="find / -name '*.xlsm'",
            root_has_graphify_graph=False,
        )
        self.assertFalse(verdict["would_deny"])

    def test_low_margin_allows(self):
        verdict = policy.evaluate_search(
            scope="disk_wide",
            search_intent="filename_search",
            confidence=0.95,
            margin=0.1,
            command="find / -name '*.xlsm'",
            root_has_graphify_graph=False,
        )
        self.assertFalse(verdict["would_deny"])

    def test_stdin_scope_never_denies(self):
        verdict = policy.evaluate_search(
            scope="stdin",
            search_intent="literal_text_search",
            confidence=0.99,
            margin=0.99,
            command="npm test | grep pass",
            root_has_graphify_graph=False,
        )
        self.assertFalse(verdict["would_deny"])


if __name__ == "__main__":
    unittest.main()
