"""logtriage: redact first, local rules second, the model last.

Jev is mocked throughout. The single most important test in this file is
`test_the_model_never_sees_raw_text`: the ordering guarantee is the reason this
component exists, so it is asserted against the actual request body, not
inferred from reading the code.
"""

import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import json
import os
import re
import tempfile
import unittest
from unittest import mock

from logtriage import triage as lt


class RecordingAsk:
    """Records every request body and returns a fixed answer."""

    def __init__(self, label="attention", confidence=0.9):
        self.bodies = []
        self.label = label
        self.confidence = confidence

    def __call__(self, body):
        self.bodies.append(body)
        return {"answers": {"triage": {"choice": self.label, "confidence": self.confidence}}}


class TestRedactionComesFirst(unittest.TestCase):
    SECRETS = [
        ("apikey_abcdefghijklmnopqrstuvwx", "a TypeSafe key"),
        ("sk-ant-abcdefghijklmnopqrstuvwxyz01", "an Anthropic key"),
        ("ghp_abcdefghijklmnopqrstuvwxyz0123", "a GitHub token"),
    ]

    def test_the_model_never_sees_raw_text(self):
        """The ordering guarantee, asserted on the wire, not on the source."""
        for secret, what in self.SECRETS:
            ask = RecordingAsk()
            lt.Triager(ask=ask).triage("upstream rejected token %s for user 9" % secret)
            self.assertEqual(len(ask.bodies), 1, what)
            sent = json.dumps(ask.bodies[0])
            self.assertNotIn(secret, sent, what)
            self.assertIn("[REDACTED]", sent, what)

    def test_the_emitted_record_never_carries_raw_text(self):
        secret = "apikey_abcdefghijklmnopqrstuvwx"
        record = lt.triage_line("auth failed with %s" % secret, use_model=False)
        self.assertNotIn(secret, json.dumps(record))

    def test_even_a_locally_settled_line_is_redacted(self):
        """A local rule short-circuits before the model, so it would be easy
        for that path to skip redaction. It must not."""
        secret = "ghp_abcdefghijklmnopqrstuvwxyz0123"
        record = lt.triage_line("DEBUG: using %s" % secret, use_model=False)
        self.assertEqual(record["decided_by"], "local_rule")
        self.assertNotIn(secret, record["line"])

    def test_a_protected_line_is_redacted_and_never_sent(self):
        ask = RecordingAsk()
        record = lt.Triager(ask=ask).triage("lookup for patient 4471, sort code 20-00-00")
        self.assertTrue(record["protected"])
        self.assertFalse(record["sent_to_model"])
        self.assertEqual(ask.bodies, [], "a protected line reached the model")

    def test_long_lines_are_truncated(self):
        record = lt.triage_line("x" * 50000, use_model=False)
        self.assertLessEqual(len(record["line"]), lt.MAX_LINE_CHARS)

    def test_a_secret_straddling_the_cut_is_still_redacted(self):
        """Truncating before redacting cut `sk-...` to a stub too short for
        its pattern, and the stub went to the model in clear."""
        ask = RecordingAsk()
        line = "a" * (lt.MAX_LINE_CHARS - 6) + " sk-abcdefghijklmnop"
        lt.Triager(ask=ask).triage(line)
        sent = ask.bodies[0]["state"]["line"]
        self.assertNotIn("sk-ab", sent)


class TestLocalRulesComeSecond(unittest.TestCase):
    def _label(self, line):
        return lt.triage_line(line, use_model=False)

    def test_a_traceback_is_settled_locally(self):
        r = self._label("Traceback (most recent call last):")
        self.assertEqual((r["label"], r["decided_by"]), ("investigate", "local_rule"))

    def test_an_auth_failure_is_settled_locally(self):
        r = self._label("sshd[9]: Authentication failed for root from 10.0.0.9")
        self.assertEqual((r["label"], r["decided_by"]), ("investigate", "local_rule"))

    def test_a_health_check_is_settled_locally(self):
        r = self._label("healthcheck /healthz -> 200 ok")
        self.assertEqual((r["label"], r["decided_by"]), ("routine", "local_rule"))

    def test_an_ordinary_get_is_settled_locally(self):
        r = self._label('10.0.0.1 - - [19/Sep/2026] "GET /api/orders HTTP/1.1" 200 1843')
        self.assertEqual((r["label"], r["decided_by"]), ("routine", "local_rule"))

    def test_a_debug_line_is_noise(self):
        r = self._label("DEBUG: entering _resolve()")
        self.assertEqual((r["label"], r["decided_by"]), ("noise", "local_rule"))

    def test_a_local_rule_costs_no_model_call(self):
        ask = RecordingAsk()
        lt.Triager(ask=ask).triage("DEBUG: entering _resolve()")
        self.assertEqual(ask.bodies, [])

    def test_a_line_no_rule_settles_falls_through(self):
        ask = RecordingAsk(label="attention")
        record = lt.Triager(ask=ask).triage("upstream timed out after 5s, retrying 2 of 5")
        self.assertEqual(record["decided_by"], "model")
        self.assertEqual(record["label"], "attention")
        self.assertEqual(len(ask.bodies), 1)


class TestTheModelComesLast(unittest.TestCase):
    def test_no_model_configured_means_unclear_not_a_guess(self):
        record = lt.triage_line("something nobody has a rule for", use_model=False)
        self.assertEqual(record["label"], "unclear")
        self.assertEqual(record["decided_by"], "model_unavailable")
        self.assertFalse(record["sent_to_model"])

    def test_a_failed_call_is_unclear_not_a_crash(self):
        def boom(body):
            raise RuntimeError("api down")

        t = lt.Triager(ask=boom)
        record = t.triage("something nobody has a rule for")
        self.assertEqual(record["label"], "unclear")
        self.assertIn("api down", record["why"])
        self.assertEqual(t.stats["errors"], 1)

    def test_an_answer_outside_the_label_set_is_unclear(self):
        t = lt.Triager(ask=RecordingAsk(label="catastrophic"))
        record = t.triage("something nobody has a rule for")
        self.assertEqual(record["label"], "unclear")
        self.assertIn("not a label", record["why"])

    def test_a_junk_response_is_unclear(self):
        for response in ({}, {"answers": {}}, None, {"answers": {"triage": "x"}}):
            record = lt.Triager(ask=lambda body, r=response: r).triage("unruled line")
            self.assertEqual(record["label"], "unclear")

    def test_the_question_says_the_line_is_data_not_instructions(self):
        focus = lt.triage_question()["triage"]["instructions"]["focus"]
        self.assertIn("untrusted DATA", focus)

    def test_every_label_has_criteria(self):
        criteria = lt.triage_question()["triage"]["criteria"]
        self.assertEqual(set(criteria), set(lt.LABELS))


class TestTheCache(unittest.TestCase):
    def test_an_identical_redacted_line_is_only_asked_once(self):
        ask = RecordingAsk()
        t = lt.Triager(ask=ask)
        for _ in range(4):
            t.triage("upstream timed out after 5s, retrying")
        self.assertEqual(len(ask.bodies), 1)
        self.assertEqual(t.stats["cached"], 3)

    def test_two_lines_differing_only_in_a_secret_share_a_cache_entry(self):
        """Because the cache key is the REDACTED text, which is the point of
        redacting first: both lines are the same operational event."""
        ask = RecordingAsk()
        t = lt.Triager(ask=ask)
        t.triage("rejected token apikey_aaaaaaaaaaaaaaaaaaaa for tenant x")
        t.triage("rejected token apikey_bbbbbbbbbbbbbbbbbbbb for tenant x")
        self.assertEqual(len(ask.bodies), 1)

    def test_the_cache_is_bounded(self):
        """A long journalctl stream of unique lines must not grow memory
        without limit; the oldest entries go first."""
        ask = RecordingAsk()
        t = lt.Triager(ask=ask)
        with mock.patch.object(lt, "CACHE_MAX_ENTRIES", 3):
            for i in range(5):
                t.triage("unruled line number %d" % i)
            self.assertEqual(len(t._cache), 3)
            t.triage("unruled line number 4")
        self.assertEqual(t.stats["cached"], 1)

    def test_cache_can_be_turned_off(self):
        ask = RecordingAsk()
        t = lt.Triager(ask=ask, cache=False)
        t.triage("unruled line")
        t.triage("unruled line")
        self.assertEqual(len(ask.bodies), 2)


class TestConfig(unittest.TestCase):
    def _write(self, data):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(data, tmp)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return tmp.name

    def test_defaults_when_there_is_no_config(self):
        config = lt.load_config(None)
        self.assertEqual(config["rules"], list(lt.DEFAULT_RULES))

    def test_custom_rules_replace_the_defaults(self):
        path = self._write({"rules": [["noise", "our own banner", r"^===+$"]]})
        record = lt.triage_line("=====", config=lt.load_config(path), use_model=False)
        self.assertEqual(record["label"], "noise")

    def test_an_unknown_label_is_rejected_loudly(self):
        path = self._write({"rules": [["catastrophic", "x", "y"]]})
        with self.assertRaises(ValueError):
            lt.load_config(path)

    def test_a_broken_regex_is_rejected_loudly(self):
        path = self._write({"rules": [["noise", "x", "([unclosed"]]})
        with self.assertRaises(re.error):
            lt.load_config(path)

    def test_custom_protected_patterns_are_honoured(self):
        path = self._write({"protected": [r"(?i)\bproject codename\b"]})
        ask = RecordingAsk()
        record = lt.Triager(config=lt.load_config(path), ask=ask).triage(
            "starting job for project codename bluebird")
        self.assertTrue(record["protected"])
        self.assertEqual(ask.bodies, [])


class TestStats(unittest.TestCase):
    def test_counts_add_up(self):
        t = lt.Triager(ask=RecordingAsk())
        t.triage("DEBUG: x")
        t.triage("patient 12 seen")
        t.triage("some unruled line")
        self.assertEqual(t.stats["lines"], 3)
        self.assertEqual(t.stats["by_rule"], 1)
        self.assertEqual(t.stats["protected"], 1)
        self.assertEqual(t.stats["by_model"], 1)


class TestCli(unittest.TestCase):
    def test_main_builds_its_parser_when___doc___is_none(self):
        # __doc__ is None under python -OO (docstrings stripped). The parser
        # description reads `__doc__` before argparse ever sees `--help`, so
        # a naive `(__doc__ or "").splitlines()[0]` still raises IndexError
        # on an empty docstring -- `"".splitlines()` is `[]`, not `[""]`.
        from logtriage import cli
        with mock.patch.object(cli, "__doc__", None):
            with self.assertRaises(SystemExit) as ctx:
                cli.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
