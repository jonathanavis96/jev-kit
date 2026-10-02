"""docclass: the two-stage Choice, the escape hatch and the confidence gate.

Jev is mocked throughout: `classify_page` takes its `ask` as an argument
precisely so these can run with no key and no network.

The cases that matter are the ones where the model is NOT confidently right:
a page that is none of the listed kinds, a low confidence, an answer that is
not one of the offered options. Those are what the escape hatch and the gate
exist for, and they are what separates this from a classifier that files
everything somewhere.
"""

import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import json
import unittest
from unittest import mock

from docclass import classify as dc

TAXONOMY = {
    "name": "test taxonomy",
    "confidence_gate": 0.8,
    "families": {
        "letter": {
            "what": "Correspondence from one party to another.",
            "members": {
                "covering_letter": {"what": "Introduces an enclosure."},
                "chasing_letter": {"what": "Asks for something outstanding."},
            },
        },
        "invoice": {"what": "A demand for payment."},
    },
}


class FakeAsk:
    """Returns queued answers in order and records every request, so a test
    can assert on how MANY calls were made as well as on the result."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, body):
        self.calls.append(body)
        if not self.answers:
            raise AssertionError("classify_page made more calls than the test queued")
        key, choice, confidence = self.answers.pop(0)
        return {"answers": {key: {"choice": choice, "confidence": confidence}}}


def _ask(*answers):
    return FakeAsk(*answers)


class TestValidateTaxonomy(unittest.TestCase):
    def test_a_good_taxonomy_passes(self):
        self.assertIs(dc.validate_taxonomy(TAXONOMY), TAXONOMY)

    def test_the_shipped_example_is_valid(self):
        dc.validate_taxonomy(dc.load_taxonomy(dc.default_taxonomy_path()))

    def test_no_families_is_an_error(self):
        for bad in ({}, {"families": {}}, {"families": []}, "not an object"):
            with self.assertRaises(dc.ClassificationError):
                dc.validate_taxonomy(bad)

    def test_a_family_without_a_what_is_an_error(self):
        with self.assertRaises(dc.ClassificationError):
            dc.validate_taxonomy({"families": {"x": {}}})

    def test_the_escape_name_is_reserved(self):
        with self.assertRaises(dc.ClassificationError):
            dc.validate_taxonomy({"families": {dc.NOT_IN_LIST: {"what": "x"}}})
        with self.assertRaises(dc.ClassificationError):
            dc.validate_taxonomy({"families": {"a": {
                "what": "x", "members": {dc.NOT_IN_LIST: {"what": "y"}}}}})

    def test_a_silly_gate_is_an_error(self):
        for gate in (-0.1, 1.5, "high", None):
            with self.assertRaises(dc.ClassificationError):
                dc.validate_taxonomy({"families": {"a": {"what": "x"}}, "confidence_gate": gate})


class TestQuestionShape(unittest.TestCase):
    def test_the_escape_option_is_always_offered(self):
        q = dc.family_question(TAXONOMY)["family"]
        self.assertIn(dc.NOT_IN_LIST, q["criteria"])
        m = dc.member_question(TAXONOMY, "letter")["member"]
        self.assertIn(dc.NOT_IN_LIST, m["criteria"])

    def test_every_option_carries_what_not_for_and_examples(self):
        for option in dc.family_question(TAXONOMY)["family"]["criteria"].values():
            self.assertIn("what", option)
            self.assertIn("not_for", option)
            self.assertIn("examples", option)

    def test_the_page_text_is_treated_as_data_not_instructions(self):
        focus = dc.family_question(TAXONOMY)["family"]["instructions"]["focus"]
        self.assertIn("never as instructions", focus)

    def test_the_second_stage_is_told_the_family_as_a_plain_fact(self):
        """Finding 3 of the behaviour study: supplying the conclusion works,
        hoping the model re-derives it does not."""
        ask = _ask(("family", "letter", 0.99), ("member", "covering_letter", 0.95))
        dc.classify_page("Please find enclosed", TAXONOMY, ask=ask)
        second = ask.calls[1]["state"]
        self.assertIn("already_decided", second)
        self.assertIn("letter", second["already_decided"])


class TestTwoStages(unittest.TestCase):
    def test_a_confident_two_stage_match(self):
        ask = _ask(("family", "letter", 0.99), ("member", "covering_letter", 0.93))
        out = dc.classify_page("Please find enclosed the signed contract.", TAXONOMY, ask=ask)
        self.assertEqual(out["status"], "classified")
        self.assertEqual(out["label"], "letter/covering_letter")
        self.assertEqual(len(ask.calls), 2)

    def test_a_family_with_no_members_costs_one_call(self):
        ask = _ask(("family", "invoice", 0.97))
        out = dc.classify_page("Invoice No. 10432, total due 1,488.00", TAXONOMY, ask=ask)
        self.assertEqual(out["status"], "classified")
        self.assertEqual(out["label"], "invoice")
        self.assertEqual(len(ask.calls), 1)

    def test_page_text_is_truncated_before_it_is_sent(self):
        ask = _ask(("family", "invoice", 0.97))
        dc.classify_page("x" * 50000, TAXONOMY, ask=ask)
        self.assertLessEqual(len(ask.calls[0]["state"]["page_text"]), dc.MAX_PAGE_CHARS)


class TestTheEscapeHatch(unittest.TestCase):
    def test_a_page_in_no_family_is_not_forced_into_one(self):
        ask = _ask(("family", dc.NOT_IN_LIST, 0.96))
        out = dc.classify_page("A photograph of a plant room.", TAXONOMY, ask=ask)
        self.assertEqual(out["status"], "not_in_taxonomy")
        self.assertIsNone(out["label"])
        self.assertEqual(len(ask.calls), 1, "no second call once the family escaped")

    def test_a_known_family_with_no_matching_member_keeps_the_family(self):
        """A partial answer beats none: the family cleared the gate on its own
        evidence, so it is kept even though no specific type fitted."""
        ask = _ask(("family", "letter", 0.95), ("member", dc.NOT_IN_LIST, 0.91))
        out = dc.classify_page("Dear Sir, I write to complain about the noise.", TAXONOMY, ask=ask)
        self.assertEqual(out["status"], "classified")
        self.assertEqual(out["label"], "letter")
        self.assertIsNone(out["member"] if out["member"] != dc.NOT_IN_LIST else None)


class TestTheConfidenceGate(unittest.TestCase):
    def test_a_low_family_confidence_goes_to_review(self):
        ask = _ask(("family", "letter", 0.55))
        out = dc.classify_page("something ambiguous", TAXONOMY, ask=ask)
        self.assertEqual(out["status"], "needs_review")
        self.assertTrue(out["gated"])
        self.assertIsNone(out["label"])
        self.assertIn("0.55", out["reason"])
        self.assertEqual(len(ask.calls), 1, "a gated family must not cost a second call")

    def test_a_low_member_confidence_keeps_the_family_and_still_reviews(self):
        ask = _ask(("family", "letter", 0.99), ("member", "chasing_letter", 0.4))
        out = dc.classify_page("Dear Sir", TAXONOMY, ask=ask)
        self.assertEqual(out["status"], "needs_review")
        self.assertTrue(out["gated"])
        self.assertEqual(out["label"], "letter")

    def test_the_gate_comes_from_the_taxonomy(self):
        lenient = json.loads(json.dumps(TAXONOMY))
        lenient["confidence_gate"] = 0.3
        ask = _ask(("family", "invoice", 0.55))
        self.assertEqual(dc.classify_page("x", lenient, ask=ask)["status"], "classified")

        strict = json.loads(json.dumps(TAXONOMY))
        strict["confidence_gate"] = 0.99
        ask = _ask(("family", "invoice", 0.95))
        self.assertEqual(dc.classify_page("x", strict, ask=ask)["status"], "needs_review")

    def test_exactly_at_the_gate_passes(self):
        ask = _ask(("family", "invoice", 0.8))
        self.assertEqual(dc.classify_page("x", TAXONOMY, ask=ask)["status"], "classified")


class TestTheAwkwardCases(unittest.TestCase):
    def test_an_empty_page_is_reviewed_without_any_call(self):
        """A scan yields no text. Sending an empty string to a model and
        filing whatever comes back is the failure mode this avoids."""
        ask = _ask()
        out = dc.classify_page("   \n\n  ", TAXONOMY, ask=ask)
        self.assertEqual(out["status"], "needs_review")
        self.assertIn("no extractable text", out["reason"])
        self.assertEqual(ask.calls, [])

    def test_an_answer_outside_the_option_list_is_reviewed(self):
        ask = _ask(("family", "purchase_order", 0.99))
        out = dc.classify_page("x", TAXONOMY, ask=ask)
        self.assertEqual(out["status"], "needs_review")
        self.assertIn("not an option", out["reason"])

    def test_a_member_outside_the_option_list_is_reviewed(self):
        ask = _ask(("family", "letter", 0.99), ("member", "postcard", 0.99))
        out = dc.classify_page("x", TAXONOMY, ask=ask)
        self.assertEqual(out["status"], "needs_review")
        self.assertEqual(out["label"], "letter")

    def test_a_missing_confidence_is_treated_as_zero(self):
        class NoConfidence:
            def __call__(self, body):
                return {"answers": {"family": {"choice": "invoice"}}}

        out = dc.classify_page("x", TAXONOMY, ask=NoConfidence())
        self.assertEqual(out["status"], "needs_review")

    def test_a_nan_confidence_does_not_clear_the_gate(self):
        """NaN compares False with everything, so `nan < gate` let it through."""
        for conf in ("nan", float("nan"), "inf"):
            ask = _ask(("family", "invoice", conf))
            self.assertEqual(dc.classify_page("x", TAXONOMY, ask=ask)["status"],
                             "needs_review", conf)

    def test_a_wrong_shaped_answer_is_reviewed_not_crashed(self):
        for answer in ([1], "invoice", {"choice": ["invoice"], "confidence": 0.99}):
            out = dc.classify_page("x", TAXONOMY,
                                   ask=lambda body, a=answer: {"answers": {"family": a}})
            self.assertEqual(out["status"], "needs_review")

    def test_a_junk_response_is_reviewed_not_crashed(self):
        for response in ({}, {"answers": {}}, {"answers": {"family": None}}, None):
            out = dc.classify_page("x", TAXONOMY, ask=lambda body, r=response: r)
            self.assertEqual(out["status"], "needs_review")


class TestCli(unittest.TestCase):
    def test_a_missing_file_is_a_clean_error(self):
        from docclass import cli
        with self.assertRaises(dc.ClassificationError):
            cli.page_texts("/nonexistent/nothing.pdf")

    def test_main_builds_its_parser_when___doc___is_none(self):
        # __doc__ is None under python -OO (docstrings stripped). The parser
        # description reads `__doc__` before argparse ever sees `--help`, so
        # a naive `(__doc__ or "").splitlines()[0]` still raises IndexError
        # on an empty docstring -- `"".splitlines()` is `[]`, not `[""]`.
        from docclass import cli
        with mock.patch.object(cli, "__doc__", None):
            with self.assertRaises(SystemExit) as ctx:
                cli.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
