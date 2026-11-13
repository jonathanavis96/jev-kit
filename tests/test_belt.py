"""The local credential belt, ported from valentynkit/jev-commit (MIT, see
docs/CREDITS.md), and rule R9's use of it.

The belt's value is entirely in its precision: a credential belt that fires on
`risk-assessment` or on `sk-your_key_here` gets switched off within a week and
then protects nothing. Most of what is tested here is therefore the NEGATIVE
cases.

Two properties hold throughout:
  - no diff, no file content and no credential VALUE ever leaves this process:
    the belt returns at most the first four characters of a match;
  - the belt is pure code, offline, with no model call.
"""

import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import unittest

from airlock import belt, rules as rules_mod


def _r9(command):
    ctx = rules_mod.build_ctx({"tool_name": "Bash", "tool_input": {"command": command}}, "Bash")
    return rules_mod.prefilter_commit_secret(ctx)


class TestHighPrecisionPatterns(unittest.TestCase):
    CREDENTIALS = {
        "aws_access_key": "AKIA1234567890ABCDEF",
        "github_token": "ghp_abcdefghijklmnopqrstuvwxyz0123",
        "github_pat": "github_pat_abcdefghijklmnopqrstu",
        "anthropic_key": "sk-ant-abcdefghijklmnopqrstuvwxyz01",
        "openai_key": "sk-abcdefghijklmnopqrstuvwxyz",
        "slack_token": "xoxb-1234567890-abcdefghij",
        "google_api_key": "AIza" + "a" * 35,
        "gitlab_token": "glpat-abcdefghijklmnopqrst",
        "npm_token": "npm_" + "a" * 36,
        "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0",
        "url_credentials": "postgres://admin:hunter2@db.internal/app",
        "typesafe_key": "apikey_abcdefghijklmnopqr",
    }

    def test_each_shape_is_detected(self):
        for kind, value in self.CREDENTIALS.items():
            hit = belt.first_blocking_hit("SOMEVAR=%s" % value)
            self.assertIsNotNone(hit, kind)
            self.assertEqual(hit["kind"], kind, "%s matched as %s" % (kind, hit["kind"]))

    def test_private_key_header(self):
        hit = belt.first_blocking_hit("-----BEGIN OPENSSH PRIVATE KEY-----")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["kind"], "private_key")

    def test_only_four_characters_are_ever_returned(self):
        """Including in the context `line`. A hit is something that gets
        logged, so no field on it may carry the value."""
        secret = "sk-ant-abcdefghijklmnopqrstuvwxyz01"
        hit = belt.first_blocking_hit("KEY=%s" % secret)
        self.assertEqual(hit["redacted"], "sk-a...")
        self.assertNotIn(secret, repr(hit))

    def test_no_credential_value_survives_on_any_field(self):
        for value in self.CREDENTIALS.values():
            hit = belt.first_blocking_hit("SOMEVAR=%s" % value)
            self.assertNotIn(value, repr(hit), value[:8])

    def test_a_second_credential_on_the_same_line_is_redacted_too(self):
        line = "A=AKIA1234567890ABCDEF B=apikey_abcdefghijklmnopq"
        hit = belt.first_blocking_hit(line)
        self.assertNotIn("apikey_abcdefghijklmnopq", repr(hit))
        self.assertNotIn("AKIA1234567890ABCDEF", repr(hit))


class TestTheNegativeCases(unittest.TestCase):
    """What separates a usable belt from one that gets switched off."""

    def test_left_anchoring_stops_substring_matches(self):
        # jev-commit's own reason for the left anchor.
        self.assertIsNone(belt.first_blocking_hit("the risk-assessment-module-name-here"))
        self.assertIsNone(belt.first_blocking_hit("blobAIza" + "a" * 35))

    def test_placeholder_values_do_not_fire(self):
        for line in (
            "ANTHROPIC_API_KEY=sk-ant-your_key_here_goes_here",
            "TOKEN=xxxxxxxxxxxxxxxxxxxxxxxx",
            "DATABASE_URL=postgres://user:password@localhost/db",
            "KEY=<your-api-key-here>",
            "KEY=${ANTHROPIC_API_KEY}",
            "KEY=$TYPESAFE_API_KEY",
            "git clone https://user:$TOKEN@github.com/x",
            "git clone https://user:${GH_TOKEN}@github.com/x",
            "git clone https://user:<password>@github.com/x",
        ):
            self.assertIsNone(belt.first_blocking_hit(line), line)

    def test_a_real_password_in_a_url_still_fires(self):
        self.assertIsNotNone(belt.first_blocking_hit("https://u:" + "hunter2real" + "@h.com/x"))

    def test_a_placeholder_word_anywhere_on_the_line_suppresses_it(self):
        line = "# the example token from the docs: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"
        self.assertIsNone(belt.first_blocking_hit(line))

    def test_ordinary_code_does_not_fire(self):
        for line in (
            "def get_api_key(): return os.environ['TYPESAFE_API_KEY']",
            "if not token: raise ValueError('no token')",
            "curl -H \"Authorization: Bearer $TOKEN\" https://api.example.com",
            "password = getpass.getpass()",
            "import hashlib",
        ):
            self.assertIsNone(belt.first_blocking_hit(line), line)

    def test_recall_grade_hits_never_block(self):
        line = "password: correcthorsebatterystaple"
        self.assertEqual(belt.blocking_hits(line), [])
        recall = belt.scan_text(line, include_recall=True)
        self.assertEqual(len(recall), 1)
        self.assertEqual(recall[0]["precision"], "recall")

    def test_high_entropy_is_recall_only(self):
        line = "hash = 'a9F3kz0QvXm2LpTt7YbNc4WsRd8EhJuG'"
        self.assertEqual(belt.blocking_hits(line), [])


class TestShannon(unittest.TestCase):
    def test_uniform_text_has_zero_entropy(self):
        self.assertEqual(belt.shannon("aaaaaaaa"), 0.0)

    def test_empty_is_zero(self):
        self.assertEqual(belt.shannon(""), 0.0)

    def test_mixed_text_has_more(self):
        self.assertGreater(belt.shannon("a9F3kz0QvXm2LpTt7YbNc4WsRd8EhJuG"), 4.0)


class TestR9UsesTheBelt(unittest.TestCase):
    def test_the_original_path_check_still_works(self):
        for command in ("git add .env", "git add server.key", "git commit -m x id_rsa"):
            self.assertIsNotNone(_r9(command), command)

    def test_a_credential_in_a_commit_message_fires(self):
        match = _r9('git commit -m "rotate to sk-ant-abcdefghijklmnopqrstuvwxyz01"')
        self.assertIsNotNone(match)
        self.assertIn("anthropic_key", match.detail)

    def test_a_credential_written_then_staged_fires(self):
        match = _r9('printf "TYPESAFE_API_KEY=apikey_abcdefghijklmnopq" > cfg && git add cfg')
        self.assertIsNotNone(match)
        self.assertIn("typesafe_key", match.detail)

    def test_the_detail_carries_no_secret(self):
        secret = "sk-ant-abcdefghijklmnopqrstuvwxyz01"
        match = _r9('git commit -m "key is %s"' % secret)
        self.assertIsNotNone(match)
        self.assertNotIn(secret, match.detail)
        self.assertNotIn(secret[8:], match.detail)

    def test_no_git_write_means_no_belt_scan(self):
        """The belt only looks at a command that stages or commits. An
        `echo` of a credential is R1's business, not R9's; R9 firing on it too
        would double-report the same call."""
        self.assertIsNone(_r9("echo sk-ant-abcdefghijklmnopqrstuvwxyz01"))
        self.assertIsNone(_r9("git status"))
        self.assertIsNone(_r9("git log --oneline -5"))

    def test_an_ordinary_commit_does_not_fire(self):
        for command in (
            'git commit -m "fix the risk assessment module"',
            "git add src/config.py tests/test_config.py",
            'git add . && git commit -m "wire the belt into R9"',
        ):
            self.assertIsNone(_r9(command), command)

    def test_r9_is_still_code_only(self):
        """No Jev question, so it costs nothing and cannot fail open into a
        network error."""
        rule = rules_mod.RULES_BY_ID["R9-commit-secret"]
        self.assertIsNone(rule.questions)
        self.assertEqual(rule.action, "deny")


if __name__ == "__main__":
    unittest.main()
