
import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import unittest

from airlock import redact


class TestRedact(unittest.TestCase):
    def assertRedacted(self, secret, text=None):
        text = text if text is not None else secret
        out = redact.redact(text)
        self.assertNotIn(secret, out, "secret leaked in: %r" % out)
        self.assertIn(redact.REDACTED, out)

    def test_apikey(self):
        self.assertRedacted("apikey_ABC123xyz789")

    def test_openai_style_key(self):
        self.assertRedacted("sk-abcdefghijklmno1234567890")

    def test_github_token(self):
        self.assertRedacted("ghp_" + "a" * 36)

    def test_slack_token(self):
        self.assertRedacted("xoxb-1234567890-abcdefghijklmno")

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQrandomsig"
        self.assertRedacted(jwt)

    def test_bearer_header(self):
        out = redact.redact("Authorization: Bearer abcdef123456.token")
        self.assertNotIn("abcdef123456", out)
        self.assertIn(redact.REDACTED, out)

    def test_password_equals(self):
        out = redact.redact("password=hunter2secret")
        self.assertNotIn("hunter2secret", out)

    def test_password_flag(self):
        out = redact.redact("mysql --password hunter2secret")
        self.assertNotIn("hunter2secret", out)

    def test_password_in_json_or_yaml(self):
        for text in ('{"password": "hunter2secret"}',
                     "password: hunter2secret",
                     "db_password: hunter2secret"):
            self.assertNotIn("hunter2secret", redact.redact(text), text)

    def test_generic_secret_with_colon(self):
        for text in ('{"api_key": "xyz987fooBAR"}',
                     "X-Auth-Token: xyz987fooBAR",
                     "client_secret : xyz987fooBAR"):
            self.assertNotIn("xyz987fooBAR", redact.redact(text), text)

    def test_numeric_counters_under_token_keys_are_kept(self):
        for text in ("max_tokens: 4096", "inputTokens: 123",
                     '{"outputTokens": 77}', "token_count=12",
                     "secret_size: 2048", "token_ms: 15"):
            self.assertEqual(redact.redact(text), text, text)

    def test_secret_value_under_counter_key_still_redacted(self):
        for text in ("max_tokens: xyz987fooBAR", "token_count=xyz987fooBAR",
                     '{"inputTokens": "xyz987fooBAR"}'):
            self.assertNotIn("xyz987fooBAR", redact.redact(text), text)

    def test_counter_word_inside_another_word_does_not_exempt(self):
        # ACCOUNT and DISCOUNT contain "count"; the key's last word is what
        # decides, and here it names the secret
        for text, secret in (("export BANK_ACCOUNT_TOKEN=99887766", "99887766"),
                             ("DISCOUNT_API_KEY=1234567890", "1234567890"),
                             ("account_secret: 552901", "552901"),
                             ("ACCOUNT_PASSWORD=4242", "4242"),
                             ("resizeToken: 31337", "31337")):
            self.assertNotIn(secret, redact.redact(text), text)

    def test_numeric_value_under_secret_key_still_redacted(self):
        for text in ("password: 12345678", "api_key=987654321"):
            self.assertNotIn("987654321" if "api" in text else "12345678",
                             redact.redact(text), text)

    def test_colon_match_does_not_cross_newline(self):
        for key in ("password", "api_key", "X-Auth-Token"):
            out = redact.redact("%s:\nnextline stays" % key)
            self.assertIn("nextline stays", out, out)

    def test_json_key_is_kept(self):
        out = redact.redact('{"api_key": "abc", "model": "x"}')
        self.assertEqual(out, '{"api_key": "[REDACTED]", "model": "x"}')
        out = redact.redact('{"password": "hunter2secret"}')
        self.assertEqual(out, '{"password": "[REDACTED]"}')

    def test_redacted_json_still_parses(self):
        import json
        doc = {"api_key": "sk_live_" + "Q" * 12, "client_secret": "xyz987fooBAR",
               "password": "hunter2 secret", "X-Auth-Token": 123456789,
               "max_tokens": 4096, "model": "x"}
        out = redact.redact(json.dumps(doc))
        parsed = json.loads(out)
        self.assertEqual(parsed["max_tokens"], 4096)
        self.assertEqual(parsed["model"], "x")
        for key in ("api_key", "client_secret", "password", "X-Auth-Token"):
            self.assertEqual(parsed[key], redact.REDACTED, key)
        self.assertNotIn("hunter2", out)
        self.assertNotIn("xyz987fooBAR", out)

    def test_a_long_unbroken_word_is_linear(self):
        """The generic NAME=value pattern retried from every character of a
        long word, quadratic: 20k chars took ~12 s on the hook's hot path."""
        import time
        start = time.monotonic()
        redact.redact("x" * 50000)
        self.assertLess(time.monotonic() - start, 1.0)

    def test_generic_secret_env(self):
        out = redact.redact("MY_APP_SECRET_TOKEN=abc123def456")
        self.assertNotIn("abc123def456", out)

    def test_generic_api_key_env(self):
        out = redact.redact("SOME_API_KEY=xyz987fooBAR")
        self.assertNotIn("xyz987fooBAR", out)

    def test_bare_hex_32(self):
        hexstr = "a" * 40
        out = redact.redact("token: %s end" % hexstr)
        self.assertNotIn(hexstr, out)

    def test_bare_base64ish_32(self):
        b64 = "QWxhZGRpbjpvcGVuIHNlc2FtZQnotarealsecretbutlong=="
        out = redact.redact("blob=%s" % b64)
        self.assertNotIn(b64, out)

    def test_short_strings_untouched(self):
        text = "run the tests and check status"
        self.assertEqual(redact.redact(text), text)

    def test_empty_and_none(self):
        self.assertEqual(redact.redact(""), "")
        self.assertIsNone(redact.redact(None))

    def test_prompt_truncation(self):
        long_prompt = "please read this file and summarize it " * 200
        out = redact.redact_and_truncate_prompt(long_prompt)
        self.assertEqual(len(out), redact.PROMPT_TRUNCATE)

    def test_command_truncation(self):
        long_cmd = "grep -rn something long_directory_name_here " * 100
        out = redact.redact_and_truncate_command(long_cmd)
        self.assertEqual(len(out), redact.COMMAND_TRUNCATE)

    def test_truncation_after_redaction_keeps_secret_out(self):
        # A secret near the truncation boundary must still be redacted, not
        # sliced in half and partially leaked.
        prefix = "a" * 3990
        secret = "sk-" + "b" * 30
        text = prefix + secret
        out = redact.redact_and_truncate_prompt(text)
        self.assertNotIn("b" * 30, out)


if __name__ == "__main__":
    unittest.main()
