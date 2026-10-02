"""Redaction: strip token-like strings before anything leaves the box or
reaches the shadow log.

Applied to every field of the state we send to Jev, and to every field we
write to the log, before either happens. Order matters only in that the
generic hex/base64 sweeps run last so they cannot eat a piece of an
already-specific match first (both outcomes redact the same substring, so in
practice order does not change the result, only readability of this file).
"""
import re

REDACTED = "[REDACTED]"

PROMPT_TRUNCATE = 4000
COMMAND_TRUNCATE = 2000

# A key/value pair is redacted by replacing only the value: the key, its
# quoting and the separator stay, so `{"api_key": "x"}` remains valid JSON.
# Separators and values never span a newline, so `password:` at the end of a
# line cannot swallow the first word of the next one.
_VALUE = r"""(?P<val>"[^"\n]*"|'[^'\n]*'|[^\s"']\S*|["']\S+)"""

_KEY_VALUE_PATTERNS = [
    # password=<value>, --password <value>, password: <value> and the JSON
    # form "password": "<value>" (case-insensitive)
    re.compile(r"(?i)(?P<key>(?:--)?password)(?P<kq>[\"']?)"
               r"(?P<sep>[ \t]*[:=][ \t]*|[ \t]+)" + _VALUE),
    # <ANYTHING>SECRET|TOKEN|PASSWORD|API_KEY<ANYTHING>=<value>, also with a
    # colon (YAML, HTTP headers, JSON keys)
    # (the lookbehind starts a match only at a word's first character; without
    # it a long word is rescanned from every position, quadratic)
    re.compile(r"(?i)(?P<key>(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]*"
               r"(?:SECRET|TOKEN|PASSWORD|API_KEY)[A-Za-z0-9_\-]*)(?P<kq>[\"']?)"
               r"(?P<sep>=|[ \t]*:[ \t]*)" + _VALUE),
]

# Keys that name a counter or a measurement (max_tokens, inputTokens,
# token_count, secret_size, token_ms). Their value is kept only when it is a
# plain number; anything else under such a key is still redacted.
# The key's LAST word must be the counter word, matched whole: a substring
# test would let ACCOUNT ("count") or DISCOUNT exempt BANK_ACCOUNT_TOKEN.
_COUNTER_WORDS = frozenset(("tokens", "count", "size", "ms"))
# words of a key: split on _ and -, and on camelCase (inputTokens, HTTPSize)
_KEY_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_NUMBER = re.compile(r"[0-9]+(?:\.[0-9]+)?")


def _is_counter_key(key):
    words = _KEY_WORD.findall(key)
    return bool(words) and words[-1].lower() in _COUNTER_WORDS


def _redact_value(match):
    key, kq, sep, val = match.group("key", "kq", "sep", "val")
    if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
        return key + kq + sep + val[0] + REDACTED + val[0]
    tail = ""
    if kq:
        # JSON-style unquoted value: keep the closing punctuation
        stripped = val.rstrip(",}]")
        if stripped:
            val, tail = stripped, val[len(stripped):]
    if _NUMBER.fullmatch(val) and _is_counter_key(key):
        return match.group(0)
    if kq:
        # a quoted key means JSON: quote the placeholder so it still parses
        return key + kq + sep + '"' + REDACTED + '"' + tail
    return key + kq + sep + REDACTED + tail


_PATTERNS = [
    # TypeSafe / vendor-style API keys
    re.compile(r"apikey_[A-Za-z0-9_]+"),
    # OpenAI-style secret keys
    re.compile(r"sk-[A-Za-z0-9_\-]{10,}"),
    # GitHub personal access tokens
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    # Slack tokens: xoxb-, xoxp-, xoxa-, xoxr-, xoxs- ...
    re.compile(r"xox[a-zA-Z]-[A-Za-z0-9\-]+"),
    # JWTs: eyJ... . eyJ... . signature
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    # Bearer <token>
    re.compile(r"Bearer\s+\S+"),
    # Bare 32+ char hex run (not already part of a matched token above)
    re.compile(r"(?<![A-Za-z0-9])[A-Fa-f0-9]{32,}(?![A-Za-z0-9])"),
    # Bare 32+ char base64-ish run
    re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/=])"),
]


def redact(text):
    """Replace every token-like substring in text with [REDACTED]. Never raises."""
    if not text:
        return text
    try:
        out = str(text)
        for pattern in _KEY_VALUE_PATTERNS:
            out = pattern.sub(_redact_value, out)
        for pattern in _PATTERNS:
            out = pattern.sub(REDACTED, out)
        return out
    except Exception:
        # Fail safe toward over-redaction, never toward leaking the input as-is.
        return REDACTED


def redact_and_truncate_prompt(text):
    return redact(text)[:PROMPT_TRUNCATE]


def redact_and_truncate_command(text):
    return redact(text)[:COMMAND_TRUNCATE]
