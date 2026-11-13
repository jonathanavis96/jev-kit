"""A local credential belt: pure-code patterns for credential-shaped text.

Ported from valentynkit/jev-commit's `jev_commit/belt.py` (MIT, see
`docs/CREDITS.md`). Two things came across:

  - the split between HIGH-PRECISION patterns, which are specific enough to
    act on, and HIGH-RECALL ones, which are not and only ever inform; and
  - the placeholder suppression, which is what stops `sk-your_key_here` and
    `password: <redacted>` from being treated as findings.

What did NOT come across is jev-commit's design around it. That tool sends the
staged diff to Jev to ask whether a matched value is a real credential, which
is inherent to the question it asks. **Nothing here sends a diff anywhere.**
This module is pure code, offline, with no network and no model call at all,
and only the redacted first four characters of a match ever reach a log row.

Used by rule R9 (`airlock/rules.py`): a `git add`/`git commit` whose own
command text carries a credential-shaped literal.
"""
import math
import re

# Every prefix is anchored on its left so it only counts at the start of a
# token. jev-commit's note on why is worth keeping: without it,
# `sk-[A-Za-z0-9]{20,}` fires on `risk-<20 chars>` and `AIza[...]{35}` fires on
# any base64 blob containing those four letters.
LEFT = r"(?<![A-Za-z0-9])"

# Specific enough to act on. A match here (that is not a placeholder) is a
# credential shape, not a guess.
HIGH_PRECISION = [
    ("aws_access_key", re.compile(LEFT + r"AKIA[0-9A-Z]{16}")),
    ("github_pat", re.compile(LEFT + r"github_pat_[A-Za-z0-9_]{20,}")),
    ("github_token", re.compile(LEFT + r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("anthropic_key", re.compile(LEFT + r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai_key", re.compile(LEFT + r"sk-[A-Za-z0-9]{20,}")),
    ("slack_token", re.compile(LEFT + r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(LEFT + r"AIza[0-9A-Za-z_\-]{35}")),
    ("gitlab_token", re.compile(LEFT + r"glpat-[\w-]{20}")),
    ("sendgrid_key", re.compile(LEFT + r"SG\.[\w-]{22}\.")),
    ("npm_token", re.compile(LEFT + r"npm_[A-Za-z0-9]{36}")),
    ("private_key", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(LEFT + r"eyJ[\w-]{10,}\.eyJ")),
    ("url_credentials", re.compile(LEFT + r"\w[\w+.-]*://[^/\s:@]+:(?P<value>[^/\s:@]+)@")),
    # This organisation's own key shape, which jev-commit had no reason to know
    # about. It is the one that has already had to be rotated once.
    ("typesafe_key", re.compile(LEFT + r"apikey_[A-Za-z0-9_]{16,}")),
]

# Not specific enough to act on. These never block; they exist so a log row
# can say "this looked credential-shaped" without the guard acting on it.
HIGH_RECALL = [
    ("config_credential",
     re.compile(r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|bindpw)\s*[:=]\s*(?P<value>\S{8,})")),
]

ENTROPY_RUN = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
ENTROPY_MIN = 4.0

PLACEHOLDER_WORDS = (
    "example", "placeholder", "dummy", "changeme", "redacted", "sample",
    "fake", "your_", "xxxx", "test-value", "user:password", "user:pass",
    "username:password",
)
PLACEHOLDER_SHAPES = [
    re.compile(r"^[xX*]+$"),
    re.compile(r"^<[^>]*>$"),
    re.compile(r"^\$\{[^}]*\}$"),
    re.compile(r"^\$[A-Z_][A-Z0-9_]*$"),
]


def shannon(text):
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_placeholder(value):
    low = (value or "").lower()
    if any(word in low for word in PLACEHOLDER_WORDS):
        return True
    stripped = (value or "").strip("\"'`,;")
    return any(shape.match(stripped) for shape in PLACEHOLDER_SHAPES)


def says_placeholder(line):
    """The blocking tier reads the whole line, not only the match.

    jev-commit's reasoning, kept verbatim in spirit: a matched value carries no
    context of its own, so `# the example token from the docs: eyJ...` blocked
    on the match alone. Widening the word check to the line loses a real
    credential sitting next to the word "sample". A false block is the costlier
    mistake, so the wider check wins.
    """
    low = (line or "").lower()
    return any(word in low for word in PLACEHOLDER_WORDS)


def redact(value):
    """First four characters, never the secret."""
    value = value or ""
    return value[:4] + "..." if len(value) > 4 else "..."


def _safe_line(line, matched):
    """The context line, with the matched credential cut out of it FIRST and
    the general redactor run over what is left.

    Order matters, and it is the ordering lesson from reachjalil/jevlogs
    (see docs/CREDITS.md): nothing downstream -- a log row, a
    deny message, a report -- should ever be able to see the raw text. The
    matched value is replaced by its own four-character prefix, because that
    is the only part callers are allowed to have; then the whole line goes
    through airlock/redact.py in case a SECOND credential is sitting on it.
    If redaction cannot run at all, the line is dropped rather than passed
    through unredacted.
    """
    line = (line or "").strip()[:120]
    if matched:
        line = line.replace(matched, redact(matched))
    try:
        from . import redact as redact_mod
        return redact_mod.redact(line)
    except Exception:
        return "[line withheld: redaction unavailable]"


def scan_text(text, include_recall=False):
    """Credential-shaped hits in one blob of text, one hit per line at most.

    Returns [{kind, precision, line, redacted}]. `redacted` is the first four
    characters and nothing more -- the value itself is never returned, never
    logged, and never sent anywhere.

    Recall-grade hits are off by default: they are for a report, not a
    decision, and R9 must not block on one.
    """
    hits = []
    for raw_line in (text or "").splitlines():
        line = raw_line
        matched = False
        for kind, pattern in HIGH_PRECISION:
            match = pattern.search(line)
            # A pattern with a `value` group names the secret part: for a URL
            # that is the password, so `user:$TOKEN@` and `user:<password>@`
            # read as the placeholders they are, not the whole URL.
            secret = (match.groupdict().get("value") or match.group(0)) if match else ""
            if match and not is_placeholder(secret) and not says_placeholder(line):
                hits.append({
                    "kind": kind,
                    "precision": "high",
                    "line": _safe_line(line, match.group(0)),
                    "redacted": redact(match.group(0)),
                })
                matched = True
                break
        if matched or not include_recall:
            continue

        for kind, pattern in HIGH_RECALL:
            match = pattern.search(line)
            if match and not is_placeholder(match.group("value")):
                hits.append({
                    "kind": kind,
                    "precision": "recall",
                    "line": _safe_line(line, match.group("value")),
                    "redacted": redact(match.group("value")),
                })
                matched = True
                break
        if matched:
            continue

        for run in ENTROPY_RUN.findall(line):
            if shannon(run) >= ENTROPY_MIN and not is_placeholder(run):
                hits.append({
                    "kind": "high_entropy_string",
                    "precision": "recall",
                    "line": _safe_line(line, run),
                    "redacted": redact(run),
                })
                break
    return hits


def blocking_hits(text):
    """Only the high-precision hits -- the ones a deny may be built on."""
    return [h for h in scan_text(text) if h["precision"] == "high"]


def first_blocking_hit(text):
    hits = blocking_hits(text)
    return hits[0] if hits else None
