"""The rules table: one entry per kind of genuinely-wrong tool use.

This module has no network and no logging, and its only filesystem access is
the cheap upward walk the legacy tool-choice rule already did plus one stat of
the key-file pointer for R1 (see `_pointer_secret_path_res`, which caches on
that stat). It answers, in microseconds, one question for a PreToolUse payload:

    could any rule possibly fire for this call?

A call that matches no rule costs a `shlex`-free string scan and nothing else:
no Jev request, no log row, no subprocess. Only when a code pre-filter matches
does airlock/enforce.py (or the shadow worker) go on to ask Jev the single
fuzzy question that rule needs -- and only for rules whose pre-filter says the
fuzzy part is actually in doubt.

Each rule carries:
  id          stable short id, used in ~/.config/airlock/rules.json
  tools       tool names it applies to ("*" for every tool)
  action      default action: "deny" | "warn" | "log" | "off"
  prefilter   ctx -> Match | None    (all code, no I/O)
  questions   (ctx, match) -> (state, questions) for the Jev call, or None
  deny_when   answers -> bool        (the fuzzy half of the rule)
  legacy      name of a pre-existing guard whose behaviour is reproduced
              unchanged (the two original guards, R8)
  fallback    True for the catch-all tier (R10): consulted ONLY when no other
              rule matched the call at all

Actions:
  deny  block the call with the suggestion text (enforce mode only)
  ask   hand the decision to the human (config only; degrades to deny when
        nobody is attending the session)
  warn  allow, and hand the advice back as hook output / a log row
  log   allow, log only, never surface anything
  off   the rule does not run at all. R6 ships this way on every platform:
        a headless machine turns it on in rules.json (install/install.sh
        writes that entry when it detects one)

Per-rule overrides live in ~/.config/airlock/rules.json, e.g.:

    {"R3-whole-test-suite": "off", "R7-destructive": "log"}

Policy source: the owner's standing CLAUDE.md for this box (the
instructions for this box). No rule here invents policy that file does not
contain, and no rule duplicates what the box's own local hooks already block
(graphify-grep-guard.py for recursive grep in a graphed repo,
webfetch-guard.py for WebFetch prompt rewriting).
"""
import json
import os
import re
import shlex

from . import keyfile, paths, scope
from .headless import cpu_count, is_small_host
from .platform_compat import is_windows

HOME = os.path.expanduser("~")

# Every tool that carries a shell command string in tool_input.command.
# Claude Code's hooks reference is explicit: "Match `Bash|PowerShell` in hooks
# that inspect shell commands, so they cover both tools", because on Windows
# without Git Bash "the tool is enabled automatically and Claude Code doesn't
# register the Bash tool at all" -- a hook matching only Bash never fires
# there. On Linux nothing changes: a Bash payload is still a Bash payload.
SHELL_TOOLS = ("Bash", "PowerShell")
CONFIG_FILE = str(paths.config_file("rules.json"))
# "ask" sits between allow and deny: the human is asked rather than the call
# being blocked outright. It is a config-only action -- no rule ships with it
# as a default -- and in an unattended session it is reported as the deny it
# actually is (see airlock/enforce.py:effective_block_action).
VALID_ACTIONS = ("deny", "ask", "warn", "log", "off")


class Match:
    """A code pre-filter hit. `ask=True` means the rule still needs Jev for
    the fuzzy half; `ask=False` means the code decided on its own."""

    __slots__ = ("ask", "detail", "extra", "suggestion")

    def __init__(self, detail, suggestion="", ask=False, extra=None):
        self.detail = detail
        self.suggestion = suggestion
        self.ask = ask
        self.extra = extra or {}


class Rule:
    __slots__ = (
        "action",
        "deny_when",
        "fallback",
        "id",
        "legacy",
        "prefilter",
        "questions",
        "tools",
        "why",
        "windows_action",
    )

    def __init__(self, id, tools, action, prefilter=None, questions=None, deny_when=None,
                 legacy=None, fallback=False, why="", windows_action=None):
        self.id = id
        self.tools = tuple(tools)
        self.action = action
        # A different DEFAULT action on native Windows, or None for "the same
        # everywhere". No rule sets it today: R6 used to, and now defaults to
        # `off` on every platform instead, which made the special case
        # redundant. The mechanism is kept because the next rule that is
        # genuinely platform-shaped will want it, and because a rules.json
        # entry still overrides it on either platform -- the per-platform
        # value is a DEFAULT, never a ceiling.
        self.windows_action = windows_action
        self.prefilter = prefilter
        self.questions = questions
        self.deny_when = deny_when
        self.legacy = legacy
        # A fallback rule is only consulted when NOTHING else matched. It is
        # the catch-all tier, and running it alongside a specific rule would
        # mean paying twice to say the same thing.
        self.fallback = fallback
        self.why = why

    def applies_to(self, tool_name):
        return "*" in self.tools or tool_name in self.tools


# --- shell helpers -----------------------------------------------------------

_SKIP_PREFIX = {"nice", "time", "command", "exec", "builtin", "stdbuf", "nohup", "ionice"}


def strip_heredocs(command):
    """Drop heredoc BODIES from a command line, keeping the command that owns
    them. A heredoc body is data (a file being written, a prompt, a note), not
    something the shell executes, so words inside it must never trip a code
    rule. Seen live on 2026-09-19: a note containing the word for the
    privilege-elevation command was blocked as if it were that command.
    The one implementation is airlock/scope.py's, which knows quoting and
    here-strings. These rules stop commands, so a body with no terminator
    stays in view. Never raises; on anything odd it returns the input
    unchanged."""
    try:
        return scope.strip_heredocs(command, keep_unterminated=True)
    except Exception:
        return command


def _ansi_string_end(s, i):
    """Index just past the `$'...'` string at `i`, where a backslash escapes the
    next character, unlike in plain single quotes."""
    i += 2
    n = len(s)
    while i < n:
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == "'":
            return i + 1
        i += 1
    return n


def _shell_nesting(s, start=0, one_construct=False):
    """(comment offsets, end) of shell text, walked with its nesting.

    A `#` opens a comment only at the start of a word in plain code. It is text
    inside `${...}`, `$((...))`, `$[...]`, `((...))`, `[[ ... ]]`, quotes and
    backticks, and `$(a)#b` is one word, so the commands after each of those
    would vanish if it were read as a comment. `$(...)` and `(...)` are plain
    code again, whatever surrounds them.

    With `one_construct`, stops where the construct at `start` closes, and `end`
    is the offset just past it. The walk never goes backwards, and the stack
    replaces recursion, so hostile nesting costs one pass.

    When the text ends with a construct open, or when a `case` inside a
    substitution makes a `)` mean two things, no further comment is reported:
    missing a comment only keeps its words in view."""
    comments = set()
    stack = []
    i = start
    n = len(s)
    word_start = True
    give_up = False
    doubles = 0  # open `"` on the stack
    while i < n:
        ch = s[i]
        top = stack[-1] if stack else None
        if top == "`":
            if ch == "\\":
                i += 2
                continue
            i += 1
            if ch == "`":
                stack.pop()
                if one_construct and not stack:
                    return comments, i
            continue
        if ch == "\\":
            i += 2
            word_start = False
            continue
        opened = None
        if ch == "`":
            opened, width = "`", 1
        elif s.startswith("$((", i):
            opened, width = "a", 3
        elif s.startswith("$(", i):
            opened, width = "$", 2
        elif s.startswith("${", i):
            opened, width = "{", 2
        elif s.startswith("$[", i):
            opened, width = "b", 2
        if opened:
            stack.append(opened)
            i += width
            word_start = opened == "$"
            continue
        if top == '"':
            i += 1
            if ch == '"':
                stack.pop()
                doubles -= 1
                word_start = False
            continue
        if ch == '"':
            stack.append('"')
            doubles += 1
            i += 1
            word_start = False
            continue
        if ch == "'" or s.startswith("$'", i):
            # In `"${x:-it's}"` the double quotes make an apostrophe plain text.
            if not (top == "{" and doubles and ch == "'"):
                if ch == "'":
                    end = s.find("'", i + 1)
                    i = n if end == -1 else end + 1
                else:
                    i = _ansi_string_end(s, i)
                word_start = False
                continue
        closed = None
        if top == "{":
            closed = ch == "}"
        elif top == "b":
            closed = ch == "]"
        elif top == "p":
            closed = ch == ")"
            if ch == "(":
                stack.append("p")
        elif top == "a":
            if s.startswith("))", i):
                stack.pop()
                i += 2
                word_start = False
                if one_construct and not stack:
                    return comments, i
                continue
            if ch == ")":
                stack[-1] = "$"  # `$((a) b)` is a subshell in a substitution
            elif ch == "(":
                stack.append("p")
        elif top == "[":
            if s.startswith("]]", i):
                stack.pop()
                i += 2
                word_start = False
                continue
        else:
            if ch == "#" and word_start and not give_up:
                comments.add(i)
                newline = s.find("\n", i)
                i = n if newline == -1 else newline
                continue
            if word_start and s.startswith("[[", i):
                stack.append("[")
                i += 2
                continue
            if word_start and top and s.startswith("case", i) and s[i + 4:i + 5].isspace():
                give_up = True
            if ch == "(":
                if s.startswith("((", i) and word_start:
                    stack.append("a")
                    i += 2
                    word_start = False
                    continue
                stack.append("$" if i > 0 and s[i - 1] in "<>" else "(")
                i += 1
                word_start = True
                continue
            if ch == ")":
                popped = stack.pop() if top else "("
                i += 1
                word_start = popped == "("
                if one_construct and not stack:
                    return comments, i
                continue
            word_start = ch in scope.COMMENT_AFTER
            i += 1
            continue
        i += 1
        word_start = False
        if closed:
            stack.pop()
            if one_construct and not stack:
                return comments, i
    return comments, n


def _comment_starts(command):
    """Offsets of the `#` that really open a comment in `command`. Never raises:
    on anything odd there are none, which keeps every word in view."""
    if "#" not in (command or ""):
        return frozenset()
    try:
        return _shell_nesting(command)[0]
    except Exception:
        return frozenset()


def split_segments(command):
    """Split a command line into pipeline/list segments on ; && || | and
    newlines, respecting single and double quotes. Cheap hand-rolled scan --
    shlex on an arbitrary command line can raise, and we must never raise."""
    return [seg for seg, _op in split_segments_ops(command)]


def split_segments_ops(command):
    """`split_segments`, with the operator that FOLLOWS each segment: "|" for a
    pipe into the next one, ";", "&&", "||", "&", or "" at the end. A comment is
    dropped to the end of its line, so an apostrophe in it can neither join the
    following lines into one quoted segment nor hide the commands on them."""
    segs = []
    ops = []
    buf = []
    quote = None
    i = 0
    comments = _comment_starts(command)
    n = len(command or "")
    while i < n:
        ch = command[i]
        if i in comments:
            newline = command.find("\n", i)
            i = n if newline == -1 else newline
            continue
        if ch == "\\" and command[i + 1:i + 2] == "\n" and quote != "'":
            # A line continuation: bash removes the pair, outside quotes and
            # inside double quotes alike. Kept, it left a lone `\` as the
            # program of `a &&\<newline>sudo rm -rf /etc` and hid the command.
            i += 2
            continue
        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(command[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "$" and command.startswith("$'", i):
            end = _ansi_string_end(command, i)
            buf.append(command[i:end])
            i = end
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(command[i + 1])
            i += 2
            continue
        if ch in ";\n":
            segs.append("".join(buf))
            ops.append(";")
            buf = []
            i += 1
            continue
        if ch == "&" and ((buf and buf[-1] in "<>") or command[i + 1:i + 2] == ">"):
            buf.append(ch)  # `2>&1` and `&> f` are redirections
            i += 1
            continue
        if ch in "&|":
            segs.append("".join(buf))
            buf = []
            start = i
            while i < n and command[i] in "&|":
                i += 1
            ops.append(command[start:i])
            continue
        buf.append(ch)
        i += 1
    segs.append("".join(buf))
    ops.append("")
    return [(seg.strip(), op) for seg, op in zip(segs, ops) if seg.strip()]


_SUBSTITUTION_DEPTH = 8

# Characters one rule may read while following nested code in one command. The
# hook has 5 seconds and fails open, so a command built to keep a rule reading
# would take every rule down with it. The whole command is always read once.
_SCAN_LIMIT = 1000000


class _ScanWork:
    """What one rule has read of one command, across its recursion."""

    def __init__(self):
        self.seen = set()
        self.left = _SCAN_LIMIT

    def spend(self, text, key=None):
        """False when the caller should stop: it has read `key` already, or the
        allowance is gone. Past that point the rule gives up on the nesting it
        has not reached, and the other rules still run."""
        if self.left < 0 or (key is not None and key in self.seen):
            return False
        if key is not None:
            self.seen.add(key)
        self.left -= len(text) + 1
        return True


def _may_substitute(command):
    return any(mark in (command or "") for mark in ("$(", "`", "<(", ">("))


def _closing_paren(text, i):
    """Index of the `)` closing a parenthesis opened just before `i`, or the
    end of `text` when it never closes."""
    depth = 1
    quote = None
    n = len(text)
    while i < n:
        ch = text[i]
        if quote == "'":
            if ch == "'":
                quote = None
        elif ch == "\\":
            i += 2
            continue
        elif ch == '"':
            quote = None if quote == '"' else '"'
        elif quote is None:
            if ch == "'":
                quote = "'"
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if not depth:
                    return i
        i += 1
    return n


def _outer_substitutions(command):
    """(offset, body) of each outermost `$(...)`, backtick and `<(...)` /
    `>(...)` substitution. Single-quoted text, `$'...'`, escapes and comments are
    skipped, as the shell skips them, and `$((...))` is arithmetic rather than a
    command.
    Never raises."""
    out = []
    try:
        s = command or ""
        n = len(s)
        i = 0
        quote = None
        comments = _comment_starts(s)
        while i < n:
            ch = s[i]
            if i in comments:
                newline = s.find("\n", i)
                i = n if newline == -1 else newline
                continue
            if quote == "'":
                if ch == "'":
                    quote = None
                i += 1
                continue
            if ch == "\\":
                i += 2
                continue
            if quote is None and s.startswith("$'", i):
                i = _ansi_string_end(s, i)
                continue
            if ch == "'" and quote is None:
                quote = "'"
            elif ch == '"':
                quote = None if quote == '"' else '"'
            elif s.startswith("$((", i):
                i += 3
                continue
            elif s.startswith("$(", i) or (quote is None and s[i:i + 2] in ("<(", ">(")):
                end = _closing_paren(s, i + 2)
                out.append((i, s[i + 2:end]))
                i = end + 1
                continue
            elif ch == "`":
                end = s.find("`", i + 1)
                end = n if end == -1 else end
                out.append((i, s[i + 1:end]))
                i = end + 1
                continue
            i += 1
    except Exception:
        pass
    return out


def command_substitutions(command, _depth=0):
    """Body of every command substitution, outermost first, nested ones too.
    The depth is bounded because this runs on untrusted text before any rule
    does: a deep enough `$($($(...` must not reach Python's recursion limit."""
    out = []
    if _depth >= _SUBSTITUTION_DEPTH or not _may_substitute(command):
        return out
    for _offset, body in _outer_substitutions(command):
        if body.strip():
            out.append(body)
            out.extend(command_substitutions(body, _depth + 1))
    return out


def all_segments(command):
    """Top-level segments plus those of every substitution: `echo $(sudo x)`
    runs `sudo x`. For the rules that ask what runs. R1 reads the top level and
    substitutions apart, because a captured value is not a printed one."""
    segs = split_segments(command)
    for body in command_substitutions(command):
        segs.extend(split_segments(body))
    return segs


_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*=")


def _after_assignment(toks, i):
    """The index after the assignment at toks[i]. `words()` splits a quoted
    value on its spaces, so `MSG="Remove sudo usage"` is three words there
    and one to bash; read word by word, `sudo` looked like the program.

    The quotes are followed the way the shell reads them (a backslash
    escapes outside single quotes, `"a b"c` is one word), across as many
    words as the value spans. A quote that never closes is not guessed at:
    only the first word is skipped, as before, so what follows is still
    checked."""
    quote = None
    j = i
    while j < len(toks):
        tok = toks[j]
        k = 0
        while k < len(tok):
            c = tok[k]
            if quote is None:
                if c == "\\":
                    k += 2
                    continue
                if c in ("'", '"'):
                    quote = c
            elif quote == '"' and c == "\\":
                k += 2
                continue
            elif c == quote:
                quote = None
            k += 1
        j += 1
        # k past the end: the word ended in a backslash, so the space after
        # it is escaped and the next word belongs to this one (`X=a\ b`).
        if quote is None and k <= len(tok):
            return j
    return i + 1


def words(segment):
    """Whitespace tokens of a segment, quotes stripped off the ends. Never
    raises (unlike shlex.split on an unbalanced quote)."""
    out = []
    for tok in (segment or "").split():
        if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "'\"":
            tok = tok[1:-1]
        out.append(tok)
    return out


# Wrappers whose own options (and, for timeout, a duration) come before the
# command they run. Not skipping them hid `env sudo rm -rf /etc` from R5 and
# `timeout 60 rm -rf /` from R7.
_VALUE_WRAPPERS = {"env", "timeout"}
_ENV_VALUE_OPTS = {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}
_TIMEOUT_VALUE_OPTS = {"-s", "--signal", "-k", "--kill-after"}


def _env_split_string(toks, i):
    """The tokens `env -S STRING` runs, when toks[i] is that option, else None.
    The string is the command: `env -S "cat .env"` reads the file."""
    t = toks[i]
    if t in ("-S", "--split-string"):
        i += 1
        value = toks[i] if i < len(toks) else ""
    elif t.startswith("--split-string="):
        value = t.split("=", 1)[1]
    elif t.startswith("-S"):
        value = t[2:]
    else:
        return None
    i += 1
    quote = value[:1]
    if quote in ("'", '"'):
        # words() split a quoted string on its spaces: put it back together.
        while not (len(value) > 1 and value.endswith(quote)) and i < len(toks):
            value += " " + toks[i]
            i += 1
        value = value.strip(quote)
    while value.endswith("\\") and i < len(toks):  # `sudo\ reboot`
        value = value[:-1] + " " + toks[i]
        i += 1
    return value.split() + toks[i:]


def _wrapped_command(toks, start=0):
    """Where the command run by the `env`/`timeout` wrapper at toks[start]
    begins, as (tokens, index), or None when it runs none."""
    wrapper, i = toks[start].rsplit("/", 1)[-1], start + 1
    value_opts = _ENV_VALUE_OPTS if wrapper == "env" else _TIMEOUT_VALUE_OPTS
    while i < len(toks):
        t = toks[i]
        if t == "--":
            i += 1
            break
        if wrapper == "env":
            if t == "-":  # `env -` is `env -i`
                i += 1
                continue
            split = _env_split_string(toks, i)
            if split is not None:
                return (split, 0) if split else None
        if t.startswith("-") and len(t) > 1:
            i += 2 if t in value_opts else 1
            continue
        if wrapper == "env" and _ASSIGN_RE.match(t):
            i = _after_assignment(toks, i)
            continue
        break
    if wrapper == "timeout":
        i += 1  # the duration
    return (toks, i) if i < len(toks) else None


# Words that put a command straight after them. A segment starts at one of
# these whenever a command sits inside a compound: `if x; then cat .env; fi`.
_COMPOUND_WORDS = {"{", "!", "if", "then", "elif", "else", "do", "while", "until"}
_FUNCTION_HEAD_RE = re.compile(r"^[A-Za-z_][\w.-]*\(\)\{?$")
_REDIRECT_RE = re.compile(r"^\d*[<>]")
_REDIRECT_OP_RE = re.compile(r"^\d*([<>]+\|?&?)")
_GLUED_REDIRECT_RE = re.compile(r"^([^<>$`]+)([<>]+\|?&?)(.*)$")


def _drop_group_closers(toks, excess):
    """Take `excess` closing parens off the end of the segment. They close a
    subshell and belong to no word: `.env)` hid `.env` from R1."""
    for i in range(len(toks) - 1, -1, -1):
        if excess <= 0:
            break
        word = toks[i]
        trailing = len(word) - len(word.rstrip(")"))
        n = min(trailing, excess)
        if n:
            toks[i] = word[:-n]
            excess -= n
    return [t for t in toks if t]


def _word_after_redirects(toks, start=0):
    """True when toks[start:] holds a word that is not a redirection or its
    target."""
    i = start
    while i < len(toks):
        op = _REDIRECT_OP_RE.match(toks[i])
        if not op:
            return True
        i += 2 if op.end() == len(toks[i]) else 1
    return False


def _is_case_pattern(toks, start=0):
    """`x)`, `a|b)` or a bare `)` with a command after it. With nothing after
    it, or only redirections, the word is the last one of a subshell."""
    head = toks[start]
    return head.endswith(")") and "(" not in head and _word_after_redirects(toks, start + 1)


def _after_in(toks, start):
    """Index just past the `in` of a `case WORD in`, or the end when none."""
    try:
        return toks.index("in", start) + 1
    except ValueError:
        return len(toks)


def program_of(segment):
    """First real command word of a segment, skipping what the shell reads
    before it: subshell and group openers, compound-command words, a function
    head, a case pattern, leading VAR=val assignments and wrappers like
    nice/time. A subshell's closing parens are dropped from the arguments.
    Returns (program, args)."""
    toks = words(segment)
    at = 0  # an index: re-slicing per word is quadratic on `! ! ! ...`
    opened = 0
    inputs = []  # files redirected in ahead of the command: `< .env cat`
    while at < len(toks):
        head = toks[at]
        op = _REDIRECT_OP_RE.match(head)
        if op:
            target = head[op.end():]
            at += 1
            if not target and at < len(toks):
                target = toks[at]
                at += 1
            if op.group(1).startswith("<") and target:
                inputs.append(target)
            continue
        if head.startswith("("):
            rest = head.lstrip("(")
            opened += len(head) - len(rest)
            if rest:
                toks[at] = rest
            else:
                at += 1
            continue
        if head in _COMPOUND_WORDS or _FUNCTION_HEAD_RE.match(head):
            at += 1
            continue
        if head == "function":
            at += 2
            continue
        if head == "case":
            at = _after_in(toks, at)
            continue
        if _is_case_pattern(toks, at):
            at += 1
            continue
        if _ASSIGN_RE.match(head):
            at = _after_assignment(toks, at)
            continue
        if head.rsplit("/", 1)[-1] in _VALUE_WRAPPERS:
            # `env FOO=1 sudo ...`, `timeout 5 rm -rf /`: the wrapper runs the
            # command after its own options. A bare `env` (or one with nothing
            # after its options) is itself the program and stays it.
            found = _wrapped_command(toks, at)
            if found is None or not _word_after_redirects(*found):
                break
            toks, at = found
            continue
        if head == "command" and at + 1 < len(toks) and toks[at + 1][:1] == "-" \
                and set(toks[at + 1][1:]) & set("vV"):
            # `command -v sudo` prints where sudo is; it runs nothing.
            break
        if head in _SKIP_PREFIX:
            at += 1
            # a wrapper's own flags (nice -n 10, stdbuf -oL) are not the program
            while at < len(toks) and toks[at].startswith("-"):
                flag = toks[at]
                at += 1
                if flag in ("-n", "-p", "-o", "-e", "-i") and at < len(toks) and not toks[at].startswith("-"):
                    if toks[at].lstrip("+-").isdigit():
                        at += 1
            continue
        break
    toks = toks[at:]
    if ")" in (segment or ""):
        code = _QUOTED_RE.sub('""', segment)
        toks = _drop_group_closers(toks, code.count(")") - code.count("(") + opened)
    if not toks:
        return None, []
    glued = _GLUED_REDIRECT_RE.match(toks[0])
    if glued:  # `cat<.env` is one word to words()
        toks = [glued.group(1)] + ([glued.group(3)] if glued.group(3) else []) + toks[1:]
    prog = toks[0]
    base = prog.rsplit("/", 1)[-1]
    return base, toks[1:] + inputs


def _expand(path):
    p = path or ""
    p = p.replace("$HOME", HOME).replace("${HOME}", HOME)
    if p.startswith("~"):
        p = HOME + p[1:]
    return p


# --- R1: secret exposure -----------------------------------------------------

READERS = {
    "cat", "bat", "less", "more", "head", "tail", "nl", "od", "xxd", "strings",
    "grep", "egrep", "rg", "ag", "awk", "sed", "cut", "tac", "jq", "yq", "tee",
}

# The same job on Windows, in either shell: `type` in cmd, `Get-Content` and
# its aliases in PowerShell, `findstr` in both. Kept SEPARATE from READERS
# above, and matched on a normalised name, because PowerShell is
# case-insensitive, a command may be written with a `.exe` suffix, and a path
# there is `\`-separated -- none of which is true of the POSIX set, whose
# matching is deliberately left exactly as it was.
WINDOWS_READERS = {
    "type", "get-content", "gc", "select-string", "sls", "findstr",
}


def _windows_reader(prog):
    """True iff `prog` names a Windows or PowerShell command that would print
    a file's contents. Never raises."""
    try:
        base = prog.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    except Exception:
        return False
    for suffix in (".exe", ".com", ".cmd", ".bat", ".ps1"):
        if base.endswith(suffix):
            base = base[:-len(suffix)]
            break
    return base in WINDOWS_READERS

# Hard-known secret stores, plus the generic shapes CLAUDE.md names ("`.env`
# files, private keys, `credentials*`, `*.key`, API tokens"). The key file is
# whichever path airlock/keyfile.py resolves to -- the kit default
# ~/.config/jev-kit/env, the guard-era default ~/.config/airlock/env, or an
# AIRLOCK_KEY_FILE / JEVKIT_KEY_FILE override. BOTH defaults are matched here,
# for good: an install whose key never moved is protected exactly as well as a
# fresh one. A machine that keeps its key somewhere else adds that path to
# AIRLOCK_EXTRA_SECRET_PATHS in install/config.env and it is matched here too,
# so R1 protects it without this file naming anybody's directory layout.
SECRET_PATH_RES = [
    # Both defaults, on both platforms and in either spelling. On POSIX the
    # pair is ~/.config/jev-kit/env and ~/.config/airlock/env; on Windows it
    # is %APPDATA%\jev-kit\env and %APPDATA%\airlock\env, which a command may
    # write with backslashes (cmd, PowerShell) or forward slashes (Git Bash).
    # One separator-tolerant, case-insensitive pattern each covers all four,
    # so `type %APPDATA%\airlock\env` and `Get-Content ...\jev-kit\env` are
    # protected exactly as well as `cat ~/.config/airlock/env`.
    re.compile(r"[\\/]jev-kit[\\/]env\b", re.IGNORECASE),
    re.compile(r"[\\/]airlock[\\/]env\b", re.IGNORECASE),
    # The same two written relative to ~/.config: `cat jev-kit/env`.
    re.compile(r"^(\.[\\/])*(jev-kit|airlock)[\\/]env$", re.IGNORECASE),
    re.compile(r"\.credentials\.json\b"),
    re.compile(r"\bcredentials(\.json|\.yml|\.yaml|\.ini)?\b(?!\.example)"),
    re.compile(r"(^|/)\.env(\.[A-Za-z0-9_-]+)?$"),
    re.compile(r"(^|/)\.env(\.[A-Za-z0-9_-]+)?(\s|$)"),
    re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$"),
    re.compile(r"\.(pem|key|p12|pfx|jks)$"),
    re.compile(r"(^|/)\.netrc$"),
    re.compile(r"(^|/)\.pgpass$"),
    re.compile(r"(^|/)\.npmrc$"),
    re.compile(r"(^|/)\.credentials\b"),
]

# Extra key-file paths this machine wants R1 to protect, colon-separated, from
# AIRLOCK_EXTRA_SECRET_PATHS in install/config.env. Each is matched literally,
# with a leading ~ or $HOME stripped so it matches however it is written in a
# command. Nothing is baked in: on a machine that sets nothing, this is empty.
def _extra_secret_path_res():
    try:
        raw = os.environ.get("AIRLOCK_EXTRA_SECRET_PATHS", "")
    except Exception:
        return []
    out = []
    for part in raw.split(os.pathsep):
        part = part.strip()
        if not part:
            continue
        for prefix in ("~/", "$HOME/", "${HOME}/"):
            if part.startswith(prefix):
                part = part[len(prefix):]
                break
        if not part:
            continue
        try:
            out.append(re.compile(re.escape(part) + r"\b"))
        except Exception:
            continue
    return out


SECRET_PATH_RES.extend(_extra_secret_path_res())


# The key-file POINTER, and whatever file it names, are both protected paths.
#
# The pointer (`$AIRLOCK_CONFIG_DIR/keyfile.path`) holds only a path, never a
# key -- but printing it tells a transcript exactly which file on this machine
# to go and read next, and it is written by install/install.sh AFTER a release
# is deployed, so a table built once at deploy time would miss it. Both are
# therefore resolved at HOOK time, and the pointer's target is read with
# `check=False`: a pointer whose permissions mean keyfile.py refuses to FOLLOW
# it still names a file that must not land in a transcript.
#
# Cost is one lstat of a small file per judged call, cached on that stat, so a
# pointer written or repointed between two tool calls is picked up on the next
# one without re-reading the file every time.
_POINTER_CACHE = {"stamp": None, "res": ()}


def _literal_path_re(path, windows=None):
    """A regex matching `path` as it could appear in a command: the absolute
    form, and the home-relative tail (`_expand` has already turned `~` and
    `$HOME` into HOME, so the tail alone covers both).

    Case-insensitive on Windows, where `%APPDATA%\\Airlock\\env` and
    `%appdata%\\airlock\\env` are the same file and R1 must not be fooled by
    which one a command happened to type."""
    flags = re.IGNORECASE if is_windows(windows) else 0
    out = []
    for form in (path, path[len(HOME) + 1:] if path.startswith(HOME + "/") else None):
        if not form:
            continue
        try:
            out.append(re.compile(re.escape(form) + r"(\b|$)", flags))
        except Exception:
            continue
    return out


def _pointer_secret_path_res():
    """Protected-path regexes for the pointer file and its target, refreshed
    whenever the pointer's stat changes. Never raises: on any error R1 falls
    back to the static table, which is the fail-open direction."""
    try:
        pointer = keyfile.pointer_file_path()
        if not pointer:
            return ()
        try:
            st = os.stat(pointer)
            stamp = (pointer, st.st_mtime_ns, st.st_size, st.st_ino)
        except Exception:
            stamp = (pointer, None, None, None)
        if _POINTER_CACHE["stamp"] == stamp:
            return _POINTER_CACHE["res"]
        res = list(_literal_path_re(pointer))
        target = keyfile.pointer_target(check=False)
        if target:
            res.extend(_literal_path_re(target))
        res = tuple(res)
        _POINTER_CACHE["stamp"] = stamp
        _POINTER_CACHE["res"] = res
        return res
    except Exception:
        return ()


def secret_path_res():
    """Every protected-path regex R1 should test: the static table, plus the
    pointer pair resolved now. Use this, never SECRET_PATH_RES directly."""
    return tuple(SECRET_PATH_RES) + _pointer_secret_path_res()

# Paths that look secret-ish but are fine, so the code pre-filter must not hit.
SAFE_PATH_RES = [
    re.compile(r"\.(example|sample|template|dist|md|rst|txt\.example)$"),
    re.compile(r"\.env\.(example|sample|template)\b"),
    re.compile(r"(^|/)env\.example\b"),
    re.compile(r"\.pub$"),
]

# Ambiguous: a reader aimed at something that MIGHT hold a secret. Code cannot
# tell; Jev is asked, and only for these.
AMBIGUOUS_SECRET_TOKENS = (
    "secret", "secrets", "token", "password", "passwd", "credential",
    "keyring", "keystore", "htpasswd", "vault", "apikey", "api_key",
)

SECRET_VAR_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z_0-9]*)\}?")
SECRET_VAR_NAME_RE = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|CREDENTIAL)", re.IGNORECASE)

R1_SUGGESTION_POSIX = (
    "Do not print a secret. Load it into the environment instead, in the same "
    "shell as the command that needs it:\n"
    "    set -a; . ~/.config/jev-kit/env; set +a\n"
    "and confirm it is present WITHOUT revealing it:\n"
    "    [ -n \"$TYPESAFE_API_KEY\" ] && echo 'key loaded'\n"
    "List variable names without their values with `compgen -e`.\n"
    "If output might contain a key, pipe it through:\n"
    "    sed 's/apikey_[A-Za-z0-9_]*/[REDACTED]/g'"
)

# The same advice in commands that exist on Windows. A deny that tells a
# Windows session to run `set -a; . ~/.config/jev-kit/env` is advice it cannot
# follow in either of its shells, so the platform picks the wording.
R1_SUGGESTION_WINDOWS = (
    "Do not print a secret. Load it into the environment instead, in the same "
    "shell as the command that needs it. In PowerShell, read it WITHOUT a "
    "reader cmdlet, so nothing can reach the transcript:\n"
    "    [IO.File]::ReadAllLines(\"$env:APPDATA\\jev-kit\\env\") | "
    "ForEach-Object { $n,$v = $_ -split '=',2; Set-Item \"env:$n\" $v }\n"
    "and confirm it is present WITHOUT revealing it:\n"
    "    if ($env:TYPESAFE_API_KEY) { 'key loaded' }\n"
    "If output might contain a key, pipe it through:\n"
    "    ... | ForEach-Object { $_ -replace 'apikey_[A-Za-z0-9_]*','[REDACTED]' }\n"
    "cmd has no equivalent one-liner: use PowerShell for this, or have the "
    "human set the variable."
)

R1_SUGGESTION = R1_SUGGESTION_WINDOWS if is_windows() else R1_SUGGESTION_POSIX


def _is_safe_path(tok):
    return any(r.search(tok) for r in SAFE_PATH_RES)


_REDIR_SPLIT_RE = re.compile(r"\d*[<>]+&?")


def _path_parts(tokens):
    """Each token, and the paths glued to a redirection inside it: `<.env`
    and `.env>/dev/stdout` are one word to `words()`, and the anchored
    secret-path patterns saw neither `.env`."""
    for tok in tokens:
        yield tok
        if "<" in tok or ">" in tok:
            for part in _REDIR_SPLIT_RE.split(tok):
                if part and part != tok:
                    yield part


def _secret_path_in(tokens):
    for tok in _path_parts(tokens):
        if tok.startswith("-"):
            continue
        if _is_safe_path(tok):
            continue
        p = _expand(tok)
        for r in secret_path_res():
            if r.search(p):
                return tok
    return None


# Readers whose first operand is a pattern, program or filter rather than a
# file, unless the script comes from an option instead (-e/-f and friends).
# Readers whose first operand is a pattern or filter rather than a file,
# unless the pattern comes from an option instead (-e/-f and friends). awk and
# sed are left out on purpose: their program text can itself read a file
# (`getline < f`, sed's `r f`), so it stays in view as before.
_PATTERN_FIRST = {
    "grep": ("-e", "-f", "--regexp", "--file"),
    "egrep": ("-e", "-f", "--regexp", "--file"),
    "rg": ("-e", "-f", "--regexp", "--file", "--files"),
    "ag": ("-f", "--file-search-regex"),
    "jq": ("-f", "--from-file"),
    "yq": ("-f", "--from-file"),
}
# Flags that take no value, per reader. The pattern is dropped only when
# every flag in front of it is one of these: an option that does take a
# value (`--include .env`, `rg -g .env`) may be a glob naming the very files
# read, and a value mistaken for the pattern would hide them.
_NO_VALUE_SHORT = {
    "grep": set("rRnilcvwxshHoqLZEFGPaUIbTuz"),
    "egrep": set("rRnilcvwxshHoqLZEFGPaUIbTuz"),
    "rg": set("inlcvwxsSFHoqLuUPaz.N"),
    "ag": set("inlcvwsSQaurUzZ"),
    "jq": set("rcnsjaSCeMR"),
    "yq": set("rcnsjaSCeMR"),
}
_NO_VALUE_LONG = frozenset((
    "--recursive", "--dereference-recursive", "--line-number", "--ignore-case",
    "--files-with-matches", "--files-without-match", "--count", "--invert-match",
    "--word-regexp", "--line-regexp", "--fixed-strings", "--extended-regexp",
    "--perl-regexp", "--only-matching", "--no-filename", "--with-filename",
    "--quiet", "--silent", "--hidden", "--no-ignore", "--follow", "--smart-case",
    "--case-sensitive", "--raw-output", "--compact-output", "--null-input",
    "--slurp", "--join-output", "--ascii-output", "--sort-keys", "--exit-status",
    "--color", "--no-messages", "--text", "--null",
))


def _only_plain_flags(prog, flags):
    letters = _NO_VALUE_SHORT.get(prog, set())
    for f in flags:
        if f.startswith("--"):
            if f.split("=", 1)[0] not in _NO_VALUE_LONG:
                return False
        elif not (len(f) > 1 and set(f[1:]) <= letters):
            return False
    return True


_OUTPUT_REDIRECT_RE = re.compile(r"^(?:\d*>>?|&>>?|>\|)(.*)$")
# An input redirection in the raw text: `< f`, `0<f`, never `<<` or `<(`.
_INPUT_REDIRECT_RE = re.compile(r"(?<![<\d])\d*<(?![<(&])")


def _pattern_from_option(script_opts, args):
    """True when an option supplies the pattern, so no operand is it. Short
    flags may be clustered (`-rf pats`, `-ie x`): any of the option letters
    anywhere in a cluster counts."""
    letters = {o[1] for o in script_opts if len(o) == 2}
    for a in args:
        if a in script_opts or a.split("=", 1)[0] in script_opts:
            return True
        if len(a) > 1 and a[0] == "-" and a[1] != "-" and letters & set(a[1:]):
            return True
    return False


def _read_operands(prog, args, seg=""):
    """The arguments of a reader that can name a file it reads.

    Left out: an output redirection and its target (`cat > .env` writes the
    file, it prints nothing), `tee`'s operands (it writes them and prints its
    stdin), and the leading pattern of grep/rg/ag/jq/yq (`grep -rn
    credentials src/` searches src/ for a word). Each is dropped only when
    the raw text shows it really is one: a quoted `">"` is an argument, and
    `tee out < .env` reads .env. When in doubt the operand stays, which only
    ever denies more."""
    code = _QUOTED_RE.sub('""', seg or "")
    if prog == "tee":
        # tee reads only its stdin. With an input redirection anywhere in
        # the segment, which word is the input is left to the full check.
        return list(args) if _INPUT_REDIRECT_RE.search(code) else []
    out = list(args)
    quoted_operator = any(_OUTPUT_REDIRECT_RE.match(q[1:-1])
                          for q in _QUOTED_RE.findall(seg or ""))
    if not quoted_operator:
        out = []
        skip_next = False
        for a in args:
            if skip_next:
                skip_next = False
                continue
            m = _OUTPUT_REDIRECT_RE.match(a)
            if m:
                skip_next = not m.group(1)
                continue
            out.append(a)
    script_opts = _PATTERN_FIRST.get(prog)
    if script_opts and not _pattern_from_option(script_opts, out):
        for i, a in enumerate(out):
            if a == "--":
                if i + 1 < len(out) and _only_plain_flags(prog, out[:i]):
                    del out[i + 1]
                break
            if a.startswith("<"):
                break  # a redirection, not the pattern: keep everything
            if not a.startswith("-"):
                if _only_plain_flags(prog, out[:i]):
                    del out[i]
                break
    return out


def _spaced_quoted_words(seg):
    """Quoted words holding whitespace, unquoted. `words()` splits on spaces
    inside quotes too, so `cat "/home/u/My Project/.env"` reached the path
    patterns as `"/home/u/My` and `Project/.env"`, and neither matched."""
    out = []
    for m in _QUOTED_RE.finditer(seg or ""):
        body = m.group(0)[1:-1]
        if any(c.isspace() for c in body):
            out.append(body)
    return out


def _key_file_paths():
    """Every path the key can live at on this machine. Never raises."""
    found = []
    try:
        found = list(keyfile.default_env_files()) + list(keyfile.legacy_env_files())
        found += [keyfile.key_file(), keyfile.pointer_file_path(),
                  keyfile.pointer_target(check=False)]
    except Exception:
        pass
    return {os.path.normpath(_expand(str(p))) for p in found if p}


def _key_file_from(tokens, cwd):
    """The relative path in `tokens` that lands on a key file when read from
    `cwd`: `cd ~/.config/jev-kit && cat env`. Key files only, because a bare
    word such as `credentials` in a directory's path must not make every file
    in that directory a secret."""
    if not cwd:
        return None
    known = None
    for tok in _path_parts(tokens):
        if tok.startswith(("-", "/", "~", "$")):
            continue
        if known is None:
            known = _key_file_paths()
        if os.path.normpath(os.path.join(cwd, tok)) in known:
            return tok
    return None


def _ambiguous_path_in(tokens):
    for tok in tokens:
        if tok.startswith("-") or _is_safe_path(tok):
            continue
        low = tok.lower()
        if "/" not in low and "." not in low:
            continue
        if any(t in low for t in AMBIGUOUS_SECRET_TOKENS):
            return tok
    return None


def _quiet_grep(args):
    """grep -q / -c / -l never puts the matched line in the transcript."""
    for a in args:
        if a.startswith("-") and not a.startswith("--"):
            if any(c in a[1:] for c in "qcl"):
                return True
        if a in ("--quiet", "--silent", "--count", "--files-with-matches"):
            return True
    return False


_ASSIGN_BUILTINS = {"export", "local", "readonly", "declare", "typeset"}


_ASSIGN_CHECK_LIMIT = 64


def _substituted_segments(command, _depth=0, work=None):
    """Segments of every substitution in the command. `echo "$(cat .env)"`
    prints the file, but its only segment is an echo."""
    out = []
    if _depth >= _SUBSTITUTION_DEPTH or not _may_substitute(command):
        return out
    if work and not work.spend(command):
        return out
    try:
        command = strip_heredocs(command)
        for index, (offset, inner) in enumerate(_outer_substitutions(command)):
            # `KEY=$(cat ~/.config/jev-kit/env)` loads the value without
            # printing it, which is what R1's own advice asks for. Past the
            # first few the exemption ends, because each check rescans the
            # command so far.
            checked = index < _ASSIGN_CHECK_LIMIT and (not work or work.spend(command[:offset]))
            before = split_segments(command[:offset]) if checked else []
            toks = words(before[-1]) if before else []
            # Glued to the assignment: `x=1 $(cat .env)` runs the file's text
            # as a command, and the shell's error prints it.
            glued = not command[:offset].endswith((" ", "\t"))
            if glued and toks and all(_ASSIGN_RE.match(t) or t in _ASSIGN_BUILTINS for t in toks):
                continue
            if inner.startswith("<"):
                inner = "cat " + inner[1:]  # `$(<.env)` is bash for `$(cat .env)`
            out.extend(split_segments(inner))
            out.extend(_substituted_segments(inner, _depth + 1, work))
    except Exception:
        return []
    return out


# `${VAR:+word}` and `${VAR+word}` expand to `word` or nothing, never to the
# value, and `${#VAR}` is its length. The word must be plain text: no `$`, no
# backtick, no `(` and no backslash, so it cannot smuggle a second expansion
# (`${KEY:+$KEY}`) or a command substitution back in.
_VALUELESS_EXPANSION_RE = re.compile(
    r"\$\{#[A-Za-z_][A-Za-z_0-9]*\}"
    r"|\$\{[A-Za-z_][A-Za-z_0-9]*:?\+[^}$`(\\]*\}"
)
# `${!name}` is indirection: it prints whatever variable `name` names.
_INDIRECT_EXPANSION_RE = re.compile(r"\$\{!")

_SHELL_META = set("<>`$;&|(){}")


def _lex(seg):
    """POSIX shlex words of one segment, or None when it cannot be lexed
    cleanly or carries any redirection, substitution or operator character
    outside quotes. A filter like that is never treated as names-only."""
    if _SHELL_META & set(_QUOTED_RE.sub("", seg)):
        return None
    try:
        lexer = shlex.shlex(seg, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except Exception:
        return None


def _class_is_name_chars(body):
    """A bracket class may hold only A-Z, a-z, 0-9 ranges and the literal
    characters [A-Za-z0-9_]. Any other range (`[*-?]` spans `=`) or a
    negation refuses."""
    i = 0
    while i < len(body):
        if body[i:i + 3] in ("A-Z", "a-z", "0-9"):
            i += 3
        elif re.match(r"[A-Za-z0-9_]", body[i]):
            i += 1
        else:
            return False
    return bool(body)


def _name_only_alternative(alt):
    """`^PREFIX...`: anchored, a literal prefix of 3+ name characters (so a
    continuation line of a multi-line value cannot match by accident), then
    only name characters, name-only classes and quantifiers. No backslash, no
    dot, no negation, no `=`."""
    m = re.match(r"^\^[A-Za-z0-9_]{3,}", alt)
    if not m:
        return False
    rest = alt[m.end():]
    i = 0
    while i < len(rest):
        c = rest[i]
        if c == "[":
            j = rest.find("]", i + 1)
            if j < 0 or not _class_is_name_chars(rest[i + 1:j]):
                return False
            i = j + 1
        elif re.match(r"[A-Za-z0-9_*+?]", c):
            i += 1
        elif c == "{":
            j = rest.find("}", i)
            if j < 0 or not re.match(r"^\d+(,\d*)?$", rest[i + 1:j]):
                return False
            i = j + 1
        else:
            return False
    return True


def _grep_flags(args):
    """Split grep args into (short-flag letters, long flags, operands), or
    None if a flag takes a value (-e/-f/-A/-m ...), which would change what the
    operands mean."""
    letters, longs, operands = set(), set(), []
    for a in args:
        if a.startswith("--"):
            if "=" in a or a in ("--regexp", "--file"):
                return None
            longs.add(a)
        elif a.startswith("-") and len(a) > 1:
            if set(a[1:]) & set("efABCmd"):
                return None
            letters.update(a[1:])
        else:
            operands.append(a)
    return letters, longs, operands


_STDERR_REDIRECT_RE = re.compile(r"^2>(&[12]|/dev/null)$")
_WC_FLAGS = {"-l", "-c", "-w", "-m", "--lines", "--bytes", "--words", "--chars"}


def _names_only_filter(toks):
    """True iff this stage, reading env output on stdin, can only print
    variable names or a count, never any part of a value.

    `cut -d= -f1 -s` is deliberately absent. It keeps whatever comes before an
    `=` on any line, and the line of a multi-line value that ends in base64
    padding is a piece of that value. `compgen -e` lists the names safely."""
    if not toks:
        return False
    prog, args = toks[0].rsplit("/", 1)[-1], toks[1:]
    if prog == "wc":
        return all(a in _WC_FLAGS for a in args)
    if prog in ("grep", "egrep"):
        parsed = _grep_flags(args)
        if parsed is None:
            return False
        letters, longs, operands = parsed
        if letters & set("qcl") or longs & {"--quiet", "--silent", "--count", "--files-with-matches"}:
            return not operands[1:]  # no file operand after the pattern
        only = "o" in letters or "--only-matching" in longs
        if not only or len(operands) != 1 or "P" in letters or "--perl-regexp" in longs:
            return False
        return all(_name_only_alternative(x) for x in re.split(r"\\\||\|", operands[0]))
    return False


def _writes_only_to_next_stage(toks):
    """True iff this stage between `env` and the filter sends everything down
    the pipe. tee, `sort -o FILE`, `uniq - FILE`, `sed w`, `awk print > file` and
    anything not named here can write elsewhere, so they end the exemption."""
    prog, args = toks[0].rsplit("/", 1)[-1], toks[1:]
    if prog in ("grep", "egrep"):
        parsed = _grep_flags(args)
        return parsed is not None and len(parsed[2]) == 1
    if prog in ("head", "tail"):
        return all(re.match(r"^-\d+$", a) for a in args)
    if prog in ("sort", "uniq"):
        return all(re.match(r"^-[bcdfinruz]+$", a) for a in args)
    return False


def _names_only_pipe(pairs, idx):
    """True iff segment `idx` (a bare `env`) pipes straight into a names-only
    filter, through stages that write only to the next one. Never raises."""
    try:
        j = idx
        while pairs[j][1] == "|" and j + 1 < len(pairs):
            j += 1
            toks = _lex(pairs[j][0])
            if not toks:
                return False
            if _names_only_filter(toks):
                return True
            if not _writes_only_to_next_stage(toks):
                return False
        return False
    except Exception:
        return False


def _reader_behind(prog, args):
    """The command `xargs` or `find -exec` runs, when that is what reads the
    file: `xargs cat .env` and `find . -name .env -exec cat {} +` print it
    just as `cat .env` does."""
    if prog == "xargs":
        i = _first_positional(args, _XARGS_VALUE_OPTS)
        if i is not None:
            return args[i].rsplit("/", 1)[-1], args[i + 1:]
    if prog == "find":
        for i, a in enumerate(args):
            if a in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(args):
                return args[i + 1].rsplit("/", 1)[-1], args[:i] + args[i + 2:]
    return prog, args


def prefilter_secret(ctx):
    tool = ctx["tool_name"]

    if tool in ("Read", "NotebookRead"):
        fp = str((ctx["tool_input"] or {}).get("file_path") or "")
        if fp and not _is_safe_path(fp):
            p = _expand(fp)
            for r in secret_path_res():
                if r.search(p):
                    return Match(
                        "Read of a secret store (%s): its contents would land in the transcript" % fp,
                        R1_SUGGESTION,
                    )
            low = p.lower()
            if any(t in low for t in AMBIGUOUS_SECRET_TOKENS):
                return Match("Read of a path that may hold secrets (%s)" % fp, R1_SUGGESTION, ask=True,
                             extra={"target": fp, "kind": "read"})
        return None

    if tool not in SHELL_TOOLS:
        return None

    command = ctx["command"]
    if not command:
        return None
    return _secret_in_shell(command, cwd=ctx.get("cwd") or "")


def _secret_in_shell(command, depth=0, cwd="", work=None):
    """R1 over a command line, and over any code it hands to another shell:
    `bash -c 'cat .env'` and `eval cat .env` print the file too.

    `_substituted_segments` flattens every level, so each level of
    `eval $(eval $(...))` reaches the same scripts again. `work` keeps that to
    one reading of each, and ends the scan for the shapes that differ on each
    path."""
    if not command or depth > _HANDED_CODE_DEPTH:
        return None
    work = work or _ScanWork()
    if not work.spend(command, (command, depth, cwd)):
        return None
    pairs = split_segments_ops(strip_heredocs(command))
    top_level = len(pairs)
    for seg_idx, seg in enumerate([seg for seg, _op in pairs] + _substituted_segments(command, work=work)):
        handed = _secret_in_shell(_handed_code(seg), depth + 1, cwd, work)
        if handed:
            return handed
        prog, args = _reader_behind(*_unsudo(*program_of(seg)))
        if prog is None:
            continue
        if prog == "cd" and args:
            cwd = os.path.join(cwd, _expand(args[0]))
            continue

        # a reader aimed at a known secret store
        if prog in READERS or _windows_reader(prog):
            if prog in ("grep", "egrep", "rg", "ag") and _quiet_grep(args):
                continue
            operands = _read_operands(prog, args, seg)
            hit = (_secret_path_in(operands) or _secret_path_in(_spaced_quoted_words(seg))
                   or _key_file_from(operands, cwd))
            if hit:
                return Match(
                    "`%s` on a secret store (%s) would print its contents" % (prog, hit),
                    R1_SUGGESTION,
                )
            amb = _ambiguous_path_in(operands)
            if amb:
                return Match(
                    "`%s` on a path that may hold secrets (%s)" % (prog, amb),
                    R1_SUGGESTION, ask=True, extra={"target": amb, "kind": "reader"},
                )

        # echo/printf/printenv of a secret-named variable. `${VAR:+set}`,
        # `${VAR+set}` and `${#VAR}` never expand to the value: they are the
        # documented way to check a key is present, so they are dropped first.
        if prog in ("echo", "printf"):
            if _INDIRECT_EXPANSION_RE.search(seg):
                return Match("`%s` of an indirect expansion (${!name}) can print any variable" % prog,
                             R1_SUGGESTION)
            for name in SECRET_VAR_RE.findall(_VALUELESS_EXPANSION_RE.sub("", seg)):
                if SECRET_VAR_NAME_RE.search(name):
                    return Match(
                        "`%s` would print $%s, whose name says it holds a secret" % (prog, name),
                        R1_SUGGESTION,
                    )
        if prog == "printenv":
            if not args:
                return Match("bare `printenv` dumps every variable, secrets included", R1_SUGGESTION)
            for a in args:
                if SECRET_VAR_NAME_RE.search(a):
                    return Match("`printenv %s` would print a secret value" % a, R1_SUGGESTION)

        # An unfiltered environment dump, unless it is piped straight into a
        # filter that keeps only names or a count (`env | wc -l`,
        # `env | grep -o '^PAPERCLIP[A-Z_]*'`, `env | grep -c X`). `2>&1` does
        # not stop `env` printing.
        args = [a for a in args if not _STDERR_REDIRECT_RE.match(a)]
        if prog in ("env", "set", "export", "declare") and not args:
            if prog == "env" and seg_idx < top_level and _names_only_pipe(pairs, seg_idx):
                continue
            # Bare `export` prints every exported variable with its value, as
            # `export -p` does, and bare `declare` every variable.
            return Match("bare `%s` dumps every variable, secrets included" % prog, R1_SUGGESTION)
        if prog == "export" and args == ["-p"]:
            return Match("`export -p` dumps every exported variable, secrets included", R1_SUGGESTION)
        if prog == "declare" and args and args[0] in ("-x", "-p"):
            return Match("`declare %s` dumps every variable, secrets included" % args[0], R1_SUGGESTION)

        # curl -v with an Authorization header on the command line
        if prog in ("curl", "http", "wget"):
            verbose = any(a in ("-v", "--verbose", "--trace", "--trace-ascii", "-i", "--include") for a in args)
            has_auth = bool(re.search(r"authorization\s*:", seg, re.IGNORECASE))
            if verbose and has_auth:
                return Match(
                    "`%s` in verbose mode echoes the Authorization header, including the token" % prog,
                    "Drop -v/--verbose when a credential is on the command line, or move the token into a "
                    "variable and pipe the output through sed 's/apikey_[A-Za-z0-9_]*/[REDACTED]/g'.",
                )
    for script in _stdin_scripts(command):
        handed = _secret_in_shell(script, depth + 1, cwd, work)
        if handed:
            return handed
    return None


def questions_secret(ctx, match):
    # This state leaves the box. R1 asks precisely about commands near a
    # secret, so it is the rule most likely to carry one inline.
    from . import redact
    state = {
        "command": redact.redact_and_truncate_command(ctx["command"] or "")[:2000],
        "tool_name": ctx["tool_name"],
        "target": redact.redact(match.extra.get("target", "")),
    }
    qs = {
        "prints_a_secret": {
            "type": "choice",
            "instructions": {
                "question": (
                    "Would running this tool call put a SECRET VALUE (an API key, "
                    "token, password, private key, or credential) into the session "
                    "transcript, where it would be recorded?"
                ),
                "focus": (
                    "The test is whether a secret VALUE gets printed. Mentioning the "
                    "NAME of a secret variable, checking that one is set without "
                    "printing it, or reading an example/template file are all safe."
                ),
            },
            "criteria": {
                "yes": {
                    "what": "The output of this call would contain the secret value itself.",
                    "not_for": "A call that only names a variable, counts matches, or tests emptiness.",
                    "examples": [
                        "cat ~/.config/jev-kit/env",
                        "echo $TYPESAFE_API_KEY",
                        "grep -n API ~/secrets/prod.env",
                    ],
                },
                "no": {
                    "what": "No secret value would be printed.",
                    "not_for": "A call that does print the value, even incidentally.",
                    "examples": [
                        "grep -rn TOKEN_NAME src/config.py",
                        "[ -n \"$GS_JIRA_API_TOKEN\" ] && echo set",
                        "cat .env.example",
                    ],
                },
                "unclear": {
                    "what": "Not enough information to tell.",
                    "not_for": "Use only when truly stuck.",
                    "examples": [],
                },
            },
        }
    }
    return state, qs


def deny_secret(answers):
    a = (answers or {}).get("prints_a_secret") or {}
    return (a.get("choice") or "") == "yes"


# --- R2: the claude-api skill ------------------------------------------------

R2_SUGGESTION = (
    "Do not load the `claude-api` skill for a price or model-id lookup: it is "
    "all-or-nothing and one load measured 324,006 input tokens. Read your local "
    "note of the model ids and rates instead, and never compute a cost by "
    "multiplying tokens by a rate -- if the number is not already recorded, say so."
)


def _skill_name(ctx):
    ti = ctx["tool_input"] or {}
    return str(ti.get("skill") or ti.get("name") or "").strip().lstrip("/")


def prefilter_claude_api(ctx):
    if ctx["tool_name"] != "Skill":
        return None
    if _skill_name(ctx) != "claude-api":
        return None
    purpose = str((ctx["tool_input"] or {}).get("args") or "").strip()
    if purpose:
        return Match("Skill(claude-api) with a stated purpose", R2_SUGGESTION, ask=True,
                     extra={"purpose": purpose})
    # No purpose in the payload: nothing to judge, so this can only warn.
    return Match("Skill(claude-api) with no stated purpose in the payload", R2_SUGGESTION,
                 extra={"downgrade_to": "warn"})


def questions_claude_api(ctx, match):
    from . import redact
    state = {"skill": "claude-api", "args": redact.redact(match.extra.get("purpose", ""))[:2000]}
    qs = {
        "purpose": {
            "type": "choice",
            "instructions": {
                "question": (
                    "A session is about to load a large API reference skill. From the "
                    "arguments given, what is it being loaded FOR?"
                ),
                "focus": "Distinguish a one-fact lookup from genuine API depth.",
            },
            "criteria": {
                "price_or_model_id_lookup": {
                    "what": "Looking up a price, a rate, a token count, a cost, or a model id/name.",
                    "not_for": "Work that needs the API's semantics rather than one of its numbers.",
                    "examples": [
                        "what did that run cost",
                        "which model id is Sonnet 4.5",
                        "per-token price for Opus",
                    ],
                },
                "api_depth": {
                    "what": "Migration, tool-use semantics, streaming, caching behaviour, SDK usage.",
                    "not_for": "A single price or model id.",
                    "examples": [
                        "migrate this client to the new tool-use format",
                        "how does prompt caching interact with streaming",
                    ],
                },
                "unclear": {
                    "what": "Not enough information to tell.",
                    "not_for": "Use only when truly stuck.",
                    "examples": [],
                },
            },
        }
    }
    return state, qs


def deny_claude_api(answers):
    a = (answers or {}).get("purpose") or {}
    return (a.get("choice") or "") == "price_or_model_id_lookup"


# --- R3: whole test suite / uncapped parallel build ---------------------------

_PYTEST_SELECTOR_FLAGS = ("-k", "-m", "--lf", "--last-failed", "--ff", "--co", "--collect-only")
_JS_RUNNERS = {"vitest", "jest", "mocha", "ava"}


def _has_path_arg(args, exts=(".py", ".js", ".ts", ".tsx", ".jsx", ".mjs")):
    for a in args:
        if a.startswith("-"):
            continue
        if "::" in a or a.endswith(exts) or "/" in a:
            return True
    return False


def prefilter_wide_run(ctx, cpus=None):
    """R3's pre-filter. Written for gs, the shared 4-core VPS: an uncapped
    whole-suite run or build genuinely contends there. It stays silent on a
    machine with headroom to spare (see `airlock.headless.is_small_host`),
    so a 12-core workstation does not get warned about someone else's box.

    `cpus` pins the core count instead of detecting it; `ctx["cpus"]` does the
    same for a caller that only has a ctx to hand (the eval harness pins it so
    a case's expected label does not depend on the machine scoring it). The
    probe is deferred until a segment actually looks like an R3 command, so an
    ordinary `ls` or `git status` costs no cgroup reads on the hook's hot path.
    """
    if ctx["tool_name"] not in SHELL_TOOLS:
        return None
    if cpus is None:
        cpus = ctx.get("cpus")
    cached = {}

    def small_host_cores():
        """Core count if this host is small enough for R3 to speak, else None.
        Probed at most once per call."""
        if "n" not in cached:
            cached["n"] = cpu_count(cpus)
        n = cached["n"]
        return n if is_small_host(n) else None

    for seg in ctx["segments"]:
        prog, args = program_of(seg)
        if prog is None:
            continue

        if prog in ("python", "python3") and args[:2] == ["-m", "pytest"]:
            prog, args = "pytest", args[2:]
        if prog == "uv" and args[:2] == ["run", "pytest"]:
            prog, args = "pytest", args[2:]

        if prog == "pytest":
            if _has_path_arg(args) or any(a in _PYTEST_SELECTOR_FLAGS for a in args):
                continue
            n = small_host_cores()
            if n is None:
                return None
            capped = any(a.startswith("-n") or a.startswith("--numprocesses") for a in args)
            return Match(
                "`pytest` with no path or selector runs the WHOLE suite on a %d-core box" % n,
                "Run only what the change touched, plus a whole-project typecheck:\n"
                "    pytest tests/test_<thing>.py -x -q%s" % ("" if capped else "\nand cap parallelism: -n2"),
            )

        # `npx jest` / `npx -y vitest` run the runner itself. Without this the
        # outer test below needed args[0] to be `test` or `run`, so the npx
        # branch inside it never matched a runner.
        shown = prog
        if prog == "npx":
            rest = list(args)
            while rest and rest[0] in ("-y", "--yes", "--no-install", "-q", "--quiet"):
                rest = rest[1:]
            if rest and rest[0] in _JS_RUNNERS:
                prog, args = rest[0], rest[1:]
                shown = "npx " + prog

        if prog in _JS_RUNNERS or (prog in ("npm", "pnpm", "yarn", "npx") and args[:1] in (["test"], ["run"])):
            joined = " ".join(args)
            if prog in ("npm", "pnpm", "yarn") and args[:1] == ["run"] and args[1:2] != ["test"]:
                continue
            if prog == "npx" and not (args[1:2] and args[1] in _JS_RUNNERS or args[:1] and args[0] in _JS_RUNNERS):
                continue
            if _has_path_arg(args):
                continue
            if "--maxWorkers" in joined or "--max-workers" in joined or "--pool" in joined or "--threads" in joined:
                continue
            n = small_host_cores()
            if n is None:
                return None
            return Match(
                "`%s` runs the whole test suite with uncapped workers (%d shared cores)"
                % (" ".join([shown] + args).strip(), n),
                "Name the test file, and cap workers:\n"
                "    %s %s -- <path/to/test> --maxWorkers=2" % (shown, (args[0] if args else "test")),
            )

        if prog == "make":
            for a in args:
                if a == "-j" or (a.startswith("-j") and not a[2:].isdigit()):
                    n = small_host_cores()
                    if n is None:
                        return None
                    return Match(
                        "`make -j` with no number takes every core on a %d-core shared box" % n,
                        "Cap it explicitly: make -j2 (and `nice -n 10 make -j2` for a long build).",
                    )

        if prog == "cargo" and args[:1] and args[0] in ("build", "test", "check", "clippy"):
            if not any(a == "-j" or a.startswith("-j") or a.startswith("--jobs") for a in args):
                n = small_host_cores()
                if n is None:
                    return None
                return Match(
                    "`cargo %s` with no -j uses every core on a %d-core shared box" % (args[0], n),
                    "Cap it explicitly: cargo %s -j2" % args[0],
                )
    return None


# --- R4: long work on a bare shell -------------------------------------------

R4_SUGGESTION = (
    "This box is reached only over SSH, so a dropped connection kills anything "
    "attached to the shell. Run it in the named tmux session with stdin closed:\n"
    "    tmux new-session -d -s work 'cd <dir> && <command> </dev/null "
    ">>~/logs/work.log 2>&1'\n"
    "then poll with `tmux has-session -t work` / tail the log."
)

# Unambiguously slow: no need to ask anything.
_SLOW_CERTAIN = (
    ("playwright", "install"),
    ("uv", "sync"),
    ("pnpm", "install"),
    ("npm", "install"),
    ("npm", "ci"),
    ("yarn", "install"),
    ("docker", "build"),
    ("docker", "pull"),
    ("apt", "install"),
    ("apt-get", "install"),
    ("apt", "upgrade"),
    ("apt-get", "upgrade"),
)


def _in_tmux(command, ctx):
    if "tmux " in command or command.strip().startswith("tmux"):
        return True
    if (ctx["tool_input"] or {}).get("run_in_background"):
        return True
    return False


def prefilter_long_run(ctx):
    if ctx["tool_name"] not in SHELL_TOOLS:
        return None
    command = ctx["command"]
    if not command or _in_tmux(command, ctx):
        return None

    for seg in ctx["segments"]:
        prog, args = program_of(seg)
        if prog is None:
            continue
        if any(a in ("--help", "-h", "--version", "--dry-run", "-n") for a in args):
            continue
        sub = args[0] if args else ""

        if prog == "sudo" and args:
            prog, args = args[0], args[1:]
            sub = args[0] if args else ""

        for p, s in _SLOW_CERTAIN:
            if prog == p and sub == s:
                return Match("`%s %s` routinely runs for minutes" % (p, s), R4_SUGGESTION)
        if prog == "npx" and args[:2] == ["playwright", "install"]:
            return Match("`npx playwright install` routinely runs for minutes", R4_SUGGESTION)

        ambiguous = (
            (prog in ("pip", "pip3") and sub == "install")
            or (prog in ("python", "python3") and args[:3] == ["-m", "pip", "install"])
            or (prog == "uv" and sub == "pip")
            or (prog == "git" and sub == "clone")
            or (prog == "cargo" and sub in ("build", "install"))
            or (prog == "make" and not args)
            or (prog in ("wget", "curl") and re.search(r"\.(tar\.gz|tgz|zip|iso|deb|whl|bin)\b", seg))
        )
        if ambiguous:
            return Match(
                "`%s %s` may run longer than two minutes on a bare SSH shell" % (prog, sub),
                R4_SUGGESTION, ask=True, extra={"segment": seg[:400]},
            )
    return None


def questions_long_run(ctx, match):
    from . import redact
    state = {"command": redact.redact_and_truncate_command(ctx["command"] or "")[:2000],
             "segment": redact.redact(match.extra.get("segment", ""))[:600]}
    qs = {
        "runs_over_two_minutes": {
            "type": "noul",
            "instructions": (
                "Is this shell command likely to run for longer than two minutes "
                "on a 4-vCPU cloud server with a normal home broadband-speed "
                "network link?"
            ),
            "criteria": {
                "true": (
                    "It installs or builds something substantial, downloads a large "
                    "artifact, or clones a large repository."
                ),
                "false": (
                    "It installs one small pure-Python package, clones a tiny repo, "
                    "is a no-op because everything is cached, or is a quick check."
                ),
            },
        }
    }
    return state, qs


def deny_long_run(answers):
    a = (answers or {}).get("runs_over_two_minutes") or {}
    return (a.get("noul") or 0.0) >= 0.5


# --- R5: sudo ----------------------------------------------------------------

_PKG_INSTALLERS = {"apt", "apt-get", "dpkg", "snap", "aptitude"}
_PKG_SUBS = {"install", "reinstall", "-i", "--install"}

R5_SUGGESTION = (
    "`sudo` is passwordless here, which is capability, not authorisation. It is "
    "for installing a named system package someone asked for, and never for "
    "anything under $HOME -- root-owned files there break the next ordinary run. "
    "/etc, /usr, /opt, systemd units, the firewall and SSH config are out of scope."
)


_PKG_REFRESH = {"update"}


def _sudo_rest(toks, idx):
    """The command sudo runs: its own options, their values and any leading
    VAR=val assignments (`sudo DEBIAN_FRONTEND=noninteractive apt-get ...`)
    stripped, so the real program is rest[0]."""
    i = idx + 1
    while i < len(toks):
        t = toks[i]
        if t == "--":
            i += 1
            break
        if t.startswith("--"):
            # `--user root`: the value is the next word (`--user=root` is one)
            i += 2 if t in _SUDO_VALUE_LONG else 1
            continue
        if t.startswith("-"):
            # A short cluster (`-iu root`, `-uroot`): the first value-taking
            # letter takes the rest of the word, or the next word if none.
            i += 1
            for j, ch in enumerate(t[1:], 1):
                if ch in _SUDO_VALUE_SHORT:
                    if j == len(t) - 1:
                        i += 1
                    break
            continue
        if _ASSIGN_RE.match(t):
            i = _after_assignment(toks, i)
            continue
        break
    return [t for t in toks[i:] if not t.startswith("-") or t in _PKG_SUBS]


def _run_segments(ctx):
    """Every segment the shell will run, substitutions included. A hand-built
    ctx may carry only `segments`."""
    return ctx.get("all_segments") or ctx["segments"]


def _is_named_install(rest):
    prog = rest[0].rsplit("/", 1)[-1] if rest else ""
    return (prog in _PKG_INSTALLERS and len(rest) > 2 and rest[1] in _PKG_SUBS)


def _with_handed_segments(segments, depth=0, work=None):
    """`segments`, plus those of any code they hand to a shell: `bash -c
    'sudo rm -rf /etc/x'` runs sudo as surely as typing it does."""
    work = work or _ScanWork()
    out = list(segments)
    if depth >= _HANDED_CODE_DEPTH:
        return out
    for seg in segments:
        try:
            code = _handed_code(seg)
        except Exception:
            code = None
        if code and work.spend(code, (code, depth)):
            out.extend(_with_handed_segments(all_segments(strip_heredocs(code)), depth + 1, work))
    return out


def prefilter_sudo(ctx):
    if ctx["tool_name"] not in SHELL_TOOLS:
        return None
    # `sudo apt-get update && sudo apt-get install -y jq` is ONE named install:
    # the index refresh is part of it. Only allowed when the same command
    # carries the named install itself.
    has_named_install = False
    segments = _with_handed_segments(_run_segments(ctx))
    for seg in segments:
        prog0, args0 = program_of(seg)
        if prog0 == "sudo" and _is_named_install(_sudo_rest(["sudo"] + args0, 0)):
            has_named_install = True
    for seg in segments:
        # Command position only: a quoted argument or a search pattern that
        # merely contains the word is not an invocation.
        prog, args = program_of(seg)
        if prog != "sudo":
            continue
        rest = _sudo_rest(["sudo"] + args, 0)
        flags = args

        # any sudo touching a path under $HOME
        for t in flags:
            p = _expand(t)
            if p.startswith(HOME + "/") or p == HOME or t.startswith("~"):
                return Match(
                    "`sudo` on a path under $HOME (%s) leaves root-owned files behind" % t,
                    R5_SUGGESTION,
                )

        prog = rest[0].rsplit("/", 1)[-1] if rest else ""
        if _is_named_install(rest):
            continue  # named package install: allowed
        if (prog in _PKG_INSTALLERS and len(rest) == 2 and rest[1] in _PKG_REFRESH
                and has_named_install):
            continue  # index refresh in front of a named install: allowed
        return Match(
            "`sudo %s` is not a named system package install" % (" ".join(rest[:3]) or "<nothing>"),
            R5_SUGGESTION,
        )
    return None


# --- R6: GUI / browser on a headless box -------------------------------------

_GUI_PROGRAMS = {
    "xdg-open", "open", "sensible-browser", "gnome-open", "kde-open", "x-www-browser",
    "www-browser", "firefox", "google-chrome", "chrome", "chromium", "chromium-browser",
    "wslview", "explorer.exe", "eog", "xdg-mime", "nautilus", "gio",
}

R6_SUGGESTION = (
    "There is no desktop on this box: no GUI, no browser, no X server, $DISPLAY "
    "unset. Print the URL or path and let the user open it on their own machine. "
    "If the task genuinely needs a browser, use Playwright headless (Chromium only)."
)

# The same advice for a machine that is Windows AND headless -- a Server Core
# box, a build agent. It never mentions $DISPLAY or an X server, because
# neither exists there. R6 is off by default on every platform, so reaching
# this text at all means rules.json on this machine turned it on, which is
# somebody saying the box has no desktop.
R6_SUGGESTION_WINDOWS = (
    "This machine is configured as one that should not open a GUI or a browser "
    "(R6 is off by default; rules.json here turns it on). Print the URL or path "
    "and let the user open it themselves. If the task genuinely needs a browser, "
    "use Playwright headless."
)


def prefilter_gui(ctx, windows=None):
    if ctx["tool_name"] not in SHELL_TOOLS:
        return None
    win = is_windows(windows)
    for seg in ctx["segments"]:
        prog, args = program_of(seg)
        if prog in _GUI_PROGRAMS:
            if prog == "gio" and args[:1] != ["open"]:
                continue
            if prog in ("chromium", "google-chrome", "chrome") and any(
                a.startswith("--headless") for a in args
            ):
                continue
            if win:
                return Match("`%s` tries to open a GUI or browser" % prog,
                             R6_SUGGESTION_WINDOWS)
            return Match("`%s` tries to open a GUI or browser on a headless server" % prog, R6_SUGGESTION)
    return None


# --- R7: destructive / outward-facing ----------------------------------------

# One sentence. The advice rides on every hit and the reader has seen it
# before; the detail line above it is the part that carries information
# (Jonathan, 2026-09-22).
R7_SUGGESTION = (
    "Hard to reverse: ask first unless the human already said to do this."
)


# Clients that run SQL given on the command line. A DROP in any other
# program's arguments is text (an echo, a commit message), not a statement.
_SQL_CLIENTS = {
    "psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "duckdb", "clickhouse-client",
    "cockroach", "mongosh", "mongo",
}
_SQL_DROP_RE = re.compile(r"\bDROP\s+(DATABASE|SCHEMA|TABLE)\b", re.IGNORECASE)
# `dd of=` targets that are not a disk. `of=/dev/null` is an everyday
# throughput test and must stay silent.
_DD_HARMLESS = ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/fd/")
# A download piped straight into a shell with no script argument, so the
# shell runs whatever came down the wire. `curl page | bash norm.sh` hands the
# page to a local script as stdin and is not this.
#
# A redirection such as `2>&1` is not a separator, `|&` pipes stderr too, and
# a shell given `-s` reads its script from stdin whatever follows, so
# `curl https://get.rvm.io | bash -s stable` is this as well.
_PIPE_TO_SHELL_RE = re.compile(
    r"\b(curl|wget)\b(?:[<>]&|[^|;&\n])*\|&?\s*(?:(?:\S*/)?sudo\s+(?:-[A-Za-z]*[ugpCUrtDRTh]\s+\S+\s+|--(?:user|group)\s+\S+\s+|-\S+\s+)*)?(?:(?:\S*/)?env\s+)?(?:\S*/)?(?:ba|z|da|k)?sh\b"
    r"(?:(?:\s+-[^\s-]\S*)*\s*(?:--?(?:\s|$)|$|[;&|\n)])"
    r"|(?:\s+-[^\s-]\S*)*\s+-[A-Za-z]*s[A-Za-z]*(?:\s|$))"
)
# Quoted text is data (a commit message, an echo), never a pipeline. Blanked
# before the pipe-to-shell search so `git commit -m 'avoid curl x | bash; ...'`
# is not read as one (Codex P2, PR #17).
_QUOTED_RE = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")
# xargs options that take the NEXT token as their value, so that token is
# not the command xargs runs (`xargs -n 1 rm -rf`, Codex P2, PR #17).
# GNU's long forms take a separate value too (`xargs --max-procs 4 rm -rf`).
_XARGS_VALUE_OPTS = {
    "-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s",
    "--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-chars",
    "--process-slot-var",
}
# git's global options that take the next token as their value.
_GIT_VALUE_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace",
                   "--exec-path", "--config-env", "--super-prefix"}
# git push options that take the next token as their value. A leading `+` on
# that value is not a refspec.
_PUSH_VALUE_OPTS = {"--push-option", "--repo", "--receive-pack", "--exec"}
# redis-cli options that take the next token as a value. The first token
# left after them is the Redis command; a later FLUSHALL is a key or a
# pattern (`redis-cli GET FLUSHALL`, Codex P2, PR #17).
_REDIS_VALUE_OPTS = {
    "-h", "-p", "-s", "-a", "-u", "-n", "-r", "-i", "-d", "--user", "--pass",
    "--sni", "--cacert", "--cacertdir", "--cert", "--key", "--tls-ciphers",
    "--tls-ciphersuites", "--pattern", "--count", "--quoted-pattern", "--eval",
}


_ESCAPED_RE = re.compile(r"\\.")


def _shell_code_only(command):
    """`command` with everything bash would not run as syntax blanked out:
    heredoc bodies, a trailing comment, backslash-escaped characters and
    quoted strings. `true # curl x | bash` and `echo curl x \\| bash` hold
    no pipeline (Codex P2, PR #17 round 2)."""
    from .scope import strip_shell_comment
    text = strip_shell_comment(strip_heredocs(command))
    text = "\n".join(strip_shell_comment(line) for line in text.split("\n"))
    return _QUOTED_RE.sub('""', _ESCAPED_RE.sub("_", text))


def _first_positional(args, value_opts):
    """Index of the first argument that is neither an option nor an option's
    value, or None."""
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            i += 2 if a in value_opts else 1
            continue
        return i
    return None


# sudo options that take a value. Skipping only the option word read the
# value as the program, so `sudo -u root rm -rf /` passed R7 as `root -rf /`.
_SUDO_VALUE_SHORT = set("ugpCUrtDRTh")
_SUDO_VALUE_LONG = {
    "--user", "--group", "--prompt", "--close-from", "--other-user", "--role",
    "--type", "--chdir", "--chroot", "--command-timeout", "--host",
}


# Sudo chains read in full, word for word, before `_unsudo` stops re-reading
# what each one runs. No real command comes near this; `sudo env sudo env ...`
# re-read without limit is quadratic and runs past the hook's 5 s timeout.
_SUDO_REREADS = 16


def _unsudo(prog, args):
    """R7 judges what runs, not how it was elevated (R5 owns `sudo`)."""
    toks, start, rereads = args, 0, 0
    while prog == "sudo" and start < len(toks):
        at = start  # an index: `sudo sudo sudo ...` must stay linear
        while at < len(toks) and toks[at].startswith("-"):
            opt = toks[at]
            at += 1
            if opt == "--":
                break
            if opt.startswith("--"):
                if opt in _SUDO_VALUE_LONG and at < len(toks):
                    at += 1
                continue
            # A short cluster (`-iu root`, `-uroot`): the first value-taking
            # letter takes the rest of the word, or the next word if none.
            for j, ch in enumerate(opt[1:], 1):
                if ch in _SUDO_VALUE_SHORT:
                    if j == len(opt) - 1 and at < len(toks):
                        at += 1
                    break
        if at >= len(toks):
            break
        base = toks[at].rsplit("/", 1)[-1]
        if base == "sudo" or rereads >= _SUDO_REREADS:
            prog, start = base, at + 1
            continue
        rereads += 1
        prog, toks = program_of(" ".join(toks[at:]))
        start = 0
    return prog, toks[start:]


def _is_recursive_rm(args):
    return any(a.startswith("-") and not a.startswith("--") and "r" in a.lower()
               or a == "--recursive" for a in args)


def _whole_tree_target(a):
    """The rm/chmod target that takes a whole tree with it, or None. `/` is
    compared before stripping slashes: stripped, it is the empty string and
    matched nothing, so `rm -rf /` passed R7 silently while `rm -rf ~` warned
    (found by the tamper-cases corpus, 2026-09-24)."""
    raw = a
    if raw and not raw.strip("/"):  # `//` strips to nothing, and so does `/`
        return raw
    if raw in ("/", "/*", "~", "~/", "$HOME", "${HOME}", "*", ".", "./", "..", "../", "./*"):
        return raw
    p = _expand(raw)
    if p.endswith("/*"):
        p = p[:-2]  # `rm -rf ~/*` empties the home directory just the same
    if p.rstrip("/") == HOME:
        return raw
    return None


def _force_push(args):
    """True when `git push ARGS` forces an update: -f alone or in a cluster
    (`-uf`), or a `+` refspec. --force-with-lease is the safe form, so it stays
    quiet. The value of a value-taking option is neither."""
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if a == "--":
            return any(r.startswith("+") and len(r) > 1 for r in args[i:])
        if a == "--force":
            return True
        if a in _PUSH_VALUE_OPTS:
            i += 1
            continue
        if a.startswith("--"):
            continue
        if a.startswith("-"):
            # -o takes the rest of the word as its value (`-oci.skip`).
            if "f" in a[1:].split("o", 1)[0]:
                return True
            if a.endswith("o"):
                i += 1
            continue
        if a.startswith("+") and len(a) > 1:
            return True
    return False


def prefilter_destructive(ctx):
    if ctx["tool_name"] not in SHELL_TOOLS:
        return None
    for seg in _run_segments(ctx):
        prog, args = _unsudo(*program_of(seg))
        if prog == "git" and args:
            # The subcommand comes after git's global options: `git -C repo
            # push --force` is still a force-push.
            i = _first_positional(args, _GIT_VALUE_OPTS)
            args = args[i:] if i is not None else []
            if not args:
                continue
            sub = args[0]
            if sub == "push" and _force_push(args[1:]):
                return Match("`git push --force` overwrites published history", R7_SUGGESTION)
            if sub == "reset" and "--hard" in args:
                return Match("`git reset --hard` discards uncommitted work irreversibly", R7_SUGGESTION)
            if sub == "branch" and any(a == "-D" or a == "--delete" and "--force" in args for a in args):
                return Match("`git branch -D` force-deletes a branch", R7_SUGGESTION)
            if sub == "clean" and any("f" in a and a.startswith("-") for a in args):
                return Match("`git clean -f` deletes untracked files irreversibly", R7_SUGGESTION)
            if sub in ("filter-branch", "filter-repo"):
                return Match("`git %s` rewrites history" % sub, R7_SUGGESTION)
        if prog == "rm":
            if not _is_recursive_rm(args):
                continue
            for a in args:
                if a.startswith("-"):
                    continue
                if _whole_tree_target(a):
                    return Match("`rm -rf %s` would delete a whole tree" % a, R7_SUGGESTION)
                p = _expand(a).rstrip("/")
                if p.startswith(HOME + "/") and os.path.exists(os.path.join(p, ".git")):
                    return Match("`rm -rf %s` would delete a whole git repository" % a, R7_SUGGESTION)
        if prog == "find":
            for i, a in enumerate(args):
                if a in ("-exec", "-execdir") and i + 1 < len(args) \
                        and args[i + 1].rsplit("/", 1)[-1] == "rm" and _is_recursive_rm(args[i + 2:]):
                    return Match("`find ... %s rm -r` recursively deletes every match" % a, R7_SUGGESTION)
        if prog == "xargs":
            i = _first_positional(args, _XARGS_VALUE_OPTS)
            rest = args[i:] if i is not None else []
            if rest and rest[0].rsplit("/", 1)[-1] == "rm" and _is_recursive_rm(rest[1:]):
                return Match("`xargs rm -r` recursively deletes whatever is piped in", R7_SUGGESTION)
        if prog in _SQL_CLIENTS:
            m = _SQL_DROP_RE.search(seg)
            if m:
                return Match("`DROP %s` deletes data irreversibly" % m.group(1).upper(), R7_SUGGESTION)
        i = _first_positional(args, _REDIS_VALUE_OPTS) if prog == "redis-cli" else None
        if i is not None and args[i].upper() in ("FLUSHALL", "FLUSHDB"):
            return Match("`redis-cli FLUSHALL`/`FLUSHDB` wipes the database", R7_SUGGESTION)
        if prog in ("terraform", "tofu"):
            # The subcommand is the first word after the global options
            # (`-chdir=dir`). `-destroy` destroys only on `apply`: on `plan`
            # it just writes a destroy plan, and `workspace new destroy`
            # names a workspace (Codex P2, PR #17 round 3).
            i = _first_positional(args, ())
            sub = args[i] if i is not None else ""
            if sub == "destroy" or sub == "apply" and "-destroy" in args[i + 1:]:
                return Match("`%s destroy` tears down real infrastructure" % prog, R7_SUGGESTION)
        if prog == "dd":
            for a in args:
                if a.startswith("of=/dev/") and not a[3:].startswith(_DD_HARMLESS):
                    return Match("`dd %s` overwrites a device" % a, R7_SUGGESTION)
        # Only -R is recursive here: `chmod -r` is the symbolic mode "remove
        # read" (Codex P2, PR #17 round 4).
        if prog in ("chmod", "chown") and any(
                a == "--recursive" or a.startswith("-") and not a.startswith("--") and "R" in a
                for a in args):
            for a in args[1:]:
                if not a.startswith("-") and _whole_tree_target(a) in ("/", "/*", "~", "~/", "$HOME", "${HOME}") \
                        or not a.startswith("-") and _expand(a).rstrip("/") == HOME:
                    return Match("`%s -R` on `%s` rewrites permissions on a whole tree" % (prog, a),
                                 R7_SUGGESTION)
    m = _PIPE_TO_SHELL_RE.search(_shell_code_only(ctx.get("command") or ""))
    if m:
        return Match("`%s ... | sh` runs a downloaded script unread" % m.group(1), R7_SUGGESTION)
    return None


# --- R7-root-delete: the one destructive shape that is denied ------------------
#
# Self-contained on purpose: its own unwrapping, so the rule reads the same on
# any release and does not move when the shared shell helpers do.

R7_ROOT_SUGGESTION = (
    "A recursive delete of / or of the home directory is never a step in a task. "
    "Name the exact directory you mean, or ask the human."
)

_RD_SHELLS = {"sh", "bash", "dash", "zsh", "ksh"}
_RD_PLAIN_WRAPPERS = {"nice", "time", "command", "exec", "builtin", "stdbuf", "nohup", "ionice", "doas"}
# Options that take the NEXT word as their value, per wrapper.
_RD_VALUE_OPTS = {
    "env": {"-u", "--unset", "-C", "--chdir"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "--class", "-n", "--classdata", "-p", "--pid"},
    "stdbuf": {"-i", "-o", "-e"},
    "doas": {"-u", "-C"},
    "sudo": {"-u", "--user", "-g", "--group", "-p", "--prompt", "-C", "--close-from", "-D",
             "--chdir", "-h", "--host", "-r", "--role", "-t", "--type", "-T", "--command-timeout",
             "-U", "--other-user", "-R", "--chroot"},
}
_RD_SUDO_SHORT_VALUE = set("ugpCDhrtTUR")
# Compound-command words that put a command after them: `then rm -rf /`.
_RD_KEYWORDS = {"if", "then", "elif", "else", "do", "while", "until"}
# Shell options that take the next word as their value: `bash -o pipefail -c`.
_RD_SHELL_VALUE_OPTS = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}
_RD_SOURCE = {"source", "."}
_HANDED_CODE_DEPTH = 8


def _rd_unquote(tok):
    """Bash quote removal for one word: `\\rm` is `rm`, `\\/` is `/`, `"/"*` is
    `/*`. An escaped leading tilde is a file literally named `~`, so it is
    kept escaped and never matches the home directory."""
    out, i, n = [], 0, len(tok)
    if n > 1 and tok[0] in "'\"" and tok[1] == "~":
        # A quoted leading tilde is literal too: `rm -rf "~"` removes a file
        # named ~, and bash never expands it to the home directory.
        out.append("\\~")
        i = 2
    while i < n:
        ch = tok[i]
        if ch == "\\" and i + 1 < n:
            if tok[i + 1] == "~" and i == 0:
                out.append("\\~")
            else:
                out.append(tok[i + 1])
            i += 2
            continue
        if ch not in "'\"":
            out.append(ch)
        i += 1
    return "".join(out)


_ANSI_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b",
                 "E": "\x1b", "f": "\f", "v": "\v", "'": "'", '"': '"', "\\": "\\", "?": "?"}
_ANSI_ESCAPE_RE = re.compile(r"\\(.)", re.DOTALL)
_WORD_END = frozenset(" \t\n;&|()<>")


def _rd_shell_word(text):
    """The first shell word of `text` as the program receives it, or None when
    a quote never closes. Adjacent pieces are one word: `'a'\\''b'` is `a'b`.
    A `$(...)` in double quotes keeps its own quotes, since it is still code."""
    out = []
    i = 0
    n = len(text)
    in_double = False
    while i < n:
        ch = text[i]
        if not in_double and ch in _WORD_END:
            break
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if not in_double or nxt in '"\\$`':
                out.append(nxt)
            elif nxt != "\n":
                out.append(ch + nxt)
            i += 2
        elif ch == '"':
            in_double = not in_double
            i += 1
        elif not in_double and ch == "'":
            end = text.find("'", i + 1)
            if end == -1:
                return None
            out.append(text[i + 1:end])
            i = end + 1
        elif not in_double and text.startswith("$'", i):
            end = _ansi_string_end(text, i)
            body = text[i + 2:end - 1]
            out.append(_ANSI_ESCAPE_RE.sub(lambda m: _ANSI_ESCAPES.get(m.group(1), m.group(0)), body))
            i = end
        elif text.startswith(("$(", "${", "`"), i):
            end = _shell_nesting(text, i, one_construct=True)[1]
            out.append(text[i:end])
            i = end
        else:
            out.append(ch)
            i += 1
    return None if in_double else "".join(out)


def _rd_shell_script(args, seg=None):
    """The script of `sh -c SCRIPT`, also when -c sits in a short-option
    cluster (`bash -lc`, `sh -xc`). Like bash, options are read up to the
    first non-option word, and a cluster ending in o/O takes the next word as
    its value (`-euo pipefail`, `-co pipefail SCRIPT`). None when the shell
    runs no -c script. `seg` is the segment `args` came from: `words` has
    already lost the quoting and the newlines, and the words after a quoted
    script are $0 and $1 rather than code (`bash -c 'cat .env' _ a`)."""
    has_c, i = False, 0
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1  # `bash -c -- 'script'`
            break
        if a in _RD_SHELL_VALUE_OPTS:
            i += 2
            continue
        if a.startswith("-") and not a.startswith("--") and len(a) > 1:
            has_c = has_c or "c" in a[1:]
            i += 2 if a[-1] in "oO" else 1
            continue
        if a.startswith("--") or (a.startswith("+") and len(a) > 1):
            i += 1
            continue
        break
    if not has_c:
        return None
    rest = args[i:]
    if seg and rest:
        starts = [m.start() for m in re.finditer(r"\S+", seg)]
        raw = seg[starts[-len(rest)]:]
        if set(raw.split(None, 1)[0]) & set("'\"\\"):
            script = _rd_shell_word(raw)
            if script is not None:
                return script
    return " ".join(rest).strip("'\"")


def _rd_command(toks, depth=0):
    """(program, args) behind assignments, wrappers and sudo, or the inner
    script's tokens for `sh -c`. Returns (None, []) when nothing runs."""
    at = 0  # an index: re-slicing per word is quadratic on `( ( ( ...`
    n = len(toks)
    while at < n:
        if at + 1 < n and toks[at + 1] == ")":
            at += 2  # a case pattern with a space before the paren: `x ) cmd`
            continue
        t = _rd_unquote(toks[at].lstrip("({!"))
        if not t or t in _RD_KEYWORDS or _FUNCTION_HEAD_RE.match(t):
            at += 1
            continue
        if t == "function":
            at += 2  # `function f {`
            continue
        redirect = _REDIRECT_OP_RE.match(t)
        if redirect:
            at += 2 if redirect.end() == len(t) else 1  # `> log rm -rf /`
            continue
        if t == "case":
            # `case WORD in PATTERN) cmd`: the command starts after the pattern
            at = _after_in(toks, at)
            continue
        if t.endswith(")") and "(" not in t:
            at += 1  # a case pattern: `x)`, `a|b)`
            continue
        if _ASSIGN_RE.match(t):
            at = _after_assignment(toks, at)
            continue
        base = t.rsplit("/", 1)[-1]
        if base in ("env", "timeout", "sudo") or base in _RD_PLAIN_WRAPPERS:
            at += 1
            value_opts = _RD_VALUE_OPTS.get(base, set())
            while at < n and toks[at].startswith("-") and toks[at] != "-":
                opt = toks[at]
                at += 1
                if opt == "--":
                    break
                if "=" in opt:
                    continue
                if opt in value_opts:
                    at += 1
                    continue
                if base == "sudo" and not opt.startswith("--"):
                    # a short cluster: `-iu root` takes the next word
                    for j, ch in enumerate(opt[1:], 1):
                        if ch in _RD_SUDO_SHORT_VALUE:
                            if j == len(opt) - 1:
                                at += 1
                            break
                if base == "nice" and opt[1:].lstrip("-").isdigit():
                    continue  # `nice -10 cmd`
            if base == "env":
                if at < n and toks[at] == "-":
                    at += 1
                while at < n and _ASSIGN_RE.match(toks[at]):
                    at = _after_assignment(toks, at)
            if base == "timeout" and at < n:
                at += 1  # the duration
            if at >= n:
                return None, []
            continue
        return base, toks[at + 1:]
    return None, []


def _rd_root_or_home(a):
    """True for an rm target that is the filesystem root or the home
    directory itself, or every child of either (`/*`, `~/*`)."""
    if a.endswith(")") and "(" not in a:
        a = a.rstrip(")")  # `(cd x && rm -rf /)`: the subshell's closing paren
    if a.endswith(";"):
        a = a.rstrip(";")  # `{ rm -rf /; }`
    if not a:
        return False
    if a.strip("/") == "" or a in ("/*", "~", "~/", "~/*", "$HOME", "${HOME}", "$HOME/*", "${HOME}/*"):
        return True
    p = _expand(a)
    if p.endswith("/*"):
        p = p[:-2]
    return p.rstrip("/") in ("", HOME)


def _handed_code(seg):
    """The script this one segment hands to a shell, or None: `eval ARGS`,
    `sh -c SCRIPT`, or a here-string into a shell."""
    prog, args = _rd_command(words(seg))
    if prog == "eval":
        return " ".join(_rd_unquote(a) for a in args)
    if prog in _RD_SHELLS or prog in _RD_SOURCE:
        script = _rd_shell_script(args, seg) if prog in _RD_SHELLS else None
        if script is None and _rd_reads_stdin(seg):
            script = _rd_herestring(seg)
        return script
    return None


def _stdin_scripts(text):
    """Scripts `text` feeds a shell on stdin: a heredoc whose opening line has a
    shell reading stdin, or echo/printf piped straight into one."""
    out = []
    pairs = split_segments_ops(strip_heredocs(text))
    for i, (seg, op) in enumerate(pairs):
        if op == "|" and i + 1 < len(pairs) and _rd_reads_stdin(pairs[i + 1][0]):
            printed = _rd_printed_text(seg)
            if printed:
                out.append(printed)
    for line, body in scope.heredoc_bodies(text):
        if any(_rd_reads_stdin(seg) for seg in split_segments(line)):
            out.append(body)
    return out


def _rd_hit(seg):
    # words(), except that a quoted word starting with ~ keeps its quotes:
    # `"~"` must reach _rd_unquote still quoted to stay a file literally
    # named ~. Every other word is read exactly as before.
    toks = [raw if len(raw) > 1 and raw[0] in "'\"" and raw[1] == "~" else word
            for raw, word in zip((seg or "").split(), words(seg))]
    prog, args = _rd_command(toks)
    if prog != "rm":
        return None
    args = [_rd_unquote(a) for a in args]
    # After `--` every word is a file name, `-r` included.
    end = args.index("--") if "--" in args else len(args)
    opts = [a for a in args[:end] if a.startswith("-")]
    operands = [a for a in args[:end] if not a.startswith("-")] + args[end + 1:]
    if not any(a == "--recursive" or not a.startswith("--") and "r" in a.lower() for a in opts):
        return None
    for a in operands:
        if _rd_root_or_home(a):
            return a
    return None


def _rd_reads_stdin(seg):
    """True when this segment's shell takes its script from stdin: no -c, and
    no script file named, or -s saying so. `source /dev/stdin` does the same."""
    prog, args = _rd_command(words(seg))
    if prog in _RD_SOURCE:
        return bool(args) and args[0] in ("/dev/stdin", "/dev/fd/0")
    if prog not in _RD_SHELLS or _rd_shell_script(args) is not None:
        return False
    i = 0
    while i < len(args):
        a = args[i]
        if _REDIRECT_RE.match(a):
            return True
        if a == "--":
            return i + 1 == len(args) or bool(_REDIRECT_RE.match(args[i + 1]))
        if a in _RD_SHELL_VALUE_OPTS:
            i += 2
            continue
        if a.startswith("-") and not a.startswith("--") and len(a) > 1:
            if "s" in a[1:]:
                return True
            i += 2 if a[-1] in "oO" else 1
            continue
        if a.startswith("--") or (a.startswith("+") and len(a) > 1):
            i += 1
            continue
        return False
    return True


def _rd_herestring(seg):
    """The word a `<<<` here-string feeds, quoting removed and a `$'...'`
    string's `\\n` turned into the newline it stands for, or None."""
    at = seg.find("<<<")
    if at < 0:
        return None
    rest = seg[at + 3:].lstrip()
    ansi = rest.startswith("$'")
    if ansi:
        rest = rest[1:]
    try:
        parts = shlex.split(rest)
    except ValueError:
        parts = [rest.strip("'\"")]
    if not parts:
        return None
    return parts[0].replace("\\n", "\n") if ansi else parts[0]


def _rd_printed_text(seg):
    """What an `echo` or `printf` segment writes, or None for any other
    program. Good enough to read a script piped into a shell."""
    prog, args = _rd_command(words(seg))
    if prog not in ("echo", "printf"):
        return None
    args = [_rd_unquote(a.replace("\\n", "\n")) for a in args]
    while prog == "echo" and args and args[0] in ("-n", "-e", "-ne", "-en"):
        args = args[1:]
    if prog == "printf" and args and "%" in args[0]:
        args = args[1:]  # the format, when the script is its argument
    return " ".join(args)


def _rd_scan(text, depth=0, work=None):
    """The root-or-home `rm` operand in `text` read as shell code, or None.
    Follows every way a shell gets handed more code: a substitution, `eval`,
    `sh -c`, and a script on stdin. Bounded, because each can nest in another."""
    if not text or depth > _HANDED_CODE_DEPTH:
        return None
    work = work or _ScanWork()
    if not work.spend(text, (text, depth)):
        return None
    code = strip_heredocs(text)
    for seg in split_segments(code):
        hit = _rd_hit(seg) or _rd_scan(_handed_code(seg), depth + 1, work)
        if hit:
            return hit
    # One level at a time: each piece is a separate part of `text`, so the work
    # stays linear in its length for each level of depth.
    for inner in [body for _offset, body in _outer_substitutions(code)] + _stdin_scripts(text):
        hit = _rd_scan(inner, depth + 1, work)
        if hit:
            return hit
    return None


def prefilter_root_delete(ctx):
    """`rm -r` of `/`, `/*`, `~`, `~/*` or `$HOME`, behind any wrapper, past
    sudo and its options, and anywhere a shell is handed the code: `sh -c`,
    `eval`, `$(...)`, backticks, a heredoc or here-string into a shell, or a
    pipe from echo/printf. A heredoc that goes anywhere else is data.
    R7-destructive only warns; this shape alone is denied (Jonathan,
    2026-10-02). A bare `*`, `.` or a named subdirectory stays
    R7-destructive's warning."""
    if ctx["tool_name"] not in SHELL_TOOLS:
        return None
    hit = _rd_scan(ctx.get("command") or "")
    if hit:
        # strict: neither an `[airlock-ok: ...]` stamp nor the loop
        # allowance (a repeat of a denied call passes) lets this through.
        return Match("`rm -r %s` would delete the whole filesystem or home directory" % hit,
                     R7_ROOT_SUGGESTION, extra={"strict": True})
    return None


# --- R9: committing a secret -------------------------------------------------

R9_SUGGESTION = (
    "Never commit secrets: .env files, private keys, credentials*, *.key, tokens. "
    "Add the path to .gitignore instead. If one is ALREADY tracked, flag it to the "
    "owner rather than quietly rewriting history to hide it."
)


_COMMIT_MESSAGE_RE = re.compile(
    r"""((?<!\S)-[a-zA-Z]*m|--message)(?:=|\s+)(?:"(?:[^"\\]|\\.)*"|'[^']*')""")


def prefilter_commit_secret(ctx):
    """Two belts, both pure code, both offline.

    1. A secret PATH being staged (`git add .env`, `git add server.key`).
    2. A credential-shaped LITERAL in the command text itself -- a key pasted
       into a commit message, a `printf '...' > .env && git add .env`, a token
       in a `git commit -m`. The patterns come from jev-commit's local belt
       (airlock/belt.py), high-precision tier only, with its placeholder
       suppression intact so `sk-your_key_here` and a line mentioning
       "example" do not fire.

    NOTHING here reads or sends a diff. jev-commit asks Jev about the staged
    hunks, which is inherent to the question it asks and is exactly what this
    rule does not do. The whole check is regexes over a string the hook was
    handed anyway, and only the first four characters of a match are ever
    recorded.
    """
    if ctx["tool_name"] not in SHELL_TOOLS:
        return None

    command = ctx.get("command") or ""
    git_write = False

    for seg in ctx["segments"]:
        prog, args = program_of(seg)
        if prog != "git" or not args:
            continue
        # Skip git's global options, or `git -C repo add .env` and
        # `git -c k=v commit -m <token>` read as no subcommand at all.
        i = _first_positional(args, _GIT_VALUE_OPTS)
        if i is None or args[i] not in ("add", "commit", "stage"):
            continue
        git_write = True
        if args[i] == "commit":
            # The message is text, not paths: `git commit -m "ignore .env"`
            # stages nothing named .env. Its words are dropped here; the
            # credential-literal belt below still reads the whole command.
            prog, args = program_of(_COMMIT_MESSAGE_RE.sub(r"\1 ''", seg))
            i = _first_positional(args, _GIT_VALUE_OPTS)
            if i is None:
                continue
        hit = _secret_path_in(args[i + 1:])
        if hit:
            return Match("`git %s` would stage a secret file (%s)" % (args[i], hit), R9_SUGGESTION)

    if not git_write:
        return None

    try:
        from . import belt
        credential = belt.first_blocking_hit(command)
    except Exception:
        credential = None
    if credential:
        return Match(
            "this command stages or commits something carrying a credential "
            "(%s, starts `%s`)" % (credential["kind"], credential["redacted"]),
            R9_SUGGESTION,
        )
    return None


# --- R10: general risk, the catch-all ----------------------------------------
#
# Ported in spirit from leepokai/jev-guard's ACTION_QUESTIONS (`src/guard.js`,
# MIT, see docs/CREDITS.md), which asks a `risk` score on
# EVERY non-read-only tool call. Asking on every call is exactly the cost this
# project exists to avoid, so the port keeps the question and drops the
# blanket: R10 runs only when
#
#   (a) no other rule matched this call at all, and
#   (b) a pure code pre-filter marks the command as potentially consequential.
#
# Every named rule above encodes a specific policy from the box's CLAUDE.md.
# R10 is the residue: the commands that are plainly capable of doing something
# outside this working tree but that no specific rule covers. It is `warn` and
# ONLY warn -- it never denies, whatever the answer, because a catch-all
# heuristic denying things it cannot name is how a guard becomes something
# people turn off.

# `user_requested` at or above this suppresses the warn entirely. The same
# one-directional rule as everywhere else: it can only ever soften.
R10_USER_REQUESTED_SOFTEN_AT = 0.75

# The risk levels, lowest first. The Score answer is a float index into this
# list, so the ORDER is load-bearing and adding a level changes what the
# threshold below means.
R10_RISK_LEVELS = [
    "none: read-only, or fully reversible inside the working directory given in "
    "`cwd` or a temporary directory. Nothing outside this checkout is changed. "
    "Writing a file under cwd, running a container that only reads, listing a "
    "database.",
    "low: changes something outside the working directory, but it is recreatable "
    "in minutes with no outside consequence: a cache, a scratch container, a "
    "local index, a file the tool that wrote it would rebuild.",
    "moderate: changes durable local state that a person would have to restore "
    "deliberately: stopping or disabling a service somebody relies on, removing "
    "a container or volume holding data, writing over a config file outside the "
    "checkout, deleting files matched by a wildcard high in the tree.",
    "high: reaches off this machine, or is not undone by deleting what it made: "
    "uploading data to another host, publishing a package or a release, writing "
    "to a shared or production database, force-changing state other people "
    "depend on.",
]

# Fires at `moderate` (index 2) and above. The threshold sits at the midpoint
# between `low` and `moderate` rather than on the level itself, because the
# score is a continuous index and an answer leaning between two levels should
# be read the way it leans.
R10_FIRE_AT = 1.5

# One sentence, same reason as R7_SUGGESTION.
R10_SUGGESTION = (
    "Reaches outside the working tree; not blocked. Check it was asked for."
)

_R10_PUBLISH = {
    ("npm", "publish"), ("pnpm", "publish"), ("yarn", "publish"),
    ("poetry", "publish"), ("uv", "publish"), ("cargo", "publish"),
    ("gem", "push"), ("twine", "upload"), ("docker", "push"),
    ("flyctl", "deploy"), ("fly", "deploy"), ("vercel", "deploy"),
    ("netlify", "deploy"),
}

_R10_DB_PROGRAMS = {"psql", "mysql", "mariadb", "sqlite3", "mongosh", "mongo",
                    "redis-cli", "clickhouse-client", "cqlsh", "sqlcmd", "duckdb"}
_R10_DB_WRITE_RE = re.compile(
    r"\b(insert\s+into|update\s+\w|delete\s+from|drop\s+(table|database|schema|index)"
    r"|truncate|alter\s+table|create\s+(table|database|schema)|grant\s|revoke\s"
    r"|flushall|flushdb|copy\s+\w+\s+from)\b"
    # the document-store and key-value shapes, which are not SQL
    r"|\.(drop|dropDatabase|deleteMany|deleteOne|insertMany|insertOne"
    r"|updateMany|updateOne|remove|renameCollection)\s*\(", re.IGNORECASE)

_R10_SERVICE_PROGRAMS = {"systemctl", "service", "launchctl", "initctl", "rc-service"}
_R10_SERVICE_VERBS = {"start", "stop", "restart", "reload", "enable", "disable",
                      "mask", "unmask", "daemon-reload", "kill", "load", "unload"}
_R10_DOCKER_VERBS = {"run", "rm", "rmi", "stop", "kill", "restart", "prune",
                     "system", "volume", "network", "swarm", "compose", "down", "up"}

# A grouped docker verb carries its real verb in the NEXT word: `docker system
# df`, `docker compose ps` and `docker volume ls` only read, and matching them
# on the group word alone is the shape that made R10 noisy.
_R10_DOCKER_GROUP_VERBS = {"system", "volume", "network", "swarm", "compose",
                           "image", "container", "builder", "context", "node",
                           "service", "stack"}
# Verbs that only read, at the top level or after a group word.
_R10_DOCKER_READ_VERBS = {"ps", "logs", "inspect", "images", "stats", "top",
                          "port", "version", "info", "diff", "history",
                          "events", "search", "ls", "config", "df"}

_R10_MASS_PROGRAMS = {"rm", "mv", "cp", "chmod", "chown", "chgrp", "truncate", "shred"}

# Directories a write is uninteresting in: anything temporary, plus the caches
# and stores every tool on this box writes to as a matter of course.
_R10_TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/", "/proc/", "/sys/")
_R10_BORING_SUFFIXES = ("/.cache", "/.npm", "/.pnpm-store", "/.cargo", "/.local/state",
                        "/.venv", "/node_modules")

# scp/rsync's remote form: [user@]host:path, where the part before the colon
# carries no slash (so a local `./dir:name` and a `https://...` URL are not
# mistaken for a host).
_R10_REMOTE_RE = re.compile(r"^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9.-]+:")
_R10_LOCALHOST = ("localhost", "127.0.0.1", "::1", "0.0.0.0")


def _r10_is_temp(path):
    if not path:
        return True
    if path.startswith(_R10_TEMP_PREFIXES) or path in ("/tmp", "/var/tmp"):
        return True
    return False


def _r10_outside_cwd(path, cwd):
    """True when `path` is an absolute location that is neither inside the
    session's cwd nor somewhere uninteresting. A relative path is always
    treated as inside the cwd -- that is what a relative path means."""
    if not path or path.startswith("-"):
        return False
    p = _expand(path)
    if not p.startswith("/"):
        return False
    if _r10_is_temp(p):
        return False
    for boring in _R10_BORING_SUFFIXES:
        if boring + "/" in p or p.endswith(boring):
            return False
    if cwd and (p == cwd or p.startswith(cwd.rstrip("/") + "/")):
        return False
    return True


def _r10_redirect_targets(segment):
    """Absolute paths a segment redirects stdout/stderr into. Deliberately
    crude: a false positive here only costs one warn-only question."""
    out = []
    for m in re.finditer(r"(?<![0-9<>])>>?\s*([^\s;|&<>]+)", segment or ""):
        out.append(m.group(1).strip("'\""))
    return out


def _r10_is_remote_target(token):
    """`host:path` or `user@host:path`, the scp/rsync remote form, excluding
    anything pointing back at this machine."""
    if not token or token.startswith("-"):
        return False
    if "://" in token:
        return False
    head = token.split(":", 1)[0]
    if "/" in head or not _R10_REMOTE_RE.match(token):
        return False
    host = head.rsplit("@", 1)[-1]
    return host not in _R10_LOCALHOST


def _r10_url_is_remote(token):
    if not token.startswith(("http://", "https://", "ftp://", "ftps://", "sftp://")):
        return False
    rest = token.split("://", 1)[1]
    host = rest.split("/", 1)[0].split("@")[-1].split(":")[0]
    return host not in _R10_LOCALHOST


def _r10_glob_high_in_tree(token):
    """A wildcard at a shallow level of the tree: `~/*`, `/etc/*`, `$HOME/*/x`,
    `/*`. A glob three or more directories deep is ordinary work."""
    if "*" not in token and "?" not in token:
        return False
    p = _expand(token)
    if not p.startswith("/"):
        return False
    head = p.split("*", 1)[0].split("?", 1)[0]
    depth = len([part for part in head.strip("/").split("/") if part])
    if head.endswith("/"):
        pass
    else:
        depth = max(depth - 1, 0)
    if _r10_is_temp(p):
        return False
    return depth <= 2


def _r10_is_user_level_service(prog, args):
    """True for service control that can only touch the caller's OWN units.

    `systemctl --user restart x` stops one unit belonging to the person
    already running this session: it cannot take the machine down and cannot
    touch another user's services, so it is not what this shape is for.
    System-level `systemctl` still matches, and a `sudo systemctl ...` is
    claimed by R5-sudo before the fallback tier is ever consulted.
    """
    if prog != "systemctl":
        return False
    return any(a == "--user" or a.startswith("--user=") for a in args)


def _r10_docker_is_read_only(positional):
    """True when a docker/podman/compose invocation only reads.

    `docker ps`, `docker logs`, `docker inspect`, `docker images`, and the
    read half of the grouped verbs (`docker system df`, `docker compose ps`,
    `docker volume ls`) change nothing. `docker stop`, `docker rm`,
    `docker restart` and `docker compose down` still match.
    """
    if not positional:
        return False
    sub = positional[0]
    if sub in _R10_DOCKER_GROUP_VERBS:
        nxt = positional[1] if len(positional) > 1 else ""
        return nxt in _R10_DOCKER_READ_VERBS
    return sub in _R10_DOCKER_READ_VERBS


def prefilter_general_risk(ctx):
    """Pure code, no I/O. Marks a Bash call as potentially consequential.

    Six shapes, each one thing a command can do that reaches beyond the
    working tree: a write outside it, an upload off the machine, a package
    publish, a database write, service/container control, and a mass file
    operation globbed high in the tree. Anything else returns None and R10
    costs nothing at all -- not a Jev call, not a log row.
    """
    if ctx["tool_name"] not in SHELL_TOOLS:
        return None
    cwd = (ctx.get("cwd") or "").rstrip("/")

    for seg in ctx["segments"]:
        prog, args = program_of(seg)
        if not prog:
            continue
        positional = [a for a in args if not a.startswith("-")]
        # The subcommand is the first non-flag argument: `systemctl --user
        # restart x` is a restart, and reading args[0] would call it "--user".
        sub = positional[0] if positional else ""

        # 1. a write landing outside the cwd and outside temp
        for target in _r10_redirect_targets(seg):
            if _r10_outside_cwd(target, cwd):
                return Match("writes to `%s`, outside this working tree" % target,
                             R10_SUGGESTION, ask=True,
                             extra={"kind": "write_outside_cwd", "segment": seg[:400]})
        if prog in ("cp", "mv", "install", "rsync", "tee", "ln") and positional:
            target = positional[-1]
            if _r10_outside_cwd(target, cwd):
                return Match("`%s` writes to `%s`, outside this working tree" % (prog, target),
                             R10_SUGGESTION, ask=True,
                             extra={"kind": "write_outside_cwd", "segment": seg[:400]})
        if prog == "dd":
            for a in args:
                if a.startswith("of=") and _r10_outside_cwd(a[3:], cwd):
                    return Match("`dd of=%s` writes outside this working tree" % a[3:],
                                 R10_SUGGESTION, ask=True,
                                 extra={"kind": "write_outside_cwd", "segment": seg[:400]})

        # 2. an upload leaving the machine
        if prog in ("scp", "rsync", "sftp"):
            # Only the DESTINATION counts. `scp remote:/x .` is a download and
            # nothing leaves this machine.
            candidates = positional[-1:] if prog in ("scp", "rsync") else positional
            for a in candidates:
                if _r10_is_remote_target(a):
                    return Match("`%s` copies to the remote host `%s`" % (prog, a.split(":", 1)[0]),
                                 R10_SUGGESTION, ask=True,
                                 extra={"kind": "network_upload", "segment": seg[:400]})
        if prog == "curl":
            uploading = any(
                a in ("-T", "--upload-file", "-F", "--form", "--data-binary", "--data-raw", "-d")
                or a.startswith(("--upload-file=", "--form=", "--data-binary=", "--data-raw="))
                for a in args
            ) or any(a in ("-X", "--request") for a in args)
            if uploading:
                for a in positional:
                    if _r10_url_is_remote(a):
                        return Match("`curl` sends a body to `%s`" % a[:120],
                                     R10_SUGGESTION, ask=True,
                                     extra={"kind": "network_upload", "segment": seg[:400]})

        # 3. a package or release publish
        if (prog, sub) in _R10_PUBLISH or (prog == "gh" and args[:2] == ["release", "create"]):
            return Match("`%s %s` publishes outward, and a publish is not undone by deleting it"
                         % (prog, sub), R10_SUGGESTION, ask=True,
                         extra={"kind": "publish", "segment": seg[:400]})

        # 4. a database CLI carrying a write verb
        if prog in _R10_DB_PROGRAMS and _R10_DB_WRITE_RE.search(seg):
            return Match("`%s` is being given a statement that writes" % prog,
                         R10_SUGGESTION, ask=True,
                         extra={"kind": "database_write", "segment": seg[:400]})

        # 5. service or container control
        if (prog in _R10_SERVICE_PROGRAMS and sub in _R10_SERVICE_VERBS
                and not _r10_is_user_level_service(prog, args)):
            return Match("`%s %s` changes what is running on this machine" % (prog, sub),
                         R10_SUGGESTION, ask=True,
                         extra={"kind": "service_control", "segment": seg[:400]})
        if (prog in ("docker", "podman", "docker-compose", "nerdctl")
                and sub in _R10_DOCKER_VERBS
                and not _r10_docker_is_read_only(positional)):
            return Match("`%s %s` changes container or image state" % (prog, sub),
                         R10_SUGGESTION, ask=True,
                         extra={"kind": "service_control", "segment": seg[:400]})

        # 6. a mass file operation globbed high in the tree
        if prog in _R10_MASS_PROGRAMS:
            for a in positional:
                if _r10_glob_high_in_tree(a):
                    return Match("`%s %s` matches a wildcard high in the tree" % (prog, a),
                                 R10_SUGGESTION, ask=True,
                                 extra={"kind": "mass_file_op", "segment": seg[:400]})
        if prog == "find" and ("-delete" in args or "-exec" in args):
            for a in positional:
                if _r10_glob_high_in_tree(a) or (_r10_outside_cwd(a, cwd) and a.rstrip("/").count("/") <= 2):
                    return Match("`find %s` deletes or executes across a broad tree" % a,
                                 R10_SUGGESTION, ask=True,
                                 extra={"kind": "mass_file_op", "segment": seg[:400]})
    return None


_R10_KIND_LABEL = {
    "write_outside_cwd": "a write landing outside the session's working directory",
    "network_upload": "data being sent to another machine",
    "publish": "publishing a package or a release",
    "database_write": "a database command carrying a write statement",
    "service_control": "starting, stopping or removing a service or container",
    "mass_file_op": "a file operation matched by a wildcard high in the tree",
}


def questions_general_risk(ctx, match):
    """One Score for risk with concrete levels, and the `user_requested` noul.

    The risk levels are deliberately about REVERSIBILITY and BLAST RADIUS, not
    about how alarming the command looks -- a `docker rm` of a scratch
    container and a `docker rm` of the only copy of a database are the same
    words and very different answers, and only the surrounding state tells
    them apart.

    `user_requested` is the same question used to soften a deny elsewhere
    (airlock/questions.py), for the same reason and with the same wording: a
    thing the person running the session asked for is not something to warn
    them about. Like everywhere else it can only ever soften.
    """
    from . import questions as questions_mod
    from . import redact

    # The user's own recent words, already redacted and truncated by
    # airlock/context.py, which never reads a tool-result row. Without them
    # the question has nothing to judge, so it is asked only when there is
    # something to judge it against.
    recent = []
    try:
        from . import context
        recent = context.user_context(
            {"transcript_path": ctx.get("transcript_path") or ""}).get("recent_user_prompts") or []
    except Exception:
        recent = []

    state = {
        "command": redact.redact_and_truncate_command(ctx.get("command") or "")[:2000],
        "segment": redact.redact(match.extra.get("segment", ""))[:600],
        "description": redact.redact(ctx.get("description") or "")[:400],
        "cwd": ctx.get("cwd") or "",
        "prefilter_kind": _R10_KIND_LABEL.get(match.extra.get("kind"), "unclassified"),
        "recent_user_prompts": list(recent),
    }
    qs = {
        "risk": {
            "type": "score",
            "instructions": {
                "question": (
                    "Score how consequential this shell command is if it runs "
                    "exactly as written, on a single-user Linux server used for "
                    "development and agent work."
                ),
                "focus": (
                    "Judge reversibility and blast radius, not how alarming the "
                    "words look. A command that only touches files inside the "
                    "working directory given in `cwd`, or a temporary directory, "
                    "is low however dramatic it reads. A command that reaches "
                    "another machine, another user's data, a production service, "
                    "or a published artefact is high however ordinary it reads."
                ),
            },
            # An ordered list, lowest first: the API returns `score` as a
            # float INDEX into these levels (0 = the first, 3 = the last),
            # with a `legend` echoing them back. Measured against jev-1.13.0,
            # 2026-09-19 -- a dict here is rejected with HTTP 422.
            "criteria": R10_RISK_LEVELS,
        },
    }
    if recent:
        qs.update(questions_mod.user_requested_question())
    return state, qs


def warn_general_risk(answers):
    """R10 fires only at `moderate` or above, and only when the person running
    the session has not already asked for this.

    The risk answer is a Score: a float index into R10_RISK_LEVELS, so
    `moderate` is 2.0 and the threshold sits at 1.5. A missing or unparseable
    answer never fires.

    `user_requested` can only ever soften: a high `user_requested` suppresses
    the warn, and a low one never creates one. The question's own wording says
    that text arriving from a tool result does not count, and
    airlock/context.py never reads a tool-result row in the first place.
    """
    a = (answers or {}).get("risk") or {}
    try:
        level = float(a.get("score"))
    except (TypeError, ValueError):
        return False
    if level < R10_FIRE_AT:
        return False
    # No `user_requested` answer at all (no transcript, no recent prompts)
    # means no softening. It is never the other way round.
    try:
        requested = float(((answers or {}).get("user_requested") or {}).get("noul") or 0.0)
    except (TypeError, ValueError):
        requested = 0.0
    return requested < R10_USER_REQUESTED_SOFTEN_AT


def general_risk_suppression(answers):
    """Why R10 stayed silent on a call whose risk answer would otherwise have
    fired, or None.

    This is for the LOG ROW only -- the verdict itself is warn_general_risk,
    and this must never change it. A row carrying `suppressed:
    "user_requested"` is the one case worth telling apart from "Jev scored it
    low": the warn was earned and then withheld because the person running the
    session had already asked for this.
    """
    a = (answers or {}).get("risk") or {}
    try:
        level = float(a.get("score"))
    except (TypeError, ValueError):
        return None
    if level < R10_FIRE_AT:
        return None
    try:
        requested = float(((answers or {}).get("user_requested") or {}).get("noul") or 0.0)
    except (TypeError, ValueError):
        return None
    if requested >= R10_USER_REQUESTED_SOFTEN_AT:
        return "user_requested"
    return None


# --- R11: a Playwright MCP call is pointed at the kit's `browse` tool ---------

# The kit ships a Jev-decided `browse` MCP tool (browse/server.py, over the
# jev-ultrafast clone browser/install.sh pins). Same goals, same browser, only
# the decision-maker changes, and the Claude spend per run falls from 0.1868
# USD to 0.0008 USD (README, "Jev as the decision-maker"). An agent that
# reaches for Playwright MCP is told to use `browse` instead.
#
# The whole rule is a tool-name match. There is no Jev question behind it: an
# MCP browser call made from a Claude session is browsing by definition, so
# there is nothing to judge. Shell commands are never looked at. A Playwright
# script is fixed code with no model choosing its steps, so there is nothing
# in one for Jev to decide, and this rule has no opinion about them.
#
# It is a cost steer, not a security control, and it removes nothing: the
# Playwright MCP servers stay registered.

R11_SUGGESTION = (
    "Plain browsing goes through the kit's `browse` MCP tool, not Playwright "
    "MCP. Jev chooses each step, so it is faster and the Claude bill for the "
    "decision loop is close to zero.\n"
    '  browse(goal="open https://example.com and report the main heading", '
    'extract="h1")\n'
    "Optional inputs: start_url, extract (a CSS selector whose text comes "
    "back too), screenshot (true writes a PNG and returns its path).\n"
    "No `browse` tool in this session? Run browse/install.sh in the jev-kit "
    "checkout and add the block it prints to ~/.claude.json.\n"
    "Write the goal as the steps you would take, not as the outcome you want: "
    '"open <url>, click X, then click Y, scroll if the link is not in view". '
    "Jev picks one action at a time out of what it can see, so a goal spelled "
    "out that way is one it can follow and a vague one is not.\n"
    "Cannot spell the route out (an open-ended task: find a fact, follow "
    "whatever leads there)? Add plan=true. A warm Claude planner, Sonnet at "
    "low effort by default or plan_model=\"haiku\", names each step and Jev "
    "executes it. It is slower and billed to the user's claude login, so plain "
    "`browse` stays the choice for spelled-out steps.\n"
    "File uploads, scripted code (browser_run_code_unsafe, browser_evaluate), "
    "and signed-in-profile multi-step work go straight to Playwright: those "
    "calls are never blocked, and the first one opens Playwright for the rest "
    "of the session.\n"
    "If `browse` comes back `blocked`, or the call errors, Playwright MCP is "
    "yours for the rest of this session as well -- this rule warns instead "
    "of blocking, automatically, no stamp needed.\n"
    "A stamp does not lift this rule and repeating the call does not either. "
    "Only the user turns the rule off, with "
    '{"R11-browse-via-jev": "off"} in ~/.config/airlock/rules.json.'
)

# Plain driving or reading of a page: the calls `browse` can do, and the only
# ones this rule redirects (and only while nothing has opened the session).
_PW_MCP_BROWSING = frozenset((
    "browser_navigate", "browser_navigate_back", "browser_click",
    "browser_type", "browser_fill_form", "browser_snapshot", "browser_find",
))

# Playwright tools `browse` genuinely cannot express. Never blocked, never
# warned, and the first one in a session opens Playwright for the rest of it
# (the match carries `open_session`; airlock/enforce.py records it through
# airlock/browse_state.py).
_PW_MCP_ALWAYS_ALLOWED = frozenset((
    "browser_file_upload", "browser_run_code_unsafe", "browser_evaluate",
    "browser_handle_dialog", "browser_drag", "browser_drop",
))

# Housekeeping and page-interaction helpers: allowed silently, but they do NOT
# open the session. Letting them would let an agent call browser_tabs once and
# then navigate freely, defeating the redirect. They write no row. Network
# inspection is here too: it is passive and works on a blank page.
_PW_MCP_HOUSEKEEPING = frozenset((
    "browser_network_request", "browser_network_requests",
    "browser_console_messages", "browser_emulate_media", "browser_resize",
    "browser_tabs", "browser_close", "browser_take_screenshot",
    "browser_wait_for", "browser_select_option", "browser_press_key",
    "browser_hover",
))


def _pw_mcp_action(tool_name):
    """`browser_click` for `mcp__playwright-ads__browser_click`, or "".

    Any server whose name contains `playwright` counts, because the same
    server is registered under several names: `mcp__playwright__`,
    `mcp__plugin_playwright_playwright__`, `mcp__playwright-ads__`,
    `mcp__playwright-jono__`. The kit's own `mcp__browse__browse` does not
    contain the word and can never match."""
    if not tool_name.startswith("mcp__"):
        return ""
    server, sep, action = tool_name[len("mcp__"):].rpartition("__")
    if not sep or "playwright" not in server.lower():
        return ""
    return action


def prefilter_browser_driving(ctx):
    action = _pw_mcp_action(ctx["tool_name"] or "")
    if action in _PW_MCP_ALWAYS_ALLOWED:
        # `browse` cannot do this, so there is nothing to steer towards. The
        # match exists only so enforce can open the session: from here on a
        # plain navigate or click is allowed too, for the rest of the session.
        return Match(
            "Playwright MCP `%s`: not expressible in `browse`" % action,
            "",
            extra={"how": "playwright mcp tool %s" % action, "no_soften": True,
                   "open_session": True, "action": action},
        )
    if action not in _PW_MCP_BROWSING:
        return None  # includes _PW_MCP_HOUSEKEEPING: allowed, opens nothing
    # ask=False: the code decided. `no_soften` keeps the `user_requested`
    # question out of it as well, so nothing about this rule ever calls Jev.
    #
    # `strict` closes the two per-call ways past a deny, for this rule only.
    # Both were measured being used to keep browsing on Playwright rather than
    # to make a judgement call: a subagent stamped `[airlock-ok: ...]` into the
    # `element` field of a click, and, failing that, sent the identical call
    # twice to ride the loop allowance. Neither is a human saying so, which is
    # what those escapes exist to carry.
    #
    # `unlock_on_browse_blocked` is the one door: when `browse` gave up in
    # this session, or an always-allowed Playwright call already opened it
    # (hooks/airlock_browse_unlock.py and enforce.py write the row through
    # airlock/browse_state.py), this deny becomes a warn / silent allow for
    # the rest of the session. The session_id is not visible here, so
    # `airlock/enforce.py` does the lookup.
    return Match(
        "Playwright MCP `%s`: use the `browse` tool instead" % action,
        R11_SUGGESTION,
        extra={"how": "playwright mcp tool %s" % action, "no_soften": True,
               "strict": True, "unlock_on_browse_blocked": True},
    )


# Rules that can explain their own silence. Keyed by rule id so the hot path
# pays nothing for the rules that cannot.
SUPPRESSION_BY_RULE = {"R10-general-risk": general_risk_suppression}


def suppression_reason(rule_id, answers):
    """Never raises. Returns None for any rule with no explanation to give."""
    fn = SUPPRESSION_BY_RULE.get(rule_id)
    if fn is None:
        return None
    try:
        return fn(answers)
    except Exception:
        return None


# --- the table ---------------------------------------------------------------

RULES = [
    Rule(
        id="R1-secret-exposure",
        tools=SHELL_TOOLS + ("Read", "NotebookRead"),
        action="deny",
        prefilter=prefilter_secret,
        questions=questions_secret,
        deny_when=deny_secret,
        why="CLAUDE.md Safety: never print a secret value; a leaked key means a rotation.",
    ),
    Rule(
        id="R2-claude-api-skill",
        tools=("Skill",),
        action="deny",
        prefilter=prefilter_claude_api,
        questions=questions_claude_api,
        deny_when=deny_claude_api,
        why="CLAUDE.md: one claude-api load measured 324,006 input tokens for a price lookup.",
    ),
    Rule(
        id="R3-whole-suite-or-uncapped-build",
        tools=SHELL_TOOLS,
        action="warn",
        prefilter=prefilter_wide_run,
        why="CLAUDE.md resource envelope: cap parallelism explicitly; prefer targeted test runs.",
    ),
    Rule(
        id="R4-long-work-bare-shell",
        tools=SHELL_TOOLS,
        action="warn",
        prefilter=prefilter_long_run,
        questions=questions_long_run,
        deny_when=deny_long_run,
        why="CLAUDE.md: long work runs in tmux and must survive disconnect.",
    ),
    Rule(
        id="R5-sudo",
        tools=SHELL_TOOLS,
        action="deny",
        prefilter=prefilter_sudo,
        why="CLAUDE.md: sudo only for a named system package, never under $HOME.",
    ),
    Rule(
        id="R6-gui-or-browser",
        tools=SHELL_TOOLS,
        action="off",
        # OFF by default on EVERY platform. The rule encodes "this box is a
        # headless server with no desktop", and most people run Claude Code on
        # a machine that has one, where opening a browser is a normal thing to
        # do. A machine that really is headless turns it on with
        # {"R6-gui-or-browser": "deny"} in rules.json -- install/install.sh
        # writes exactly that entry when it detects a headless Linux box, and
        # `install/install.sh --headless` forces it. The deny text adapts to
        # the platform (see prefilter_gui).
        prefilter=prefilter_gui,
        why="CLAUDE.md: there is no desktop; print the URL instead. Off by "
            "default everywhere; headless machines turn it on in rules.json.",
    ),
    Rule(
        id="R7-destructive",
        tools=SHELL_TOOLS,
        action="warn",
        prefilter=prefilter_destructive,
        why="CLAUDE.md: ask first for anything hard to reverse or outward-facing.",
    ),
    Rule(
        id="R7-root-delete",
        tools=SHELL_TOOLS,
        action="deny",
        prefilter=prefilter_root_delete,
        why="A recursive delete of / or the home directory is never part of a task.",
    ),
    Rule(
        id="R8-tier-guard",
        tools=("Agent",),
        action="deny",
        legacy="tier_guard",
        why="Original tier guard, behaviour unchanged.",
    ),
    Rule(
        id="R8-tool-choice-guard",
        tools=SHELL_TOOLS,
        action="deny",
        legacy="tool_choice_guard",
        why="Original tool-choice guard, behaviour unchanged.",
    ),
    Rule(
        id="R9-commit-secret",
        tools=SHELL_TOOLS,
        action="deny",
        prefilter=prefilter_commit_secret,
        why="CLAUDE.md Safety: never commit secrets. Credential shapes from "
            "jev-commit's local belt (airlock/belt.py); no diff is ever sent anywhere.",
    ),
    Rule(
        id="R10-general-risk",
        tools=SHELL_TOOLS,
        action="warn",
        prefilter=prefilter_general_risk,
        questions=questions_general_risk,
        deny_when=warn_general_risk,
        fallback=True,
        why="Ported in spirit from leepokai/jev-guard's ACTION_QUESTIONS risk score "
            "(docs/CREDITS.md), narrowed to calls no other rule covers "
            "and that a code pre-filter marks as reaching outside the working tree. "
            "Warn only, never deny.",
    ),
    Rule(
        id="R11-browse-via-jev",
        # Every tool: an MCP tool name is not known ahead of time. The
        # pre-filter returns on its first line for anything that is not an
        # `mcp__` call, so the cost of the wide `tools` is a string compare.
        tools=("*",),
        action="deny",
        prefilter=prefilter_browser_driving,
        why="The kit ships a Jev-decided `browse` MCP tool that reaches the same "
            "goals for roughly 1/233rd of the Claude spend (README, browse/). A "
            "Playwright MCP browsing call is pointed at it. Code only, no Jev "
            "question; the Playwright servers stay registered.",
    ),
]

RULES_BY_ID = {r.id: r for r in RULES}


# --- config ------------------------------------------------------------------

def load_action_overrides(path=None):
    """Read ~/.config/airlock/rules.json -> {rule_id: action}. Unknown ids and
    invalid actions are ignored. Never raises."""
    p = path or CONFIG_FILE
    try:
        with open(p, "r") as f:
            data = json.load(f)
    except Exception:
        return {}
    out = {}
    if isinstance(data, dict):
        raw = data.get("rules") if isinstance(data.get("rules"), dict) else data
        for k, v in (raw or {}).items():
            if k in RULES_BY_ID and isinstance(v, str) and v in VALID_ACTIONS:
                out[k] = v
    return out


def default_action(rule, windows=None):
    """The rule's default action on THIS platform, before rules.json.

    Identical to `rule.action` for every rule that does not set
    `windows_action`. Never raises."""
    try:
        if rule.windows_action is not None and is_windows(windows):
            return rule.windows_action
    except Exception:
        pass
    return rule.action


def effective_action(rule, overrides=None, windows=None):
    ov = overrides if overrides is not None else load_action_overrides()
    return ov.get(rule.id, default_action(rule, windows=windows))


# --- the hot path ------------------------------------------------------------

def build_ctx(data, tool_name=None):
    ti = data.get("tool_input") or {}
    tool_name = tool_name or data.get("tool_name") or ""
    command = str(ti.get("command") or "") if tool_name in SHELL_TOOLS else ""
    return {
        "tool_name": tool_name,
        "tool_input": ti,
        "cwd": data.get("cwd") or "",
        "command": command,
        "description": str(ti.get("description") or ""),
        # Only the PATH, never the transcript's contents: airlock/context.py
        # is the one place that reads it, and it reads user rows only. Carried
        # on the ctx so a rule that asks `user_requested` as part of its own
        # question set (R10) can supply the evidence for it.
        "transcript_path": data.get("transcript_path") or "",
        "segments": split_segments(strip_heredocs(command)) if command else [],
        "all_segments": all_segments(strip_heredocs(command)) if command else [],
    }


def prefilter_matches(ctx, overrides=None, windows=None):
    """Return [(rule, Match|None)] for every rule that could fire on this call.

    Legacy rules yield (rule, None) -- their own pre-filter lives in the guard
    they reproduce. Rules switched "off" are skipped here, so an off rule costs
    nothing at all. Never raises: a rule whose pre-filter throws is treated as
    not matching.
    """
    out = []
    fallbacks = []
    ov = overrides if overrides is not None else load_action_overrides()
    tool_name = ctx.get("tool_name") or ""
    for rule in RULES:
        if not rule.applies_to(tool_name):
            continue
        if ov.get(rule.id, default_action(rule, windows=windows)) == "off":
            continue
        if rule.fallback:
            fallbacks.append(rule)
            continue
        if rule.legacy:
            if rule.legacy == "tool_choice_guard":
                from . import policy
                if not policy.bash_is_search_like(ctx.get("command") or ""):
                    continue
            out.append((rule, None))
            continue
        if rule.prefilter is None:
            continue
        try:
            match = rule.prefilter(ctx)
        except Exception:
            match = None
        if match is not None:
            out.append((rule, match))

    # The catch-all tier. Skipped entirely when any specific rule already
    # covers this call, so it never doubles up and never costs a second Jev
    # request for a call that was going to be judged anyway.
    if not out:
        for rule in fallbacks:
            try:
                match = rule.prefilter(ctx)
            except Exception:
                match = None
            if match is not None:
                out.append((rule, match))
    return out


def dry_run(ctx, ask=None, overrides=None, windows=None):
    """Evaluate every rule against one payload with NO logging, NO stdout and
    NO session state -- used by the eval harness and the unit tests.

    `ask(rule, ctx, match) -> answers` supplies the Jev half. When it is None,
    a rule whose pre-filter says the fuzzy part is in doubt is reported with
    fires=None ("would have asked"), never as a fire.

    Returns a list of dicts: rule_id, action (effective), matched, asked,
    fires, detail, suggestion, confidence, margin.
    """
    from . import policy

    out = []
    ov = overrides if overrides is not None else load_action_overrides()
    for rule, match in prefilter_matches(ctx, ov, windows=windows):
        eff = ov.get(rule.id, default_action(rule, windows=windows))
        row = {
            "rule_id": rule.id,
            "action": eff,
            "matched": True,
            "asked": False,
            "fires": True,
            "detail": match.detail if match else "",
            "suggestion": match.suggestion if match else "",
            "legacy": bool(rule.legacy),
        }
        if rule.legacy:
            row["fires"] = None
            out.append(row)
            continue
        if eff == "deny" and match.extra.get("downgrade_to"):
            row["action"] = eff = match.extra["downgrade_to"]
            row["downgraded"] = True
        if match.ask and eff != "log":
            if ask is None:
                row["fires"] = None
                out.append(row)
                continue
            row["asked"] = True
            try:
                answers = ask(rule, ctx, match)
            except Exception as exc:
                row["error"] = str(exc)[:300]
                row["fires"] = False
                out.append(row)
                continue
            row["answers"] = answers
            fires = bool(rule.deny_when(answers)) if rule.deny_when else False
            conf = margin = None
            for a in (answers or {}).values():
                if isinstance(a, dict) and "choice" in a:
                    conf = a.get("confidence")
                    margin = policy.compute_margin(a.get("probabilities"))
                    break
            row["confidence"] = conf
            row["margin"] = margin
            if eff == "deny" and conf is not None and not policy.meets_deny_bar(conf, margin):
                fires = False
                row["gated"] = "below_deny_bar"
            row["fires"] = fires
            if not fires:
                reason = suppression_reason(rule.id, answers)
                if reason:
                    row["suppressed"] = reason
        out.append(row)
    return out
