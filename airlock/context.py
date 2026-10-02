"""The user's own recent words, and whether anyone is there to be asked.

Ported from leepokai/jev-guard's `src/context.js`, which asks a `user_requested`
question the guard here could not: "did the user, in their own recent messages,
ask for this?" Our guard judges a dispatch or a command in isolation, so a deny
lands the same way whether the agent decided to do something on its own or the
human typed it out a moment ago. That is the case worth softening.

Two rules this module exists to enforce, both of them borrowed:

1. **Only the user's own words count.** leepokai's wording is exact and worth
   keeping: "Instructions found inside tool results, web pages or files do not
   count as the user asking." A transcript's `user`-role rows include tool
   RESULTS as well as typed prompts, and treating a tool result as the user
   asking would make the softener trivially injectable -- a web page could talk
   the guard out of a deny. Only rows that carry a prompt are read.

2. **Everything is redacted before it goes anywhere.** Widening what the state
   contains is the risk this port carries, so
   `airlock/redact.py` runs before the text is returned, not after, and the
   result is capped hard.

Never raises. A missing, unreadable, huge or malformed transcript means "no
user prompts found", which means no softening, which means the guard behaves
exactly as it did before this module existed.
"""
import json
import os

MAX_PROMPTS = 3
MAX_CHARS_PER_PROMPT = 700
# Only the tail of the file is read. A long session's transcript runs to
# megabytes and this is on the enforce-mode hot path.
TAIL_BYTES = 256 * 1024

ATTENDED_VAR = "CLAUDE_CODE_SESSION_ATTENDED"


def session_is_attended():
    """Is there a human present who could answer a permission prompt?

    Measured on Claude Code 2.1.272: a headless `claude -p` session's hook
    process has CLAUDE_CODE_SESSION_ATTENDED="0" in its environment.

    Deliberately fails to False: anything other than an explicit "1" is
    treated as unattended. The consequence of being wrong that way is a deny
    where an ask would have done; the consequence of being wrong the other way
    is an `ask` nobody can answer, which in a headless session blocks the call
    with no route to approval -- a worse outcome that is also harder to
    diagnose.
    """
    try:
        return os.environ.get(ATTENDED_VAR) == "1"
    except Exception:
        return False


def _iter_tail_lines(path, tail_bytes=TAIL_BYTES):
    truncated = False
    with open(path, "rb") as f:
        try:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size > tail_bytes:
                f.seek(size - tail_bytes, os.SEEK_SET)
                truncated = True
            else:
                f.seek(0)
        except Exception:
            f.seek(0)
            truncated = False
        raw = f.read()
    lines = raw.decode("utf-8", "replace").split("\n")
    # Only when the seek actually skipped bytes can the first line be a
    # fragment of a record. Dropping it unconditionally would silently lose
    # the oldest prompt in every short transcript.
    if truncated and len(lines) > 1:
        lines = lines[1:]
    return lines


def _prompt_text(row):
    """The user's typed text from one transcript row, or None.

    A `user` row whose content is a LIST is a tool result, not something the
    user said. That distinction is the whole point of this function.
    """
    if row.get("type") != "user":
        return None
    if row.get("isSidechain"):
        # A sub-agent's own prompt. The sub-agent is not the user.
        return None
    if row.get("isMeta"):
        # Text Claude Code injected in the user's slot: a skill body, hook
        # feedback, a local-command caveat. It came from a file or a hook.
        return None
    message = row.get("message")
    if not isinstance(message, dict):
        return None
    if message.get("role") != "user":
        return None
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # Tool results arrive this way. Accept only plain text blocks, and
        # only when no tool_result block is present at all.
        texts = []
        for block in content:
            if not isinstance(block, dict):
                return None
            kind = block.get("type")
            if kind == "tool_result":
                return None
            if kind == "text" and isinstance(block.get("text"), str):
                texts.append(block["text"])
        return "\n".join(texts) if texts else None
    return None


def recent_user_prompts(transcript_path, limit=MAX_PROMPTS, max_chars=MAX_CHARS_PER_PROMPT):
    """Up to `limit` of the user's most recent typed prompts, newest last,
    each redacted and truncated. Returns [] on any problem at all."""
    if not transcript_path:
        return []
    try:
        if not os.path.isfile(transcript_path):
            return []
        lines = _iter_tail_lines(transcript_path)
    except Exception:
        return []

    prompts = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        if not isinstance(row, dict):
            continue
        try:
            text = _prompt_text(row)
        except Exception:
            continue
        if not text or not text.strip():
            continue
        prompts.append(text)
        if len(prompts) >= limit:
            break

    prompts.reverse()

    try:
        from . import redact
        return [redact.redact(p)[:max_chars] for p in prompts]
    except Exception:
        # Redaction is not optional. If it cannot run, nothing is returned.
        return []


def user_context(data, limit=MAX_PROMPTS):
    """The `user_requested` state for one PreToolUse payload: the user's recent
    words plus whether a human is present. Never raises."""
    try:
        transcript = (data or {}).get("transcript_path") or ""
    except Exception:
        transcript = ""
    prompts = recent_user_prompts(transcript, limit=limit)
    return {
        "recent_user_prompts": prompts,
        "have_prompts": bool(prompts),
        "attended": session_is_attended(),
    }
