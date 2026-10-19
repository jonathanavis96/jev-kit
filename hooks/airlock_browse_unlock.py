#!/usr/bin/env python3
"""PostToolUse and PostToolUseFailure hook: notice when the kit's `browse` tool has given up.

WHY THIS EXISTS
===============

R11 is strict. A Playwright MCP browsing call is denied, and neither an
`[airlock-ok: ...]` stamp nor a repeat gets past it (airlock/rules.py,
prefilter_browser_driving). That is the right shape while the kit's own
`browse` tool can do the job for a fraction of the cost.

It cannot always. Jev's chooser sees one step at a time and only inside the
viewport, so a multi-hop goal is out of reach; measured, `browse` came back
`status: blocked` on a two-hop Wikipedia link-navigation task. A strict
rule on top of that leaves the session with no browser at all.

So this hook watches `browse` calls. It is registered twice, under
PostToolUse and under PostToolUseFailure, because a call that raises never
reaches PostToolUse at all: Claude Code sends it to PostToolUseFailure, with
an `error` string in place of `tool_response`. Registered under PostToolUse
alone, the hook missed every errored call, which is the commonest way
`browse` gives up (measured 2026-09-25: three "60-action demo budget" errors
in one session, an empty state file, and R11 still denying).

When a call comes back `blocked`, or the call itself errored, it writes a small per-session row through
airlock/browse_state.py, and R11 turns from a deny into a warn for the next
rest of that session. Nothing else opens that door: with no row,
stamps and repeats still do nothing.

WHAT IT PROMISES
================

  - It never blocks and never speaks. No stdout, no stderr, exit 0, always.
    PostToolUse runs after the tool has already done its work, so there is
    nothing here worth risking a session over.
  - It only ever WRITES local state, and only for `mcp__browse__browse`.
  - Fail open by doing nothing: a payload it cannot parse, a response shape
    it does not recognise, a state file it cannot write -- every one of those
    records nothing, which leaves R11 exactly as strict as it was.

THE RESPONSE SHAPES IT HANDLES
==============================

`tool_response` for an MCP tool arrives in more than one shape, so all of
them are handled rather than guessed at. Taken from real transcripts on this
box:

  - a LIST of content blocks, which is the ordinary success shape:
        [{"type": "text", "text": "{\\"final_url\\": ..., \\"status\\": \\"blocked\\", ...}"}]
  - a STRING, which is what a failed call leaves behind:
        "Error: browse failed: a Chromium this server did not start is ..."
  - a DICT in the MCP CallToolResult shape, `{"content": [...], "isError": true}`,
    which is what browse/server.py itself returns over the wire.
  - NO `tool_response`, on PostToolUseFailure: the payload carries
    `hook_event_name: "PostToolUseFailure"`, a top-level `error` string and
    `is_interrupt`. Any failure but an interrupt records "error".

The text inside is JSON from browse/server.py: `final_url`, `title`, `status`,
`steps`, `elapsed_ms`, `text`. `status` is the field that matters. `done`
records nothing.
"""
import json
import os
import sys

HOOK_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HOOK_DIR)

# Same sys.path surgery as hooks/airlock.py, and for the same reason: this
# directory is not a package and nothing in it should ever shadow a module in
# the `airlock` package next to it.
for _p in (HOOK_DIR, ""):
    while _p in sys.path:
        sys.path.remove(_p)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# The kit's own browse tool, as Claude Code names it. The server half is
# browse/server.py and browse/install.sh prints the block that registers it.
# Matched on the server name containing "browse" and the action being
# "browse", so a session that registered it under a slightly different server
# name still counts, and no Playwright tool ever can.
BROWSE_ACTION = "browse"


def _is_browse_tool(tool_name):
    if not isinstance(tool_name, str) or not tool_name.startswith("mcp__"):
        return False
    server, sep, action = tool_name[len("mcp__"):].rpartition("__")
    return bool(sep) and action == BROWSE_ACTION and "browse" in server.lower()


def _blocks_text(blocks):
    parts = []
    for block in blocks:
        if isinstance(block, dict):
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
        elif isinstance(block, str):
            parts.append(block)
    return "\n".join(parts)


def _text_and_error(response):
    """(text, is_error) out of whatever `tool_response` turned out to be.

    `is_error` is only ever True when the payload said so. A string response
    carries no flag, so the caller falls back to reading the text."""
    if isinstance(response, str):
        return response, False
    if isinstance(response, list):
        return _blocks_text(response), False
    if isinstance(response, dict):
        is_error = bool(response.get("isError") or response.get("is_error"))
        content = response.get("content")
        if isinstance(content, list):
            return _blocks_text(content), is_error
        if isinstance(content, str):
            return content, is_error
        # Some hosts hand over the already-decoded result object. If it looks
        # like one of browse/server.py's, re-encode it so the one parser below
        # handles every shape.
        if isinstance(response.get("status"), str):
            try:
                return json.dumps(response), is_error
            except Exception:
                return "", is_error
        return "", is_error
    return "", False


def _looks_like_browse_error(text):
    """A failed `browse` call, read off the text, for the shapes that carry no
    flag. Deliberately narrow: an ordinary result is JSON and never matches."""
    if not text:
        return False
    head = text.strip()[:200]
    return head.startswith("Error:") or "browse failed:" in head


def _is_failure_event(payload):
    """True for a PostToolUseFailure payload. Keyed on the event name, with
    the payload's shape as the fallback for a host that leaves the name out:
    a top-level `error` and no `tool_response`."""
    event = payload.get("hook_event_name")
    if event == "PostToolUseFailure":
        return True
    if event:
        return False
    return "error" in payload and "tool_response" not in payload


def outcome(payload):
    """(status, goal, url) to record, or None to record nothing.

    `status` is "blocked" when `browse` gave up on the goal, or "error" when
    the call itself failed. Never raises."""
    try:
        if not isinstance(payload, dict):
            return None
        if not _is_browse_tool(payload.get("tool_name")):
            return None

        tool_input = payload.get("tool_input")
        tool_input = tool_input if isinstance(tool_input, dict) else {}
        goal = tool_input.get("goal")
        url = tool_input.get("start_url")

        # A call that raised arrives as PostToolUseFailure: an `error` string
        # and no `tool_response` at all. That is the ordinary shape of a
        # broken `browse`, so it counts. An interrupt is the user pressing
        # Esc, which says nothing about whether `browse` could do the job.
        if _is_failure_event(payload):
            if payload.get("is_interrupt"):
                return None
            return ("error", goal, url)

        text, is_error = _text_and_error(payload.get("tool_response"))

        result = None
        try:
            result = json.loads(text)
        except Exception:
            result = None

        if isinstance(result, dict) and isinstance(result.get("status"), str):
            if result.get("final_url"):
                url = result.get("final_url")
            status = result["status"].strip().lower()
            # `done`, and anything else browse grows later, records nothing.
            # Only giving up opens the door.
            return ("blocked", goal, url) if status == "blocked" else None

        # No parseable result. A call that errored still counts -- a broken
        # `browse` must not strand the session with no browser at all.
        if is_error or _looks_like_browse_error(text):
            return ("error", goal, url)
        return None
    except Exception:
        return None


def main():
    try:
        raw = sys.stdin.read()
    except Exception:
        return 0
    try:
        payload = json.loads(raw)
    except Exception:
        return 0

    found = outcome(payload)
    if not found:
        return 0
    status, goal, url = found
    try:
        from airlock import browse_state
        browse_state.record_gave_up(payload.get("session_id"), status,
                                    goal=goal, url=url)
    except Exception:
        return 0
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        # Nothing this hook can fail at is worth a word on a session's stderr.
        sys.exit(0)
