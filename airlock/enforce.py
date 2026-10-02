"""Synchronous judging path, run IN the PreToolUse hook process
(hooks/airlock.py), never detached -- unlike shadow mode, a deny has to
reach stdout before the hook exits, so this cannot hand off to a background
worker the way airlock/worker.py does.

Since the all-tools widening this is driven by the rules table
(airlock/rules.py). The hook is registered for EVERY tool; the pure code
pre-filters in that table decide in microseconds whether any rule could apply.
A call no rule covers costs nothing and logs nothing. Only a rule whose
pre-filter matched AND whose fuzzy half is genuinely in doubt spends a Jev
request.

Per-rule action (`deny` / `warn` / `log`, plus `off` in config) comes from the
rule's default, overridable in ~/.config/airlock/rules.json. Only `deny` can
block; `warn` returns its advice as hook output; `log` writes a row and
nothing else.

Budget: AIRLOCK_BUDGET_MS bounds every client.ask() call -- default 1500ms,
2000ms on native Windows (no warm daemon there, see budget_ms() below).
Fail-open everywhere: any exception, a malformed answer, the daemon being
down plus a slow fallback, or exceeding the budget all mean ALLOW, logged
with `error` set and `enforced: false`. This module never raises to its
caller (hooks/airlock.py still wraps every call here in try/except as a
second line of defence).
"""
import datetime
import json
import re
import sys
import time

# client and guards are imported lazily (inside the branches that need them):
# they pull in urllib and the keyfile reader, several ms of start-up that a
# code-only rule -- the common matched case -- must not pay for.
from . import log, paths, policy
from . import rules as rules_mod
from . import state as state_mod
from .platform_compat import is_windows

DEFAULT_BUDGET_MS = 1500

# Windows has no warm daemon (airlock/platform_compat.py:has_unix_sockets is
# False there), so every judgement is a fresh HTTPS connection rather than a
# socket round-trip to an already-running process. Measured against a native
# Windows host: median 1030ms, max 1359ms over 32 calls, with 1 of 32
# exceeding the POSIX 1500ms budget and fail-opening (see
# docs/measurements.md). The owner's call is 2000ms on Windows so that
# variance does not routinely eat the budget and silently disable
# enforcement; POSIX, WSL and macOS keep 1500ms, where the daemon is
# available and the measured latency is far below it.
WINDOWS_DEFAULT_BUDGET_MS = 2000

LOOP_WINDOW_S = 600  # 10 minutes, per the brief

# `user_requested` softening. At or above this, a deny becomes a warn. It is
# deliberately high: softening a deny is a one-way door for the guard, and the
# answer comes from a question a tool result would love to be able to
# influence. See airlock/context.py for the code-side belt.
USER_REQUESTED_SOFTEN_AT = 0.75

# All three stamps are accepted: `[airlock-ok: ...]` is the current name,
# `[plumbline-ok: ...]` and `[jev-ok: ...]` are what existing sessions,
# transcripts and habits on a machine running either older layout already
# use. Dropping an old one would silently stop honouring overrides
# mid-cutover, which is exactly the class of failure a rename is meant to
# avoid.
_OVERRIDE_RE = re.compile(r"\[(?:airlock|plumbline|jev)-ok:\s*([^\]]*)\]", re.IGNORECASE)

_ACTION_RANK = {"deny": 0, "ask": 1, "warn": 2, "log": 3, "off": 4}


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def budget_ms(windows=None):
    """The hard budget for one client.ask() call, in milliseconds.

    Default is platform-dependent: 2000ms on native Windows (no warm daemon,
    every call is a fresh HTTPS connection), 1500ms everywhere else (POSIX,
    WSL, macOS -- all have the daemon). AIRLOCK_BUDGET_MS and its legacy
    names (PLUMBLINE_BUDGET_MS, JEV_GUARD_BUDGET_MS) override the default on
    every platform, exactly as before this default became platform-aware.

    `windows` is the injection point every caller in this package forwards
    (see airlock/platform_compat.py); real detection is used when it is
    None.
    """
    default = WINDOWS_DEFAULT_BUDGET_MS if is_windows(windows) else DEFAULT_BUDGET_MS
    try:
        return int(paths.env("AIRLOCK_BUDGET_MS", "PLUMBLINE_BUDGET_MS", "JEV_GUARD_BUDGET_MS",
                             default=str(default)))
    except Exception:
        return default


def emit_deny(reason):
    sys.stdout.write(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))


def emit_ask(reason):
    """Hand the decision to the human: allow, but only if they say so.

    Measured empirically against Claude Code 2.1.272 (the same way the warn
    channel was), not assumed:

      - `permissionDecision: "ask"` IS honoured for PreToolUse. The CLI does
        not ignore it, and `permissionDecisionReason` reaches the model
        verbatim.
      - In a HEADLESS `claude -p` session there is nobody to answer, and the
        CLI resolves an ask exactly as it resolves a deny: the tool does not
        run and the call is recorded in the session result's
        `permission_denials` array. `--permission-mode bypassPermissions` does
        NOT bypass it.

    So an ask in an unattended session is a deny with a more confusing reason
    string. `_effective_block_action()` turns it back into an honest deny
    there, detected from CLAUDE_CODE_SESSION_ATTENDED (see
    airlock/context.py:session_is_attended).
    """
    sys.stdout.write(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        }
    }))


def emit_warn(advice):
    """A warn NEVER blocks. It returns the advice two ways: `systemMessage`
    (documented for every hook event, shown to the user) and
    hookSpecificOutput.additionalContext, which this CLI accepts generically
    for PreToolUse -- if a future version ignores it for this event the warn
    silently degrades to the systemMessage plus the log row, and still never
    blocks."""
    text = "\n\n".join(advice)
    sys.stdout.write(json.dumps({
        "systemMessage": text,
        "suppressOutput": True,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": text,
        },
    }))


def emit_rewrite(updated_input, text):
    """Allow the call, but with an edited tool_input.

    Verified against the installed CLI, not assumed. Claude Code 2.1.278 on
    this box ships its own hooks reference, which lists under
    hookSpecificOutput:

        `updatedInput` - Modified tool input (PreToolUse only)

    and a live `claude -p` run with a PreToolUse hook returning
    `permissionDecision: "allow"` plus `updatedInput` executed the REWRITTEN
    command, not the original one, and showed the accompanying
    additionalContext to the model.

    If a future CLI ignores the field the call simply runs unchanged, with the
    context note still attached -- a rewrite degrades to a warn, never to a
    block.
    """
    sys.stdout.write(json.dumps({
        "systemMessage": text,
        "suppressOutput": True,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": text,
            "updatedInput": updated_input,
            "additionalContext": text,
        },
    }))


def find_override(*texts):
    """Return the reason string from the first `[airlock-ok: <reason>]` (or
    legacy `[plumbline-ok: ...]` / `[jev-ok: ...]`) stamp found in any of
    `texts`, or None."""
    for t in texts:
        m = _OVERRIDE_RE.search(t or "")
        if m:
            return m.group(1).strip()
    return None


def _override_texts(ctx):
    ti = ctx.get("tool_input") or {}
    texts = [
        str(ti.get("description") or ""),
        str(ti.get("prompt") or ""),
        str(ti.get("command") or ""),
        str(ti.get("args") or ""),
    ]
    # An MCP tool has none of those four fields, so a stamp could never reach
    # a rule that matches one (R11). Any top-level text field of the call
    # carries it there: `element` on a click, `text` on a type.
    if (ctx.get("tool_name") or "").startswith("mcp__") and isinstance(ti, dict):
        texts.extend(v for v in ti.values() if isinstance(v, str))
    return texts


# A plocate or locate database is a snapshot from its last rebuild. The kit's
# own home.db is rebuilt hourly by airlock-filesearch.timer, but a
# `--no-systemd` install or the system database can be older than that, so
# the note names no schedule. Without it, an agent that just wrote a file and
# then searched for it would read the empty result as "absent". Only said
# when the suggestion actually runs plocate or locate: Everything keeps a live
# NTFS index, and a graphify query is not a filename search at all.
PLOCATE_FRESHNESS_NOTE = (
    "The plocate index is a snapshot from its last rebuild, so a file created\n"
    "since then is missing from it. For a recent file, search the directory it\n"
    "was written to directly, with `fd` or `find` scoped to that directory.\n"
)

# A suggestion line that runs the index, as opposed to prose that mentions it
# (ES_WSL_SUGGESTION says "the plocate index covers $HOME" and runs only es).
_LOCATE_COMMAND_RE = re.compile(r"^\s*(?:plocate|locate)\s", re.MULTILINE)


def suggests_locate(suggestion):
    return bool(_LOCATE_COMMAND_RE.search(suggestion or ""))


def _bash_deny_reason(entry):
    suggestion = entry.get("suggestion") or "a more targeted search"
    scope = entry.get("scope") or "a broad search"
    freshness = PLOCATE_FRESHNESS_NOTE if suggests_locate(suggestion) else ""
    return (
        "BLOCKED (airlock enforce): this looks like a %s search. Run instead:\n"
        "    %s\n"
        "%s"
        # "this call", not "this Bash call": the same rule fires for the
        # PowerShell tool on a Windows machine without Git Bash, where the
        # Bash tool is never registered at all.
        "Wrong call? Add `[airlock-ok: <reason>]` to this call's description to override."
        % (scope, suggestion, freshness)
    )


def _agent_deny_reason(entry):
    chosen = entry.get("chosen_type", "?")
    if chosen == "fable" and (entry.get("prior_failed") or 0.0) < 0.5:
        return (
            "BLOCKED (airlock enforce): dispatching 'fable' without stating a prior failed "
            "attempt. Name what was already tried and why it failed (fable is last resort, "
            "after worker then Opus), or dispatch a cheaper agent first.\n"
            "Wrong call? Add `[airlock-ok: <reason>]` to the Agent prompt or description to override."
        )
    suggestion = entry.get("suggestion") or "a cheaper sub-agent"
    return (
        "BLOCKED (airlock enforce): this task looks like '%s', at least two rungs cheaper "
        "than '%s'. Retry with subagent_type=%s.\n"
        "Wrong call? Add `[airlock-ok: <reason>]` to the Agent prompt or description to override."
        % (entry.get("task_kind", "?"), chosen, suggestion)
    )


def _agent_warn_text(entry):
    """Two short lines: what was chosen, what Jev judged adequate, what to use
    instead, and that nothing was blocked."""
    from . import tiers
    chosen = entry.get("chosen_type") or "?"
    suggested = tiers.dispatch_name_for_rung(entry.get("suggestion")) or entry.get("suggestion") or "a cheaper agent"
    return (
        "airlock tier advice: dispatched '%s', but Jev judged this task '%s', which '%s' "
        "covers. Next time use subagent_type=%s.\n"
        "Advice only -- nothing was blocked and this call ran as you wrote it."
        % (chosen, entry.get("task_kind", "?"), entry.get("suggestion", "?"), suggested)
    )


def _agent_rewrite_text(entry, target):
    return (
        "airlock tier rewrite: subagent_type changed from '%s' to '%s' -- Jev judged this "
        "task '%s', which '%s' covers.\n"
        "To keep your own choice, put `[airlock-ok: <reason>]` in the Agent description "
        "and dispatch again."
        % (entry.get("chosen_type", "?"), target, entry.get("task_kind", "?"),
           entry.get("suggestion", "?"))
    )


def _rule_deny_reason(rule_id, detail, suggestion, action="deny", strict=False):
    lead = "NEEDS APPROVAL" if action == "ask" else "BLOCKED"
    text = "%s (airlock %s): %s\n%s" % (lead, rule_id, detail, suggestion)
    if strict:
        # The stamp would be refused, so offering it here would be a lie and,
        # worse, a hint. A strict rule's own suggestion says what to do.
        return text
    return (text + "\nWrong call? Add `[airlock-ok: <reason>]` to this call's "
            "description to override.")


def _rule_warn_text(rule_id, detail, suggestion):
    return "airlock %s: %s\n%s" % (rule_id, detail, suggestion)


def _browse_unlock_warn_text(rule_id, detail, row):
    """R11 standing aside because `browse` already gave up in this session.

    Says WHICH failure opened the door and how long it stays open, so the
    session can tell this apart from the rule simply not firing."""
    row = row or {}
    how = ("`browse` came back blocked" if row.get("status") == "blocked"
           else "a `browse` call errored")
    goal = row.get("goal")
    line = "%s in this session" % how
    if goal:
        line += " on: %s" % (goal if len(goal) <= 120 else goal[:117] + "...")
    return (
        "airlock %s: %s\n"
        "%s, so Playwright MCP is allowed for 30 minutes from then. Nothing "
        "was blocked and this call ran as you wrote it.\n"
        "Go back to `browse` for the next piece of browsing: this door is "
        "open because that one failed, not because Playwright is the default "
        "again." % (rule_id, detail, line)
    )


def effective_block_action(action):
    """`ask` is only a real outcome when somebody is there to answer it.

    In an unattended session an ask blocks the call exactly as a deny does
    (measured -- see emit_ask), with no route to approval, so it is reported
    and logged as the deny it actually is rather than dressed up as a
    question.
    """
    if action != "ask":
        return action
    try:
        from . import context
        return "ask" if context.session_is_attended() else "deny"
    except Exception:
        return "deny"


def user_requested_score(data, ctx, b_ms, entry):
    """Ask Jev whether the user's own recent words asked for this action.

    Returns a float in [0, 1], or None when the question could not be asked at
    all -- no transcript, no recent user prompts, no key, an error, or the
    budget blown. None and 0.0 mean the same thing to the caller (no
    softening); they are kept distinct only so the log says which happened.

    This answer can ONLY soften a deny. It is never consulted for a rule that
    was not already going to deny, and it can never turn a warn into a deny.
    """
    try:
        from . import context
        uctx = context.user_context(data)
    except Exception:
        return None
    if not uctx.get("have_prompts"):
        entry["user_requested_skipped"] = "no_user_prompts"
        return None

    start = time.monotonic()
    try:
        from . import client, questions
        state = questions.user_requested_state(_input_summary(ctx), uctx["recent_user_prompts"])
        result, _latency = client.ask(
            {"state": state, "model": client.MODEL,
             "questions": questions.user_requested_question()},
            timeout_s=b_ms / 1000.0,
        )
    except Exception as exc:
        entry["user_requested_error"] = str(exc)[:200]
        return None
    elapsed_ms = int((time.monotonic() - start) * 1000)
    if elapsed_ms > b_ms:
        entry["user_requested_error"] = "budget exceeded (%dms > %dms)" % (elapsed_ms, b_ms)
        return None
    try:
        answer = ((result or {}).get("answers") or {}).get("user_requested") or {}
        score = float(answer.get("noul") or 0.0)
    except Exception:
        return None
    entry["user_requested"] = score
    return score


def handle(data, tool_name, mode="enforce"):
    """Top-level dispatch for one PreToolUse call.

    Returns True if a deny was emitted to stdout, False otherwise. Never
    raises -- every branch is wrapped so a bug here can only ever fail open.
    """
    try:
        return _handle(data, tool_name, mode)
    except Exception:
        return False


def _handle(data, tool_name, mode="enforce"):
    b_ms = budget_ms()
    session_id = data.get("session_id") or ""
    ctx = rules_mod.build_ctx(data, tool_name)

    overrides = rules_mod.load_action_overrides()
    matches = rules_mod.prefilter_matches(ctx, overrides)
    if not matches:
        # Nothing any rule covers: no Jev call, no log row, no output.
        return False

    matches.sort(key=lambda rm: _ACTION_RANK.get(overrides.get(rm[0].id, rm[0].action), 9))
    override_reason = find_override(*_override_texts(ctx))

    base = {
        "ts": _now_iso(),
        "session_id": session_id,
        "cwd": ctx.get("cwd"),
        "tool_name": tool_name,
        "mode": mode,
        "budget_ms": b_ms,
    }

    advice = []
    for rule, match in matches:
        eff = overrides.get(rule.id, rules_mod.default_action(rule))
        if eff == "off":
            continue
        # One rule failing (a malformed Jev answer reaching compute_margin, say)
        # fails open for that rule only. Letting it escape to handle() used to
        # skip every later rule, drop any advice already collected and leave
        # no log row at all.
        try:
            if rule.legacy:
                denied = _run_legacy(data, tool_name, rule, eff, base, override_reason,
                                     b_ms, session_id, mode, advice)
            else:
                denied = _run_rule(ctx, rule, match, eff, base, override_reason,
                                   b_ms, session_id, mode, advice, data)
        except Exception as exc:
            entry = dict(base)
            entry.update({
                "guard": rule.legacy or "rules",
                "rule_id": rule.id,
                "action": eff,
                "error": ("%s: %s" % (type(exc).__name__, exc))[:300],
                "fires": False,
                "enforced": False,
            })
            log.append(entry)
            continue
        if denied and mode == "enforce":
            return True

    if advice and mode == "enforce":
        emit_warn(advice)
    return False


def _run_rule(ctx, rule, match, eff, base, override_reason, b_ms, session_id, mode, advice, data=None):
    """Evaluate one non-legacy rule. Returns True if it emitted a deny."""
    entry = dict(base)
    entry.update({
        "guard": "rules",
        "rule_id": rule.id,
        "action": eff,
        "detail": match.detail,
        "input_summary": _log_input_summary(ctx),
    })

    if eff == "deny" and match.extra.get("downgrade_to") in ("warn", "log"):
        eff = match.extra["downgrade_to"]
        entry["action"] = eff
        entry["downgraded"] = True

    fires = True
    if match.ask and eff != "log":
        start = time.monotonic()
        try:
            from . import client
            state, qs = rule.questions(ctx, match)
            result, latency_ms = client.ask(
                {"state": state, "model": client.MODEL, "questions": qs},
                timeout_s=b_ms / 1000.0,
            )
        except Exception as exc:
            entry["error"] = str(exc)[:300]
            entry["elapsed_ms"] = int((time.monotonic() - start) * 1000)
            entry["fires"] = False
            entry["enforced"] = False
            log.append(entry)
            return False
        elapsed_ms = int((time.monotonic() - start) * 1000)
        entry["elapsed_ms"] = elapsed_ms
        entry["answers"] = (result or {}).get("answers")
        entry["latency_ms"] = latency_ms
        entry["usage"] = (result or {}).get("usage")
        entry["jev_model"] = (result or {}).get("model")
        answers = (result or {}).get("answers") or {}
        fires = bool(rule.deny_when(answers)) if rule.deny_when else False
        conf, margin = _confidence_and_margin(answers)
        entry["confidence"] = conf
        entry["margin"] = margin
        if eff == "deny" and conf is not None:
            # A Choice-backed deny must clear the shared bar; a Noul answer
            # carries no margin and is never used for a deny action.
            if not policy.meets_deny_bar(conf, margin):
                fires = False
                entry.setdefault("gated", "below_deny_bar")
        if elapsed_ms > b_ms:
            fires = False
            entry.setdefault("error", "budget exceeded (%dms > %dms)" % (elapsed_ms, b_ms))
        if not fires:
            # A rule that can explain its own silence says so on the row. R10
            # withholding an earned warn because the human already asked for
            # this is not the same event as Jev scoring the command low, and
            # tuning cannot tell them apart without the field.
            reason = rules_mod.suppression_reason(rule.id, answers)
            if reason:
                entry["suppressed"] = reason
    else:
        entry["elapsed_ms"] = 0

    entry["fires"] = fires
    if not fires:
        entry["enforced"] = False
        log.append(entry)
        return False

    if eff == "log":
        entry["enforced"] = False
        log.append(entry)
        return False

    if eff == "warn":
        entry["enforced"] = False
        entry["warned"] = True
        log.append(entry)
        advice.append(_rule_warn_text(rule.id, match.detail, match.suggestion))
        return False

    # The `browse` unlock, before anything else in the deny path: when the
    # kit's own browser tool has already given up in this session, R11 has
    # nothing left to steer anyone towards, and a strict deny would leave the
    # session with no browser at all. A PostToolUse hook
    # (hooks/airlock_browse_unlock.py) writes the row; airlock/browse_state.py
    # holds it for 30 minutes. Only `browse` failing opens this -- a stamp and
    # a repeat still do nothing, which is the rest of `strict` untouched.
    #
    # Checked before the `mode != enforce` return so a shadow-mode row says
    # `unlocked_by` too, rather than reporting a would-be deny that would not
    # have happened.
    if match.extra.get("unlock_on_browse_blocked"):
        row = None
        try:
            from . import browse_state
            row = browse_state.recent_give_up(session_id)
        except Exception:
            row = None
        if row is not None:
            entry["unlocked_by"] = "browse_blocked"
            entry["browse_status"] = row.get("status")
            entry["action"] = "warn"
            entry["enforced"] = False
            entry["warned"] = True
            # Said once per unlock window, on the first Playwright call after
            # `browse` gave up; later calls in the window run silently.
            announce = False
            try:
                announce = browse_state.claim_announcement(session_id)
            except Exception:
                announce = False
            entry["announced"] = announce
            log.append(entry)
            if announce:
                advice.append(_browse_unlock_warn_text(rule.id, match.detail, row))
            return False

    # deny (or ask). Softening comes first: an explicit override stamp and a
    # user_requested hit are both "the human already said so", and neither
    # should cost a state write or an emitted block.
    #
    # A match carrying `no_soften` skips the `user_requested` question. R11
    # sets it: that rule is code-only from end to end, and a Jev answer that
    # could turn its deny into a warn would put a judgement call back in.
    if eff in ("deny", "ask") and mode == "enforce" and not match.extra.get("no_soften"):
        score = user_requested_score(data or {}, ctx, b_ms, entry)
        if score is not None and score >= USER_REQUESTED_SOFTEN_AT:
            entry["softened"] = "user_requested"
            entry["action"] = "warn"
            entry["enforced"] = False
            entry["warned"] = True
            log.append(entry)
            advice.append(_rule_warn_text(rule.id, match.detail, match.suggestion))
            return False

    # A `strict` match closes both per-call ways past a deny: the
    # `[airlock-ok: ...]` stamp and the loop allowance. Two rules set it. R11,
    # because both were measured being used to keep browsing on Playwright
    # (airlock/rules.py, prefilter_browser_driving). R7-root-delete, because a
    # recursive delete of / or the home directory must never pass on a stamp
    # the model writes itself. Every other rule keeps both, unchanged.
    strict = bool(match.extra.get("strict"))

    if override_reason is not None:
        if strict:
            # Logged, not honoured, so report.py's override count still means
            # "a stamp was written" and this one is visibly not a way out.
            entry["override_refused"] = True
            entry["override_reason"] = override_reason[:300]
        else:
            entry["override"] = True
            entry["override_reason"] = override_reason[:300]
            entry["enforced"] = False
            log.append(entry)
            return False

    key = (rule.id, (ctx.get("command") or json.dumps(ctx.get("tool_input"), default=str, sort_keys=True)).strip())
    if not strict and state_mod.was_recently_denied(session_id, key, LOOP_WINDOW_S):
        entry["enforced"] = False
        entry["loop_allow"] = True
        log.append(entry)
        return False

    if mode != "enforce":
        entry["enforced"] = False
        entry["would_enforce"] = True
        log.append(entry)
        return False

    emitted = effective_block_action(eff)
    if emitted != eff:
        entry["downgraded_from"] = eff
    entry["action"] = emitted
    # A strict rule still records the denial. The state write is harmless:
    # nothing reads it for this rule any more, since the loop check above is
    # skipped, and keeping it means tuning and any future reader still see one
    # row per denied call whatever the rule.
    state_mod.record_denial(session_id, key)
    entry["enforced"] = True
    entry["loop_allow"] = False
    log.append(entry)
    reason = _rule_deny_reason(rule.id, match.detail, match.suggestion, emitted, strict)
    if emitted == "ask":
        emit_ask(reason)
    else:
        emit_deny(reason)
    return True


# Two caps, on purpose. Jev's user_requested judgment reads the same
# summary as the log row, and a shorter one there would change what it
# decides (gate on jev-kit PR #5). So Jev keeps the 300-character view, and
# only the row written to shadow.jsonl is cut to 200 for the command and 120
# for the rest: enough to recognise the call when tuning, without a Bash
# heredoc turning every row into a page (Jonathan, 2026-09-22).
JEV_SUMMARY_CAP = 300
LOG_COMMAND_CAP = 200
LOG_FIELD_CAP = 120


def _input_summary(ctx, command_cap=JEV_SUMMARY_CAP, field_cap=JEV_SUMMARY_CAP):
    from . import redact
    ti = ctx.get("tool_input") or {}
    summary = {}
    if ctx.get("command"):
        summary["command"] = redact.redact_and_truncate_command(ctx["command"])[:command_cap]
    for k in ("file_path", "skill", "subagent_type", "description"):
        if ti.get(k):
            summary[k] = redact.redact(str(ti[k]))[:field_cap]
    return summary


def _log_input_summary(ctx):
    """The shorter form for the shadow log row only."""
    return _input_summary(ctx, LOG_COMMAND_CAP, LOG_FIELD_CAP)


def _confidence_and_margin(answers):
    for a in (answers or {}).values():
        if not isinstance(a, dict):
            continue
        if "choice" in a:
            return a.get("confidence"), policy.compute_margin(a.get("probabilities"))
    return None, None


def _surface_tier(entry, data, surface, session_id, mode, advice):
    """Non-blocking outcome for an over-tiered Agent dispatch. Returns True
    only when it wrote to stdout itself (a rewrite), which ends the rule loop
    -- one hook invocation produces at most one JSON document."""
    entry["enforced"] = False
    entry["loop_allow"] = False
    entry["surfaced"] = surface

    if mode != "enforce":
        # Dry run: record what would have happened, emit nothing.
        entry["surfaced"] = None
        entry["would_surface"] = surface
        log.append(entry)
        return False

    if surface == "rewrite":
        target = policy.tier_rewrite_target(entry)
        if not target:
            entry["surfaced"] = None
            log.append(entry)
            return False
        original = (data.get("tool_input") or {})
        # Every other field byte-identical: only subagent_type is touched.
        updated = dict(original)
        updated["subagent_type"] = target
        entry["action"] = "rewrite"
        entry["rewrote_from"] = entry.get("chosen_type")
        entry["rewrote_to"] = target
        text = _agent_rewrite_text(entry, target)
        log.append(entry)
        emit_rewrite(updated, text)
        return True

    entry["action"] = "warn"
    entry["warned"] = True
    log.append(entry)
    advice.append(_agent_warn_text(entry))
    return False


def _run_legacy(data, tool_name, rule, eff, base, override_reason, b_ms, session_id, mode, advice):
    """The two original guards, behaviour unchanged for action=deny. `warn`
    and `log` downgrade them to a logged row without any block."""
    guard_name = rule.legacy
    if tool_name in rules_mod.SHELL_TOOLS:
        key = ("bash", str((data.get("tool_input") or {}).get("command") or "").strip())
    else:
        key = ("agent", str((data.get("tool_input") or {}).get("description") or "").strip())

    lbase = dict(base)
    lbase.update({"guard": guard_name, "rule_id": rule.id, "action": eff})

    if override_reason is not None and eff in ("deny", "ask"):
        entry = dict(lbase)
        entry.update({
            "override": True,
            "override_reason": override_reason[:300],
            "enforced": False,
            "loop_allow": False,
            "elapsed_ms": 0,
        })
        log.append(entry)
        return False

    start = time.monotonic()
    try:
        from . import guards
        if tool_name == "Agent":
            entry = guards.compute_tier_entry(data, timeout_s=b_ms / 1000.0)
        else:
            entry = guards.compute_search_entry(data, timeout_s=b_ms / 1000.0)
    except Exception as exc:
        entry = dict(lbase)
        entry.update({
            "error": str(exc)[:300],
            "override": False,
            "loop_allow": False,
            "enforced": False,
            "elapsed_ms": int((time.monotonic() - start) * 1000),
        })
        log.append(entry)
        return False

    elapsed_ms = int((time.monotonic() - start) * 1000)
    if entry is None:
        return False

    entry.update(lbase)
    entry["elapsed_ms"] = elapsed_ms
    entry["override"] = False

    should_deny = False
    surface = None
    if "error" not in entry:
        if tool_name in rules_mod.SHELL_TOOLS:
            should_deny = policy.enforce_deny_search(entry)
        else:
            surface = policy.tier_surface(entry)
            should_deny = surface == "block"
        if elapsed_ms > b_ms:
            should_deny = False
            surface = None
            entry.setdefault("error", "budget exceeded (%dms > %dms)" % (elapsed_ms, b_ms))

    # An over-tiered dispatch too small to block used to end here as a log row
    # nobody ever saw. Now it comes back as advice, or -- only when the machine
    # has opted in -- as an edited subagent_type.
    if surface in ("warn", "rewrite") and eff in ("deny", "ask", "warn"):
        return _surface_tier(entry, data, surface, session_id, mode, advice)

    if not should_deny:
        entry["enforced"] = False
        entry["loop_allow"] = False
        log.append(entry)
        return False

    reason = (_bash_deny_reason(entry) if tool_name in rules_mod.SHELL_TOOLS
              else _agent_deny_reason(entry))

    if eff not in ("deny", "ask"):
        entry["enforced"] = False
        entry["loop_allow"] = False
        log.append(entry)
        if eff == "warn":
            advice.append(reason)
        return False

    if mode == "enforce":
        score = user_requested_score(data, rules_mod.build_ctx(data, tool_name), b_ms, entry)
        if score is not None and score >= USER_REQUESTED_SOFTEN_AT:
            entry["softened"] = "user_requested"
            entry["action"] = "warn"
            entry["enforced"] = False
            entry["warned"] = True
            log.append(entry)
            advice.append(reason)
            return False

    if state_mod.was_recently_denied(session_id, key, LOOP_WINDOW_S):
        entry["enforced"] = False
        entry["loop_allow"] = True
        log.append(entry)
        return False

    if mode != "enforce":
        entry["enforced"] = False
        entry["would_enforce"] = True
        log.append(entry)
        return False

    emitted = effective_block_action(eff)
    if emitted != eff:
        entry["downgraded_from"] = eff
    entry["action"] = emitted
    state_mod.record_denial(session_id, key)
    entry["enforced"] = True
    entry["loop_allow"] = False
    log.append(entry)
    if emitted == "ask":
        emit_ask(reason.replace("BLOCKED (airlock", "NEEDS APPROVAL (airlock", 1))
    else:
        emit_deny(reason)
    return True
