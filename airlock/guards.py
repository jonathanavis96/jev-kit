"""Guard implementations: build state, call Jev, apply policy, log.

Runs entirely inside the detached worker process (airlock/worker.py), well
after the PreToolUse hook has already exited 0. Every function here is called
from a caller that swallows all exceptions, but each also guards its own
early-outs (no API key, prefilter says no) so an ordinary "there was nothing
to judge" case never even reaches the network.
"""
import datetime
import random

from . import client, keyfile, log, policy, questions, redact, tiers
from . import scope as scope_mod

# `adequate` when the judgement never happened (the call was skipped, or the
# request failed). The row still carries every field, and `skipped`/`error`
# says which it was -- a null there was what made the live log unreadable.
NOT_JUDGED = "unknown"


def _tier_detail(chosen, adequate, task_kind, note=None):
    """One human sentence per tier row. Without it every legacy row logged
    `detail: null`, unlike every rules row, so the two could not be read the
    same way."""
    if note:
        return "Agent dispatch to '%s': %s" % (chosen or "?", note)
    return (
        "Agent dispatch to '%s'; Jev judged the task '%s', adequate at '%s'."
        % (chosen or "?", task_kind or "?", adequate or "?")
    )


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def compute_tier_entry(data, timeout_s=None):
    """Build the tier-guard log entry for one Agent dispatch, WITHOUT logging
    it -- the caller decides when/whether to log (shadow logs immediately;
    enforce mode logs once it also knows override/loop-protection/deny
    outcome, so everything lands in one row). Returns None when there is
    nothing to judge (no API key). `timeout_s`, when given, is passed through
    to client.ask as the hard budget for a synchronous (enforce-mode) call."""
    ti = data.get("tool_input") or {}
    subagent_type = str(ti.get("subagent_type") or "")
    model_override = str(ti.get("model") or "")
    judged_type = tiers.effective_type(subagent_type, model_override)
    description = redact.redact(str(ti.get("description") or ""))
    prompt = redact.redact_and_truncate_prompt(str(ti.get("prompt") or ""))

    api_key = keyfile.get_api_key()
    if not api_key:
        return None

    entry_base = {
        "ts": _now_iso(),
        "session_id": data.get("session_id"),
        "cwd": data.get("cwd"),
        "tool_name": "Agent",
        "guard": "tier_guard",
        "input_summary": {
            "subagent_type": subagent_type,
            "model_override": model_override,
            "description": description[:300],
            "prompt_head": prompt[:300],
        },
    }

    sampled = False
    if not policy.deny_possible_agent(judged_type):
        sampled = random.random() < policy.sample_rate()
        if not sampled:
            entry = dict(entry_base)
            entry["would_deny"] = False
            entry["under_tiered"] = False
            entry["skipped"] = "no_deny_possible"
            entry["chosen"] = subagent_type
            entry["chosen_type"] = subagent_type
            entry["adequate"] = NOT_JUDGED
            entry["detail"] = _tier_detail(
                subagent_type, None, None,
                note="cheapest rung ('%s'), no deny reachable, not judged"
                     % tiers.rung_names()[0])
            return entry

    state = questions.tier_state(subagent_type, model_override, description, prompt)
    qs = questions.tier_questions()

    entry = dict(entry_base)

    try:
        ask_kwargs = {"timeout_s": timeout_s} if timeout_s is not None else {}
        result, latency_ms = client.ask({"state": state, "model": client.MODEL, "questions": qs}, **ask_kwargs)
    except Exception as exc:
        entry["error"] = str(exc)[:300]
        entry["chosen"] = subagent_type
        entry["chosen_type"] = subagent_type
        entry["adequate"] = NOT_JUDGED
        entry["detail"] = _tier_detail(subagent_type, None, None,
                                       note="judgement failed (%s)" % str(exc)[:120])
        if sampled:
            entry["skipped"] = "sampled_shadow"
        return entry

    answers = result.get("answers") or {}
    entry["answers"] = answers
    entry["latency_ms"] = latency_ms
    entry["usage"] = result.get("usage")
    entry["jev_model"] = result.get("model")

    task_kind_answer = answers.get("task_kind") or {}
    task_kind = task_kind_answer.get("choice") or "unclear"
    task_kind_conf = task_kind_answer.get("confidence", 0.0)
    task_kind_margin = policy.compute_margin(task_kind_answer.get("probabilities"))
    prior_failed = (answers.get("states_prior_failed_attempts") or {}).get("noul", 0.0)

    verdict = policy.evaluate_tier(
        task_kind=task_kind,
        task_kind_confidence=task_kind_conf,
        task_kind_margin=task_kind_margin,
        states_prior_failed_attempts=prior_failed,
        chosen_type=judged_type,
    )
    entry.update(policy.tier_entry_fields(
        verdict, task_kind, task_kind_conf, task_kind_margin,
        prior_failed, judged_type, chosen_model=model_override))
    # A sampled shadow row must never look like a deny, whatever the verdict.
    entry["would_deny"] = verdict["would_deny"] and not sampled
    entry["chosen"] = subagent_type
    entry["adequate"] = verdict.get("adequate_rung") or NOT_JUDGED
    entry["detail"] = _tier_detail(subagent_type, verdict.get("adequate_rung"), task_kind)
    if sampled:
        entry["skipped"] = "sampled_shadow"

    return entry


def run_tier_guard(data):
    """PreToolUse(Agent) shadow judgement: which rung was this dispatched to,
    and was that the minimum adequate rung for the kind of task it is? Logs
    immediately (shadow mode has no override/loop-protection to wait for)."""
    entry = compute_tier_entry(data)
    if entry is not None:
        log.append(entry)
    return entry


def compute_search_entry(data, timeout_s=None):
    """Build the tool-choice-guard log entry for one Bash search command,
    WITHOUT logging it (see compute_tier_entry). Returns None when there is
    nothing to judge (not search-like, or no API key)."""
    ti = data.get("tool_input") or {}
    command = str(ti.get("command") or "")

    if not policy.bash_is_search_like(command):
        return None

    description = str(ti.get("description") or "")
    cwd = data.get("cwd") or ""

    command_r = redact.redact_and_truncate_command(command)
    description_r = redact.redact(description)

    api_key = keyfile.get_api_key()
    if not api_key:
        return None

    scope_result = scope_mod.classify_command(command, cwd)
    command_scope = scope_result["scope"]
    program = scope_result.get("program")
    has_graph = scope_mod.root_has_graphify_graph(scope_result)

    entry_base = {
        "ts": _now_iso(),
        "session_id": data.get("session_id"),
        "cwd": cwd,
        "tool_name": data.get("tool_name") or "Bash",
        "guard": "tool_choice_guard",
        "scope": command_scope,
        "input_summary": {
            "command": command_r[:300],
            "description": description_r[:300],
        },
    }

    # The POLICY parsers read `command`, not `command_r`. Redaction and the
    # 2000-character truncation exist for what leaves this machine -- the
    # Jev payload and the log line below -- and these functions send
    # nothing: they lex the command locally to decide which roots it
    # searches and whether it already reaches for an index. Handing them
    # the truncated copy denied a command that was already doing the right
    # thing, because `roots` came from the full text while the `es` stage
    # that answered them sat past the cutoff (review finding, PR #1).
    sampled = False
    if not policy.deny_possible_bash(command_scope, program, has_graph,
                                     roots=scope_result.get("roots"),
                                     command=command):
        sampled = random.random() < policy.sample_rate()
        if not sampled:
            entry = dict(entry_base)
            entry["would_deny"] = False
            entry["under_tiered"] = False
            entry["skipped"] = "no_deny_possible"
            return entry

    state = questions.bash_state(command_r, description_r, cwd, command_scope, has_graph)
    qs = questions.bash_questions()

    entry = dict(entry_base)

    try:
        ask_kwargs = {"timeout_s": timeout_s} if timeout_s is not None else {}
        result, latency_ms = client.ask({"state": state, "model": client.MODEL, "questions": qs}, **ask_kwargs)
    except Exception as exc:
        entry["error"] = str(exc)[:300]
        if sampled:
            entry["skipped"] = "sampled_shadow"
        return entry

    answers = result.get("answers") or {}
    entry["answers"] = answers
    entry["latency_ms"] = latency_ms
    entry["usage"] = result.get("usage")
    entry["jev_model"] = result.get("model")

    search_intent_answer = answers.get("search_intent") or {}
    search_intent = search_intent_answer.get("choice") or "unclear"
    search_intent_conf = search_intent_answer.get("confidence", 0.0)
    margin = policy.compute_margin(search_intent_answer.get("probabilities"))

    # The live guard is the ONE caller that detects what this machine has.
    # Everywhere else keeps policy.ASSUMED_*, so the generated policy and its
    # pinned fingerprint read the same on every host (Codex P1, PR #1).
    db_kind, has_es = policy.detect_availability()
    verdict = policy.evaluate_search(
        scope=command_scope,
        search_intent=search_intent,
        confidence=search_intent_conf,
        command=command,
        root_has_graphify_graph=has_graph,
        margin=margin,
        roots=scope_result.get("roots"),
        db_kind=db_kind,
        has_es=has_es,
    )
    entry["would_deny"] = verdict["would_deny"] and not sampled
    entry["suggestion"] = verdict.get("suggestion")
    entry["under_tiered"] = False
    entry["margin"] = margin
    # The deciding input to the graphify-suggestion deny branch of
    # evaluate_search, recorded only here: this is the one place that branch
    # was actually evaluated (a Jev call was made and its verdict computed).
    # The "no_deny_possible" skip above and the client.ask() exception path
    # never reach evaluate_search, so they never get this field -- and it is
    # never filled in by statting the filesystem after the fact, only by the
    # value the policy call above already used.
    entry["root_has_code_graph"] = has_graph
    if sampled:
        entry["skipped"] = "sampled_shadow"

    return entry


def run_tool_choice_guard(data):
    """PreToolUse(Bash) shadow judgement: is this search command reaching for
    the wrong tool (a disk-wide filename crawl, a raw grep where the repo has
    a graphify graph)? Only spends an API call once the cheap pre-filter has
    confirmed a search-like program is present. Logs immediately (shadow mode
    has no override/loop-protection to wait for)."""
    entry = compute_search_entry(data)
    if entry is not None:
        log.append(entry)
    return entry
