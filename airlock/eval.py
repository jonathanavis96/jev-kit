"""python3 -m airlock.eval -- run every labelled case in eval/cases.jsonl
through the REAL Jev call (via client.ask, which prefers the warm daemon) and
report accuracy per guard, a confusion table, false-deny/missed-deny counts,
mean latency, and total tokens.

The tier guard is scored on its THREE LIVE OUTCOMES, not on one flag
=================================================================

`policy.evaluate_tier`'s `would_deny` is the union of two different live
behaviours: a rung gap of two or more (and fable without a stated prior failed
attempt) BLOCKS, while a gap of exactly one only WARNS, and everything else --
adequate, under-tiered, or an unclear task -- is silent. Scoring one boolean
against one label cannot tell a block apart from a warn, and the tier labels in
eval/cases.jsonl had been written to the two-rung block rule while the eval
scored the wider flag. The result was 16 "false denies" and 5 "missed denies"
that were label artefacts rather than anything Jev got wrong.

So a `tier_guard` case now carries `expect_block`, `expect_warn` and
`expect_silent` (exactly one true), and this module predicts the outcome with
`policy.tier_surface` -- the same function the hook calls -- against an entry
built by `policy.tier_entry_fields`, the same builder `guards.compute_tier_entry`
uses. Rewrite mode is forced OFF, because it is off by default.

A case whose text does not determine the adequate tier carries
`ambiguous: true` and is excluded from both accuracies rather than guessed at.


Runs cases in parallel (max 4 concurrent Jev calls). Exit code is always 0 --
this is a report, not a test suite; the numbers are the output. Pass --json
to also write eval/last_result.json.
"""
import argparse
import json
import statistics
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import client, policy, questions, tiers
from . import rules as rules_mod
from . import scope as scope_mod

REPO_ROOT = Path(__file__).resolve().parent.parent

# The eval asks "does each rule classify its own cases correctly", never "is
# this rule on by default on the machine running the eval". R6 (GUI/browser)
# ships `off` on every platform -- see airlock/headless.py -- so it is pinned
# at its intended action here; every other rule is already at its default.
EVAL_OVERRIDES = {"R6-gui-or-browser": "deny"}
#: The host the rules table's expected labels were written for: gs, the shared
#: 4-core VPS. Cases are scored as if running there, whatever the runner is.
EVAL_HOST_CPUS = 4
CASES_FILE = REPO_ROOT / "eval" / "cases.jsonl"
RESULT_FILE = REPO_ROOT / "eval" / "last_result.json"

MAX_WORKERS = 4


def load_cases(path=None):
    path = Path(path) if path else CASES_FILE
    cases = []
    if not path.exists():
        return cases
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                cases.append(json.loads(line))
            except Exception:
                continue
    return cases


TIER_OUTCOMES = ("block", "warn", "silent")


def tier_outcome(subagent_type, entry):
    """What the live hook would DO with this judgement: "block", "warn" or
    "silent". `policy.tier_surface` is the hook's own function; rewrite mode is
    forced off because it is off by default, and the cheapest-rung shortcut is
    applied because `policy.deny_possible_agent` means such a call is never
    even judged."""
    if not policy.deny_possible_agent(subagent_type):
        return "silent"
    surfaced = policy.tier_surface(entry, rewrite_on=False)
    return surfaced if surfaced in TIER_OUTCOMES else "silent"


def expected_tier_outcome(expected):
    """The one of expect_block/expect_warn/expect_silent that is true, or None
    when a case carries none of them (an older cases file)."""
    for name in TIER_OUTCOMES:
        if expected.get("expect_%s" % name):
            return name
    return None


def _judge_tier(payload):
    ti = payload.get("tool_input") or {}
    subagent_type = str(ti.get("subagent_type") or "")
    model_override = str(ti.get("model") or "")
    judged_type = tiers.effective_type(subagent_type, model_override)
    description = str(ti.get("description") or "")
    prompt = str(ti.get("prompt") or "")

    state = questions.tier_state(subagent_type, model_override, description, prompt)
    qs = questions.tier_questions()
    response, latency_ms = client.ask({"state": state, "model": client.MODEL, "questions": qs})

    answers = response.get("answers") or {}
    task_kind_answer = answers.get("task_kind") or {}
    task_kind = task_kind_answer.get("choice") or "unclear"
    confidence = task_kind_answer.get("confidence", 0.0)
    margin = policy.compute_margin(task_kind_answer.get("probabilities"))
    prior_failed = (answers.get("states_prior_failed_attempts") or {}).get("noul", 0.0)

    verdict = policy.evaluate_tier(
        task_kind=task_kind,
        task_kind_confidence=confidence,
        task_kind_margin=margin,
        states_prior_failed_attempts=prior_failed,
        chosen_type=judged_type,
    )
    entry = policy.tier_entry_fields(verdict, task_kind, confidence, margin,
                                     prior_failed, judged_type, chosen_model=model_override)
    usage = response.get("usage") or {}
    tokens = (usage.get("input_tokens") or 0) + (usage.get("output_tokens") or 0)
    return {
        "predicted_label": task_kind,
        "predicted_would_deny": verdict["would_deny"],
        "predicted_outcome": tier_outcome(judged_type, entry),
        "rung_diff": verdict.get("rung_diff"),
        "confidence": confidence,
        "margin": margin,
        "latency_ms": latency_ms,
        "tokens": tokens,
    }


def _judge_bash(payload):
    ti = payload.get("tool_input") or {}
    command = str(ti.get("command") or "")
    description = str(ti.get("description") or "")
    cwd = payload.get("cwd") or ""

    scope_result = scope_mod.classify_command(command, cwd)
    has_graph = scope_mod.root_has_graphify_graph(scope_result)

    state = questions.bash_state(command, description, cwd, scope_result["scope"], has_graph)
    qs = questions.bash_questions()
    response, latency_ms = client.ask({"state": state, "model": client.MODEL, "questions": qs})

    answers = response.get("answers") or {}
    intent_answer = answers.get("search_intent") or {}
    search_intent = intent_answer.get("choice") or "unclear"
    confidence = intent_answer.get("confidence", 0.0)
    margin = policy.compute_margin(intent_answer.get("probabilities"))

    verdict = policy.evaluate_search(
        scope=scope_result["scope"],
        search_intent=search_intent,
        confidence=confidence,
        command=command,
        root_has_graphify_graph=has_graph,
        margin=margin,
        roots=scope_result.get("roots"),
    )
    usage = response.get("usage") or {}
    tokens = (usage.get("input_tokens") or 0) + (usage.get("output_tokens") or 0)
    return {
        "predicted_label": search_intent,
        "predicted_would_deny": verdict["would_deny"],
        "confidence": confidence,
        "margin": margin,
        "latency_ms": latency_ms,
        "tokens": tokens,
        "scope": scope_result["scope"],
    }


def _ask_jev(rule, ctx, match):
    state, qs = rule.questions(ctx, match)
    response, _latency = client.ask({"state": state, "model": client.MODEL, "questions": qs})
    return (response or {}).get("answers") or {}


def _judge_rules(payload, rule_id):
    """Run the rules table over one payload (real Jev for any rule whose code
    pre-filter says the fuzzy half is in doubt) and report what `rule_id` did."""
    tool_name = payload.get("tool_name") or ""
    # A case may ship a tiny transcript fixture for the questions that read
    # the user's own recent words. Relative paths resolve against the repo, so
    # nothing in eval/cases.jsonl is tied to a particular machine.
    payload = dict(payload)
    tp = payload.get("transcript_path")
    if tp and not Path(tp).is_absolute():
        payload["transcript_path"] = str(REPO_ROOT / tp)
    ctx = rules_mod.build_ctx(payload, tool_name)
    # Pin the host capacity R3 reads. Its pre-filter is silent on a roomy
    # machine, so without this the r3-* cases score as misses on any runner
    # with more cores than airlock.headless.SMALL_HOST_CPU_THRESHOLD, and the
    # per-rule accuracy number would then depend on which box ran the eval.
    ctx["cpus"] = EVAL_HOST_CPUS
    rows = rules_mod.dry_run(ctx, ask=_ask_jev, overrides=EVAL_OVERRIDES)
    mine = [r for r in rows if r["rule_id"] == rule_id]
    other = sorted({r["rule_id"] for r in rows if r["rule_id"] != rule_id and r.get("fires")})
    row = mine[0] if mine else None
    # A rule whose Jev call failed is an ERROR, not a quiet "did not fire" --
    # reporting it as a wrong answer hides a broken question set behind a
    # plausible-looking accuracy number.
    if row and row.get("error"):
        raise RuntimeError(row["error"])
    return {
        "predicted_label": (row or {}).get("action") if row and row.get("fires") else "no_fire",
        "predicted_would_deny": bool(row and row.get("fires") and row.get("action") == "deny"),
        "predicted_fires": bool(row and row.get("fires")),
        "predicted_action": (row or {}).get("action"),
        "asked": bool(row and row.get("asked")),
        "confidence": (row or {}).get("confidence"),
        "margin": (row or {}).get("margin"),
        "latency_ms": 0,
        "tokens": 0,
        "also_fired": other,
    }


def run_case(case):
    guard = case.get("guard")
    payload = case.get("payload") or {}
    expected = case.get("expected") or {}

    try:
        if guard == "tier_guard":
            judged = _judge_tier(payload)
            expected_label = expected.get("task_kind")
        elif guard == "tool_choice_guard":
            judged = _judge_bash(payload)
            expected_label = expected.get("search_intent")
        elif guard == "rules":
            rule_id = expected.get("rule_id") or case.get("rule_id")
            judged = _judge_rules(payload, rule_id)
            expected_label = expected.get("action") if expected.get("fires") else "no_fire"
        else:
            return {"id": case.get("id"), "guard": guard, "error": "unknown guard"}
    except Exception as exc:
        return {"id": case.get("id"), "guard": guard, "error": str(exc)}

    if guard == "rules":
        expected_deny = bool(expected.get("fires") and expected.get("action") == "deny")
    elif guard == "tier_guard":
        # For the tier guard "deny" means the live BLOCK outcome, which is a
        # strict subset of would_deny. Scoring against would_deny is what made
        # the one-rung warn cases look like false denies.
        expected_deny = bool(expected.get("expect_block"))
    else:
        expected_deny = bool(expected.get("would_deny"))
    result = {
        "id": case.get("id"),
        "guard": ("rules:%s" % (expected.get("rule_id") or case.get("rule_id"))) if guard == "rules" else guard,
        "expected_label": expected_label,
        "predicted_label": judged["predicted_label"],
        "label_correct": expected_label is None or expected_label == judged["predicted_label"],
        "expected_would_deny": expected_deny,
        "predicted_would_deny": judged["predicted_would_deny"],
        "deny_correct": expected_deny == judged["predicted_would_deny"],
        "confidence": judged.get("confidence"),
        "margin": judged.get("margin"),
        "latency_ms": judged.get("latency_ms"),
        "tokens": judged.get("tokens", 0),
    }
    if guard == "tier_guard":
        expected_outcome = expected_tier_outcome(expected)
        predicted_outcome = judged.get("predicted_outcome")
        result["ambiguous"] = bool(expected.get("ambiguous"))
        result["expected_outcome"] = expected_outcome
        result["predicted_outcome"] = predicted_outcome
        result["outcome_correct"] = (expected_outcome is None
                                     or expected_outcome == predicted_outcome)
        result["rung_diff"] = judged.get("rung_diff")
        # An ambiguous case is not scored, so it must not be counted wrong
        # either -- the label is the thing that could not be derived.
        if result["ambiguous"]:
            result["label_correct"] = None
        # predicted_would_deny stays the raw flag for reference; the deny that
        # is actually enforced is the block outcome.
        result["predicted_would_deny"] = (predicted_outcome == "block")
        result["deny_correct"] = expected_deny == result["predicted_would_deny"]
    return result


def run_eval(cases, max_workers=MAX_WORKERS):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for result in pool.map(run_case, cases):
            results.append(result)
    return results


def summarize(results):
    by_guard = {}
    for r in results:
        guard = r.get("guard") or "unknown"
        stats = by_guard.setdefault(guard, {
            "total": 0, "errors": 0, "label_correct": 0,
            "scored": 0, "ambiguous": 0,
            "false_deny": 0, "missed_deny": 0,
            "confusion": {}, "latencies": [], "tokens": 0,
            "outcome_confusion": {}, "per_outcome": {},
            "outcome_correct": 0, "outcome_scored": 0, "outcome_misses": [],
        })
        stats["total"] += 1
        if "error" in r:
            stats["errors"] += 1
            continue
        if r.get("ambiguous"):
            stats["ambiguous"] += 1
        else:
            stats["scored"] += 1
            if r["label_correct"]:
                stats["label_correct"] += 1
        key = "%s->%s" % (r["expected_label"], r["predicted_label"])
        stats["confusion"][key] = stats["confusion"].get(key, 0) + 1
        if r.get("expected_outcome") is not None:
            okey = "%s->%s" % (r["expected_outcome"], r["predicted_outcome"])
            stats["outcome_confusion"][okey] = stats["outcome_confusion"].get(okey, 0) + 1
            if not r.get("ambiguous"):
                per = stats["per_outcome"].setdefault(
                    r["expected_outcome"], {"expected": 0, "correct": 0})
                per["expected"] += 1
                if r["outcome_correct"]:
                    per["correct"] += 1
                    stats["outcome_correct"] += 1
                else:
                    stats["outcome_misses"].append(r)
                stats["outcome_scored"] += 1
        if r["predicted_would_deny"] and not r["expected_would_deny"]:
            stats["false_deny"] += 1
        if r["expected_would_deny"] and not r["predicted_would_deny"]:
            stats["missed_deny"] += 1
        if isinstance(r.get("latency_ms"), (int, float)):
            stats["latencies"].append(r["latency_ms"])
        stats["tokens"] += r.get("tokens", 0)

    summary = {}
    for guard, stats in by_guard.items():
        judged = stats["total"] - stats["errors"]
        scored = stats["scored"] or judged
        accuracy = (stats["label_correct"] / scored) if scored else 0.0
        mean_latency = statistics.mean(stats["latencies"]) if stats["latencies"] else 0.0
        per_outcome = {}
        for name, per in stats["per_outcome"].items():
            per_outcome[name] = {
                "expected": per["expected"],
                "correct": per["correct"],
                "accuracy": (per["correct"] / per["expected"]) if per["expected"] else 0.0,
            }
        entry = {
            "total": stats["total"],
            "judged": judged,
            "scored": scored,
            "ambiguous": stats["ambiguous"],
            "errors": stats["errors"],
            "accuracy": accuracy,
            "false_deny": stats["false_deny"],
            "missed_deny": stats["missed_deny"],
            "confusion": stats["confusion"],
            "mean_latency_ms": mean_latency,
            "total_tokens": stats["tokens"],
        }
        if stats["outcome_scored"]:
            entry["outcome_accuracy"] = stats["outcome_correct"] / stats["outcome_scored"]
            entry["outcome_scored"] = stats["outcome_scored"]
            entry["per_outcome"] = per_outcome
            entry["outcome_confusion"] = stats["outcome_confusion"]
            entry["outcome_misses"] = [
                {"id": m["id"], "expected": m["expected_outcome"],
                 "predicted": m["predicted_outcome"],
                 "expected_label": m["expected_label"],
                 "predicted_label": m["predicted_label"],
                 "confidence": m.get("confidence"), "margin": m.get("margin")}
                for m in stats["outcome_misses"]
            ]
        summary[guard] = entry
    return summary


def print_summary(summary):
    print("airlock eval results")
    print("cases file: %s" % CASES_FILE)
    print()
    for guard, s in sorted(summary.items()):
        print("== %s ==" % guard)
        print("  total=%d judged=%d scored=%d ambiguous=%d errors=%d"
              % (s["total"], s["judged"], s["scored"], s.get("ambiguous", 0), s["errors"]))
        print("  label accuracy=%.1f%%" % (s["accuracy"] * 100.0))
        if "outcome_accuracy" in s:
            print("  outcome accuracy=%.1f%% (%d scored)"
                  % (s["outcome_accuracy"] * 100.0, s["outcome_scored"]))
            for name in TIER_OUTCOMES:
                per = s["per_outcome"].get(name)
                if not per:
                    continue
                print("    %-7s expected=%-3d correct=%-3d accuracy=%.1f%%"
                      % (name, per["expected"], per["correct"], per["accuracy"] * 100.0))
        note = "  (deny == the live block outcome)" if "outcome_accuracy" in s else ""
        print("  false_deny=%d missed_deny=%d%s"
              % (s["false_deny"], s["missed_deny"], note))
        print("  mean_latency_ms=%.0f total_tokens=%d" % (s["mean_latency_ms"], s["total_tokens"]))
        print("  label confusion (expected->predicted : count):")
        for key, count in sorted(s["confusion"].items(), key=lambda kv: -kv[1]):
            print("    %-40s %d" % (key, count))
        if s.get("outcome_confusion"):
            print("  outcome confusion (expected->predicted : count):")
            for key, count in sorted(s["outcome_confusion"].items(), key=lambda kv: -kv[1]):
                print("    %-40s %d" % (key, count))
        if s.get("outcome_misses"):
            print("  cases where Jev is actually wrong under these labels:")
            for m in s["outcome_misses"]:
                print("    %-42s expected %-6s got %-6s  (label %s -> %s, conf %s, margin %s)"
                      % (m["id"], m["expected"], m["predicted"],
                         m["expected_label"], m["predicted_label"],
                         m["confidence"], m["margin"]))
        print()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="also write eval/last_result.json")
    parser.add_argument("--cases", default=None, help="override cases file path")
    parser.add_argument("--max-workers", type=int, default=MAX_WORKERS)
    args = parser.parse_args(argv)

    cases = load_cases(args.cases)
    if not cases:
        print("No cases found at %s" % (args.cases or CASES_FILE))
        return 0

    results = run_eval(cases, max_workers=args.max_workers)
    summary = summarize(results)
    print_summary(summary)

    if args.json:
        RESULT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(RESULT_FILE, "w") as f:
            json.dump({"summary": summary, "results": results}, f, indent=2, default=str)
        print("wrote %s" % RESULT_FILE)

    return 0


if __name__ == "__main__":
    sys.exit(main())
