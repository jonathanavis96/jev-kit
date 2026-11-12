#!/usr/bin/env python3
"""airlock unattended tuning loop -- one run.

Reads NEW rows from the shadow log, has a headless Claude judge them against
the current criteria, turns the ones Jev got wrong into new eval cases, asks
a second headless Claude for replacement criteria text, and only commits the
result on branch auto-tune (in a dedicated worktree, never the main working
tree) if a hard gate passes: the diff touches only airlock/questions.py and
eval/cases.jsonl, unit tests pass, and eval accuracy does not regress.

Designed to do nothing rather than something wrong: every failure mode is a
discard-and-log, never a partial commit. See tuning/README.md for the full
design and the install/promote steps a human runs separately.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# The deployed release runs this file as `<release>/tuning/tune.py`, which
# puts `tuning/` on sys.path but not the release root, so a bare
# `import airlock` would fail. Put the release (or checkout) root first, so
# the redaction sanity check below can use the very same redactor that wrote
# the rows rather than a second, divergent copy of the rules.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    from airlock import paths as _paths
except Exception:  # pragma: no cover - only if the tree is broken
    _paths = None
try:
    from airlock.redact import redact as _redact
except Exception:  # pragma: no cover - only if the tree is broken
    _redact = None
try:
    from airlock import policy as _policy
except Exception:  # pragma: no cover - only if the tree is broken
    _policy = None

from tuning import sampling
from tuning import verdicts as verdict_store

try:
    from tuning import policy_text as _policy_text
except Exception:  # pragma: no cover - only if the tree is broken
    _policy_text = None

HOME = Path(os.environ.get("HOME") or os.path.expanduser("~"))


def _default_state_dir():
    if _paths is not None:
        try:
            return Path(_paths.state_dir())
        except Exception:
            pass
    return HOME / ".local" / "state" / "airlock"


def _default_config_dir():
    if _paths is not None:
        try:
            return Path(_paths.config_dir())
        except Exception:
            pass
    return HOME / ".config" / "airlock"


def _refresh_paths():
    """(Re)compute every path constant from the CURRENT environment.

    They are computed once at import too, so module-level readers keep
    working; main() calls this again so that a caller -- a test, or a hand
    run with AIRLOCK_STATE_DIR/AIRLOCK_CONFIG_DIR pointed at throwaway
    directories -- is actually obeyed instead of losing to import order.
    """
    global HOME, STATE_DIR, STATE_FILE, TUNE_LOG_FILE, WORKTREE_DIR
    global SHADOW_LOG_FILE, CONFIG_DIR, DISABLED_FILE, TUNING_DISABLED_FILE
    HOME = Path(os.environ.get("HOME") or os.path.expanduser("~"))
    STATE_DIR = Path(os.environ.get("AIRLOCK_TUNE_STATE_DIR") or _default_state_dir())
    STATE_FILE = STATE_DIR / "tune_state.json"
    TUNE_LOG_FILE = STATE_DIR / "tune_log.jsonl"
    WORKTREE_DIR = Path(
        os.environ.get("AIRLOCK_TUNE_WORKTREE_DIR") or (STATE_DIR / "tune-worktree")
    )
    SHADOW_LOG_FILE = Path(
        os.environ.get("AIRLOCK_TUNE_SHADOW_LOG") or (_default_state_dir() / "shadow.jsonl")
    )
    CONFIG_DIR = _default_config_dir()
    DISABLED_FILE = CONFIG_DIR / "disabled"
    TUNING_DISABLED_FILE = CONFIG_DIR / "tuning-disabled"


_refresh_paths()


# --- which claude binary, which account, which model ----------------------
#
# The unattended failure this exists to stop: a systemd user unit runs with a
# minimal PATH (typically /usr/bin:/bin) that does not contain the npm global
# prefix the `claude` CLI is installed under, so the judge call died with
# "[Errno 2] No such file or directory: 'claude'" on every timer firing --
# while the same script run by hand from a login shell worked, which is
# exactly why it looked healthy. Resolution lives in ONE function so the
# installer, doctor.sh and the run itself all agree on the answer.

JUDGE_BIN_ENV = ("AIRLOCK_TUNE_CLAUDE_BIN", "AIRLOCK_CLAUDE_BIN")


def _judge_bin_candidate_dirs():
    """Usual per-user install locations for the `claude` CLI, in the order a
    login shell would normally find them. No shell is sourced: nvm is read
    from its directory layout, never by running `nvm use`."""
    dirs = [
        HOME / ".npm-global" / "bin",
        HOME / ".local" / "bin",
        HOME / ".claude" / "local",
        HOME / "bin",
        HOME / ".bun" / "bin",
        HOME / ".yarn" / "bin",
    ]
    nvm_dir = Path(os.environ.get("NVM_DIR") or (HOME / ".nvm"))
    dirs.append(nvm_dir / "current" / "bin")
    try:
        versions = sorted((nvm_dir / "versions" / "node").iterdir())
    except Exception:
        versions = []
    for version in reversed(versions):
        dirs.append(version / "bin")
    return dirs


def _is_executable(path):
    try:
        return os.path.isfile(str(path)) and os.access(str(path), os.X_OK)
    except Exception:
        return False


def resolve_judge_bin():
    """Return (path_to_claude or None, list_of_places_searched).

    Order: an explicit override from the environment (which is how
    $AIRLOCK_CONFIG_DIR/tune.env reaches us, since tune.sh sources it), then
    PATH, then the usual per-user install locations. First executable wins.
    Never raises."""
    searched = []
    for name in JUDGE_BIN_ENV:
        value = os.environ.get(name)
        if not value:
            continue
        searched.append("$%s=%s" % (name, value))
        expanded = os.path.expanduser(value)
        if os.sep in expanded:
            if _is_executable(expanded):
                return expanded, searched
        else:
            found = shutil.which(expanded)
            if found:
                return found, searched
    searched.append("PATH=%s" % (os.environ.get("PATH", "") or "<empty>"))
    found = shutil.which("claude")
    if found:
        return found, searched
    for directory in _judge_bin_candidate_dirs():
        candidate = directory / "claude"
        searched.append(str(candidate))
        if _is_executable(candidate):
            return str(candidate), searched
    return None, searched


def resolve_claude_config_dir():
    """Which Claude account tree the tuning judge bills.

    A box with a single login leaves every one of these unset and gets
    ~/.claude; a box with several records its own value in
    $AIRLOCK_CONFIG_DIR/tune.env or install/config.env (see
    install/config.env.example). No account directory is baked in here.
    """
    return (
        os.environ.get("AIRLOCK_TUNE_CLAUDE_CONFIG_DIR")
        or os.environ.get("PLUMBLINE_TUNE_CLAUDE_CONFIG_DIR")
        or os.environ.get("JEV_TUNE_CLAUDE_CONFIG_DIR")
        or os.environ.get("CLAUDE_CONFIG_DIR")
        or str(HOME / ".claude")
    )


# Judge and criteria-rewrite calls share the same model/effort: a much more
# expensive judge is only worth it if it is also the one rewriting criteria
# from what it found wrong. Opus at high effort is the default because a
# cheaper judge is exactly what auto-tune exists to correct for -- Sonnet at
# low/medium was cheap but also the thing most likely to rubber-stamp Jev's
# own mistakes. Both are read live so tune.env can override them.
DEFAULT_JUDGE_MODEL = "opus"
DEFAULT_JUDGE_EFFORT = "high"


def judge_model():
    return os.environ.get("AIRLOCK_TUNE_JUDGE_MODEL") or DEFAULT_JUDGE_MODEL


def judge_effort():
    return os.environ.get("AIRLOCK_TUNE_JUDGE_EFFORT") or DEFAULT_JUDGE_EFFORT


BASE_BRANCH = os.environ.get("AIRLOCK_TUNE_BASE_BRANCH") or "main"

MIN_INTERVAL_MIN = 30
MAX_INTERVAL_MIN = 1440
DEFAULT_MIN_ROWS = 10
# Lowered from 40: the judge is now Opus-high, a much more expensive call
# per row, so each run's row cap is halved to keep run cost in check.
MAX_JUDGE_ROWS = 20
MAX_CASES = 400

TIER_QUESTION_IDS = {"task_kind"}
BASH_QUESTION_IDS = {"search_intent"}

# --- run categories -------------------------------------------------------
#
# Every run records exactly one of these, so `tail tune_log.jsonl` answers
# "is tuning alive?" at a glance instead of needing the reason strings read
# and interpreted. doctor.sh prints the newest one and its age.
CATEGORY_DID_NOT_RUN = "did_not_run"        # interval not elapsed, or disabled
CATEGORY_COULD_NOT_RUN = "could_not_run"    # no judge binary, no repo, no worktree
CATEGORY_RAN_NOTHING = "ran_nothing"        # ran, found nothing worth changing
CATEGORY_RAN_REJECTED = "ran_rejected"      # ran, produced a change, gate discarded it
CATEGORY_RAN_COMMITTED = "ran_committed"    # ran, committed to auto-tune

CATEGORY_BLURB = {
    CATEGORY_DID_NOT_RUN: "did not run",
    CATEGORY_COULD_NOT_RUN: "could not run",
    CATEGORY_RAN_NOTHING: "ran, nothing to change",
    CATEGORY_RAN_REJECTED: "ran, gate rejected",
    CATEGORY_RAN_COMMITTED: "ran, committed",
}


def log(msg):
    print("[tune] %s" % msg, file=sys.stderr)


# Facts a run learns as it goes that EVERY later log entry should carry --
# how it sampled, how many rows the judge declined, where the verdicts went.
# Held here so the dozen `_finish` call sites do not each have to remember.
_RUN_EXTRA = {}


def _int_env(name):
    """An optional integer from the environment. A bad value is None, never a
    crash: a sampling seed is a debugging aid, not a reason to lose a run."""
    raw = os.environ.get(name)
    if not raw:
        return None
    try:
        return int(raw)
    except Exception:
        return None


# --- state -------------------------------------------------------------


def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"interval_min": MIN_INTERVAL_MIN, "last_run_epoch": 0, "last_processed_ts": ""}


def save_state(state):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(STATE_FILE)


def append_tune_log(entry):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with open(TUNE_LOG_FILE, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")


# --- shadow rows ---------------------------------------------------------


def read_shadow_rows():
    rows = []
    if not SHADOW_LOG_FILE.exists():
        return rows
    with open(SHADOW_LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def new_rows_since(rows, last_processed_ts):
    if not last_processed_ts:
        return rows
    return [r for r in rows if str(r.get("ts", "")) > last_processed_ts]


# --- git worktree management ---------------------------------------------


def run(cmd, cwd=None, check=True, input_text=None, timeout=None):
    proc = subprocess.run(
        cmd, cwd=cwd, check=False, capture_output=True, text=True,
        input=input_text, timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            "command failed (%s): %s\nstdout:\n%s\nstderr:\n%s"
            % (proc.returncode, " ".join(cmd), proc.stdout, proc.stderr)
        )
    return proc


def resolve_main_repo(script_dir):
    """The git checkout the tuning loop operates on, or None.

    Delegates to `airlock.repo_path.resolve_repo`, the one place this order is
    written down: AIRLOCK_TUNE_REPO env -> the repo.path pointer the installer
    records -> script_dir's own parent if THAT is a git checkout -> None. A
    deployed release (script_dir under $AIRLOCK_HOME/current/tuning, no
    .git anywhere in it) resolves via the pointer or not at all; a plain
    checkout resolves via its own parent with no pointer needed.
    """
    repo_root = Path(script_dir).resolve().parent
    sys.path.insert(0, str(repo_root))
    from airlock import (
        repo_path as _repo_path,  # local import: sys.path just set up above
    )

    resolved = _repo_path.resolve_repo(script_dir)
    return Path(resolved).resolve() if resolved else None


def _worktree_belongs_to(worktree_dir, repo_dir):
    """True iff `worktree_dir` is a linked worktree of `repo_dir` (its own
    main checkout is `repo_dir`, per `git worktree list` run from inside it).
    False (never raises) for anything else, including a directory that isn't
    a git worktree at all."""
    if not (worktree_dir / ".git").exists():
        return False
    proc = run(["git", "-C", str(worktree_dir), "worktree", "list", "--porcelain"], check=False)
    if proc.returncode != 0:
        return False
    for line in proc.stdout.splitlines():
        if line.startswith("worktree "):
            try:
                return Path(line[len("worktree "):].strip()).resolve() == Path(repo_dir).resolve()
            except Exception:
                return False
    return False


def retire_foreign_worktree(worktree_dir):
    """Move a tune-worktree that belongs to a DIFFERENT repository aside
    rather than reusing or deleting it -- it may hold auto-tune commits worth
    keeping around for inspection. tune_state.json (the interval backoff)
    lives in STATE_DIR, not inside the worktree, so it is untouched."""
    retired = worktree_dir.parent / ("%s.retired-%d" % (worktree_dir.name, int(time.time())))
    worktree_dir.rename(retired)
    log("existing tune-worktree at %s belongs to a different repository; moved it aside to %s" % (worktree_dir, retired))
    return retired


def ensure_tune_worktree(main_repo):
    if WORKTREE_DIR.exists():
        if not _worktree_belongs_to(WORKTREE_DIR, main_repo):
            retire_foreign_worktree(WORKTREE_DIR)
        else:
            # Rebase auto-tune onto the base branch. On conflict, abort and report.
            run(["git", "-C", str(WORKTREE_DIR), "fetch", str(main_repo), "%s:refs/heads/tune-main-ref" % BASE_BRANCH])
            proc = run(
                ["git", "-C", str(WORKTREE_DIR), "rebase", "refs/heads/tune-main-ref"],
                check=False,
            )
            if proc.returncode != 0:
                run(["git", "-C", str(WORKTREE_DIR), "rebase", "--abort"], check=False)
                raise RuntimeError("rebase of auto-tune onto %s conflicted; aborted:\n%s" % (BASE_BRANCH, proc.stdout))
            return
    WORKTREE_DIR.parent.mkdir(parents=True, exist_ok=True)
    # Branch may already exist (e.g. worktree dir was removed manually).
    proc = run(["git", "-C", str(main_repo), "branch", "--list", "auto-tune"], check=False)
    if proc.stdout.strip():
        run(["git", "worktree", "add", str(WORKTREE_DIR), "auto-tune"], cwd=str(main_repo))
    else:
        run(["git", "worktree", "add", "-b", "auto-tune", str(WORKTREE_DIR), BASE_BRANCH], cwd=str(main_repo))


def worktree_diff_files():
    proc = run(["git", "-C", str(WORKTREE_DIR), "diff", "--name-only"], check=False)
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def worktree_discard_changes():
    run(["git", "-C", str(WORKTREE_DIR), "checkout", "--"] + ["."], check=False)
    run(["git", "-C", str(WORKTREE_DIR), "clean", "-fd", "eval/", "airlock/"], check=False)


# --- redaction sanity (rows are already redacted at log time; belt+braces) -
#
# This check used to be a substring search for the literals "apikey_" and
# "sk-". It was wrong twice over, and it killed three live runs outright:
#
#   * "sk-" is a substring of ordinary text. The live shadow log contains
#     `disk-wide` (a scope word this project uses constantly) and `mask a
#     disk-wide find`, neither of which is a secret.
#   * Worse, it fired on correctly redacted material. Every "apikey_" hit in
#     the live log was the literal source of a REDACTION command -- e.g.
#     `sed 's/apikey_[A-Za-z0-9_]*/[REDACTED]/g'` -- because redact()'s own
#     `apikey_[A-Za-z0-9_]+` needs at least one following word character and
#     `[` is not one. So the check tripped on the pattern text of the thing
#     that does the redacting.
#
# Both directions of the error came from a hand-maintained second list of
# what a secret looks like. There is exactly one such list, airlock/redact.py,
# so ask IT: a row is clean when running the real redactor over it changes
# nothing, i.e. nothing secret-shaped survived. Over the live log that takes
# 1140 rows down from "23 rows tripped, every one benign" to 2 rows, both a
# long base64-ish run inside a file path.
#
# A row that does trip is SKIPPED and counted; it never aborts the run.


def redaction_residue(obj):
    """Return the substrings of `obj` that airlock's redactor would still
    remove, i.e. secret-shaped material that survived log-time redaction.
    Empty list means the row is clean. Never raises."""
    try:
        text = json.dumps(obj, default=str)
    except Exception:
        return ["<row is not serialisable>"]
    if _redact is None:
        # No redactor importable: we cannot prove the row is clean, so we
        # must not claim it is. Callers treat this as "skip the row".
        return ["<airlock.redact unavailable>"]
    try:
        cleaned = _redact(text)
    except Exception:
        return ["<redactor raised>"]
    if cleaned == text:
        return []
    return ["<%d char(s) of secret-shaped text survived redaction>" % abs(len(text) - len(cleaned))]


def _looks_redacted(obj):
    """Back-compat wrapper: True when the row carries no redaction residue."""
    return not redaction_residue(obj)


# --- headless Claude judge calls ------------------------------------------


def _run_claude(prompt, effort, model="sonnet", bin_path=None):
    if bin_path is None:
        bin_path, searched = resolve_judge_bin()
        if bin_path is None:
            raise RuntimeError("no judge binary found; searched: %s" % "; ".join(searched))
    env = dict(os.environ)
    env["CLAUDE_CONFIG_DIR"] = resolve_claude_config_dir()
    cmd = [
        bin_path, "-p", prompt,
        "--model", model,
        "--effort", effort,
        "--safe-mode",
        "--tools", "",
    ]
    proc = subprocess.run(
        cmd, env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=300,
    )
    if proc.returncode != 0:
        raise RuntimeError("claude call failed (%s): %s" % (proc.returncode, proc.stderr[:2000]))
    return proc.stdout


def _extract_json(text):
    text = text.strip()
    start = None
    for i, ch in enumerate(text):
        if ch in "{[":
            start = i
            break
    if start is None:
        raise ValueError("no JSON object/array found in claude output")
    # Use raw_decode so trailing prose/fences after the JSON value (or a
    # closing ``` fence) don't turn a valid answer into a parse error.
    decoder = json.JSONDecoder()
    value, _ = decoder.raw_decode(text, start)
    return value


RUBRIC_SUMMARY = """
Guard rubrics (both guards judge a single narrow question about one tool call):

tier_guard.task_kind options: lookup, mechanical_edit, scoped_implementation,
judgement, hard_problem, unclear. lookup = a fact already on disk, no edits.
mechanical_edit = a rename/format/boilerplate/one-line change with zero
ambiguity. scoped_implementation = a specified feature/test/refactor/bugfix
whose approach is already decided. judgement = ambiguous requirements, an
architecture decision, an unknown root cause, or reviewing another agent's
work. hard_problem = the prompt explicitly names a prior failed attempt at
this exact task. unclear = not enough information to tell.

tool_choice_guard.search_intent options: filename_search, code_structure_search,
literal_text_search, not_a_search, unclear. filename_search = matches file
NAMES, not contents. code_structure_search = the pattern is shaped like code
syntax (a definition, a call, an import, a type) -- a DEFINITION search is
always code_structure_search even via grep. literal_text_search = an exact
error message, config key/value, log line, or filtering piped stdout.
not_a_search = find -delete, du, tree with no pattern, grep -c just counting.
unclear = not enough information.

Scope (disk_wide/single_repo/single_dir/stdin/unknown) is decided in CODE, not
by the model -- every tool_choice_guard row below already carries its own
code-computed "scope" field as ground truth. Treat it as given and judge
search_intent only; do not re-derive or second-guess scope.
""".strip()


# Keys stripped from a row before it is shown to the judge: internal
# bookkeeping this module added, never part of the evidence.
INTERNAL_ROW_KEYS = ("_sample_rule",)


def _judge_row(row, index):
    """One row as the judge sees it: the log entry, minus our bookkeeping,
    plus a stable id so verdicts can be matched back even if the model
    reorders them."""
    out = {k: v for k, v in row.items() if k not in INTERNAL_ROW_KEYS}
    out["id"] = row.get("id") or "row-%d" % index
    return out


def guard_policy_text():
    """The real, code-generated policy block. Falls back to a loud marker
    rather than silently shipping a prompt with no policy in it at all --
    which is the failure this whole module exists to stop."""
    if _policy_text is None:  # pragma: no cover - only if the tree is broken
        return ("POLICY TEXT UNAVAILABLE: airlock could not be imported. Judge "
                "the LABEL only and answer cannot_tell for every question about "
                "the action taken.")
    try:
        return _policy_text.policy_text()
    except Exception as exc:  # pragma: no cover
        return ("POLICY TEXT UNAVAILABLE (%s). Judge the LABEL only and answer "
                "cannot_tell for every question about the action taken." % exc)


JUDGE_TASK = """
You are auditing a shadow-mode AI guard for correctness. Each row below is one
already-redacted log entry: a guard name, the input it judged, what Jev (a
small classifier) answered, and what the guard then did.

Judge TWO separate things per row, and never let one decide the other:

  A. THE LABEL. Given the rubric, was the option Jev chose the right one for
     this input? This is about classification only.

  B. THE ACTION TAKEN. Given the policy above and the fields on the row, did
     the guard do the right thing? An action can be right while the label is
     wrong (the policy may not have reached that answer at all), and the label
     can be right while the action is wrong. Silence is an action, and below
     the bar it is the CORRECT one.

You may -- and should -- answer "cannot tell" rather than guess. Set
"cannot_tell": true when the row does not carry what the question needs: no
Jev answer, no input summary, a question your rubric does not cover, or a
field you would have to invent. A cannot_tell is not counted against the
guard and is not counted against you. Guessing is.

Respond with ONLY a JSON array, no prose before or after, one object per row
in the same order, each shaped exactly like:
{"id": "<the row's id>", "guard": "<guard>", "correct_label": "<option name or null>",
 "label_correct": true|false|null, "action_correct": true|false|null,
 "cannot_tell": true|false, "reason": "<one line>"}
""".strip()


def build_judge_prompt(rows):
    rows_json = json.dumps(
        [_judge_row(r, i) for i, r in enumerate(rows)], indent=2, default=str
    )
    return (
        guard_policy_text()
        + "\n\n"
        + RUBRIC_SUMMARY
        + "\n\n"
        + JUDGE_TASK
        + "\n\nRows (JSON array):\n"
        + rows_json
        + "\n"
    )


def normalise_verdict(verdict, row, index):
    """One judge answer, reduced to the fields this run acts on.

    `wrong` is deliberately the union of "the label was wrong" and "the action
    was wrong", with cannot_tell winning over both: the previous run counted a
    row as wrong whenever the judge did not say true, which turned every
    unanswerable row into a guard error."""
    if not isinstance(verdict, dict):
        verdict = {}
    cannot_tell = bool(verdict.get("cannot_tell"))
    label_correct = verdict.get("label_correct")
    action_correct = verdict.get("action_correct")
    if label_correct is None and action_correct is None and not cannot_tell:
        # A judge that answered neither has told us nothing. That is a
        # cannot_tell, not a guard error.
        cannot_tell = True
    answers = row.get("answers") or {}
    question = next((q for q in sampling.RUBRIC_QUESTIONS if q in answers), None)
    jev_label = None
    if question:
        jev_label = (answers.get(question) or {}).get("choice")
    wrong = (not cannot_tell) and (label_correct is False or action_correct is False)
    return {
        "id": row.get("id") or "row-%d" % index,
        "ts": row.get("ts"),
        "guard": row.get("guard"),
        "sample_rule": row.get("_sample_rule"),
        "question": question,
        "jev_label": jev_label,
        "correct_label": verdict.get("correct_label"),
        "label_correct": None if cannot_tell else label_correct,
        "action_taken": describe_action(row),
        "action_correct": None if cannot_tell else action_correct,
        "cannot_tell": cannot_tell,
        "wrong": wrong,
        "reason": str(verdict.get("reason", ""))[:300],
    }


def _row_confidence(row, question):
    """Jev's confidence for one question. Older rows put it only inside
    `answers`; newer ones also mirror it at the top level. Read both."""
    answer = (row.get("answers") or {}).get(question) or {}
    if answer.get("confidence") is not None:
        return answer.get("confidence")
    if question == "task_kind":
        return row.get("task_kind_confidence")
    return row.get("confidence")


def expected_case_fields(row, guard, correct_label):
    """The `expected` block for a new eval case built from a shadow row.

    The old version copied `would_deny` straight off the row, which recorded
    what the guard DID as what it SHOULD have done -- on a row the judge had
    just called wrong. The deny expectation is now re-derived from the live
    policy given the corrected label, and when the row does not carry what
    the policy needs, it is left out entirely rather than guessed. Returns
    None when even the label cannot be stated.
    """
    if not correct_label:
        return None
    if guard == "tier_guard":
        expected = {"task_kind": correct_label}
        chosen = row.get("chosen_type") or row.get("chosen")
        if _policy is not None and chosen:
            try:
                verdict = _policy.evaluate_tier(
                    correct_label,
                    _row_confidence(row, "task_kind"),
                    row.get("prior_failed"),
                    chosen,
                    task_kind_margin=row.get("margin"),
                )
                entry = _policy.tier_entry_fields(
                    verdict, correct_label, _row_confidence(row, "task_kind"),
                    row.get("margin"), row.get("prior_failed"), chosen,
                )
                expected["expect_block"] = bool(_policy.enforce_deny_tier(entry))
                expected["would_deny"] = bool(verdict.get("would_deny"))
            except Exception:
                expected["deny_expectation"] = "unverified"
        else:
            expected["deny_expectation"] = "unverified"
        return expected

    expected = {"search_intent": correct_label}
    scope = row.get("scope")
    command = (row.get("input_summary") or {}).get("command")
    if _policy is None or scope is None or command is None:
        expected["deny_expectation"] = "unverified"
        return expected
    recorded_graph = row.get("root_has_code_graph")
    if recorded_graph is not None:
        # The row itself carries the deciding input -- the value the policy
        # actually used when this branch was evaluated. Prefer it over any
        # inference.
        graph_present = bool(recorded_graph)
    elif correct_label == "code_structure_search" and row.get("search_intent") != correct_label:
        # Denying here turns on whether the search root has a graphify graph.
        # This row predates that field, or the branch was never evaluated,
        # and the label just changed under the corrected answer -- nothing
        # honest to infer. Say so instead of picking one.
        expected["deny_expectation"] = "unverified"
        return expected
    else:
        graph_present = bool(row.get("would_deny")) and \
            (row.get("answers") or {}).get("search_intent", {}).get("choice") == "code_structure_search"
    try:
        verdict = _policy.evaluate_search(
            scope, correct_label, _row_confidence(row, "search_intent"), command,
            graph_present,
            margin=row.get("margin"),
        )
        expected["would_deny"] = bool(verdict.get("would_deny"))
    except Exception:
        expected["deny_expectation"] = "unverified"
    return expected


def describe_action(row):
    """What the guard ACTUALLY did, from the row's own outcome fields -- not
    from `action`, which is the rule's configured action and says nothing
    about this call."""
    if row.get("skipped"):
        return "skipped:%s" % row.get("skipped")
    if row.get("enforced"):
        return "blocked"
    if row.get("warned"):
        return "warned"
    if row.get("would_deny"):
        return "flagged_would_deny_not_enforced"
    return "allowed_silently"


QUESTION_FN_NAMES = {"task_kind": "tier_questions", "search_intent": "bash_questions"}


def allowed_criteria_options(source):
    """Map question id -> the option names its criteria dict actually has,
    read from questions.py itself rather than from a hand-kept list here.

    This is what the criteria prompt shows the judge and what
    apply_criteria_replacement enforces, so the two can never drift: a live
    run was lost to `unknown option 'not_for' for question 'search_intent'`,
    a key the judge invented because nothing had told it what the real ones
    were. Returns {} if the source cannot be parsed."""
    import ast

    out = {}
    try:
        tree = ast.parse(source)
    except Exception:
        return out
    for question_id, fn_name in QUESTION_FN_NAMES.items():
        for node in ast.walk(tree):
            if not (isinstance(node, ast.FunctionDef) and node.name == fn_name):
                continue
            for sub in ast.walk(node):
                if not (isinstance(sub, ast.Return) and isinstance(sub.value, ast.Dict)):
                    continue
                for k, v in zip(sub.value.keys, sub.value.values):
                    if not (isinstance(k, ast.Constant) and k.value == question_id):
                        continue
                    if not isinstance(v, ast.Dict):
                        continue
                    for ck, cv in zip(v.keys, v.values):
                        if isinstance(ck, ast.Constant) and ck.value == "criteria" and isinstance(cv, ast.Dict):
                            out[question_id] = [
                                key.value for key in cv.keys
                                if isinstance(key, ast.Constant) and isinstance(key.value, str)
                            ]
                break
            break
    return out


def build_criteria_prompt(current_questions_source, wrong_cases, docs_summary):
    wrong_json = json.dumps(wrong_cases, indent=2, default=str)
    allowed = allowed_criteria_options(current_questions_source)
    if allowed:
        allowed_text = (
            "The ONLY keys you may use are these, exactly as written. Any "
            "other key is dropped and wasted:\n"
            + "".join(
                "  %s: %s\n" % (qid, ", ".join(opts))
                for qid, opts in sorted(allowed.items())
            )
            + "\n"
        )
    else:
        allowed_text = ""
    return (
        "You are improving the CRITERIA TEXT of a TypeSafe System One Choice "
        "question, based on cases the model got wrong. Do not change option "
        "names, question ids, or add/remove options -- only sharpen the "
        "wording of the criteria for options that are being confused.\n\n"
        + allowed_text
        + docs_summary + "\n\n"
        "Current airlock/questions.py source (for context only):\n"
        "```python\n" + current_questions_source + "\n```\n\n"
        "Cases the model got wrong (each has the command/prompt, the wrong "
        "answer, and the correct label):\n" + wrong_json + "\n\n"
        "Respond with ONLY a JSON object, no prose, shaped exactly like:\n"
        '{"task_kind": {"<option_name>": "<new criteria text>", ...}, '
        '"search_intent": {"<option_name>": "<new criteria text>", ...}}\n'
        "Include only the options you are actually changing. Criteria text "
        "may be a plain string (it will replace the option's current value "
        "verbatim, whatever shape it was before)."
    )


DOCS_GUIDANCE_SUMMARY = (
    "TypeSafe guidance: give each Choice option a concrete description; when "
    "two options are confused, describe each with what it covers, what "
    "belongs to a neighbouring option instead, and 1-3 concrete examples, "
    "using the same field names across options so they can be compared "
    "directly. Ask the narrow fuzzy question only; anything decidable from "
    "code (like scope) should not be re-litigated in the criteria text."
)


# --- applying a criteria replacement (AST-based, criteria text only) -------


def apply_criteria_replacement(source, replacements):
    """Replace only the criteria VALUE nodes for named options inside
    tier_questions()/bash_questions(), leaving every other structure, key,
    option name, and formatting untouched. Returns the new source, or raises
    if a referenced question id / option name cannot be found (fail loud
    rather than silently no-op).

    Implemented as a source-level splice using each target node's own
    (lineno, col_offset, end_lineno, end_col_offset), not ast.unparse of the
    whole tree -- ast.unparse is semantically correct but reformats every
    line, which would turn a hand-written, human-reviewable diff into a
    wall of noise. Splicing only the changed spans keeps the diff to exactly
    the criteria text that changed."""
    import ast

    tree = ast.parse(source)
    question_fn_names = QUESTION_FN_NAMES

    def find_dict_value_for_key(dict_node, key_name):
        for k, v in zip(dict_node.keys, dict_node.values):
            if isinstance(k, ast.Constant) and k.value == key_name:
                return v
        return None

    # Collect (node_to_replace, new_text) targets first; only splice the
    # source afterwards, in reverse position order, so earlier edits never
    # invalidate the offsets of edits still to come.
    targets = []
    applied = set()
    skipped = []

    for question_id, option_map in replacements.items():
        fn_name = question_fn_names.get(question_id)
        if not fn_name:
            skipped.append((question_id, None, "unknown question id"))
            continue
        fn_node = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == fn_name:
                fn_node = node
                break
        if fn_node is None:
            raise ValueError("could not find function %s in questions.py" % fn_name)

        # Find the Return statement's dict, then [question_id]["criteria"].
        top_dict = None
        for node in ast.walk(fn_node):
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
                top_dict = node.value
                break
        if top_dict is None:
            raise ValueError("could not find return dict in %s" % fn_name)

        question_spec = find_dict_value_for_key(top_dict, question_id)
        if question_spec is None or not isinstance(question_spec, ast.Dict):
            raise ValueError("could not find question %r in %s" % (question_id, fn_name))

        criteria_dict = find_dict_value_for_key(question_spec, "criteria")
        if criteria_dict is None or not isinstance(criteria_dict, ast.Dict):
            raise ValueError("could not find criteria dict for %r" % question_id)

        if not isinstance(option_map, dict):
            raise ValueError("replacement for %r is not an object of options" % question_id)

        for option_name, new_text in option_map.items():
            # Be lenient about a judge model wandering off-schema (an unknown
            # option name, or a value that isn't plain text): skip and note
            # it rather than discarding an otherwise-good run over one bad
            # key. Skipped edits still respect "criteria text only" -- they
            # just don't happen.
            if not isinstance(new_text, str):
                skipped.append((question_id, option_name, "value is not a string"))
                continue
            found = False
            for i, k in enumerate(criteria_dict.keys):
                if isinstance(k, ast.Constant) and k.value == option_name:
                    node = criteria_dict.values[i]
                    if not hasattr(node, "end_lineno"):
                        skipped.append((question_id, option_name, "AST node has no end position"))
                        found = True  # known option, just can't splice it
                        break
                    targets.append((node, new_text))
                    found = True
                    applied.add((question_id, option_name))
                    break
            if not found:
                skipped.append((question_id, option_name, "unknown option name"))

    lines = source.splitlines(keepends=True)

    def offset(lineno, col):
        """Absolute character offset into `source` for a 1-indexed line and
        0-indexed column, as ast gives them."""
        return sum(len(line) for line in lines[: lineno - 1]) + col

    # Replace furthest-in-the-file first so earlier offsets stay valid.
    targets.sort(key=lambda t: (t[0].lineno, t[0].col_offset), reverse=True)

    new_source = source
    for node, new_text in targets:
        start = offset(node.lineno, node.col_offset)
        end = offset(node.end_lineno, node.end_col_offset)
        replacement_literal = repr(new_text)
        new_source = new_source[:start] + replacement_literal + new_source[end:]

    # Confirm the spliced result is still valid Python before handing it back.
    ast.parse(new_source)
    return new_source, applied, skipped


# --- case dedupe / capping -------------------------------------------------


def case_tool_input(row, guard):
    """The tool_input an eval case replays, from a shadow row's input_summary.

    The tier guard logs the prompt as `prompt_head` and the model as
    `model_override`, but the eval and normalize_key read `prompt` and
    `model`. Copied as-is, every tier case judged an empty prompt and all of
    them for one subagent_type deduplicated to a single case."""
    ti = dict(row.get("input_summary") or {})
    if guard == "tier_guard":
        if "prompt" not in ti and "prompt_head" in ti:
            ti["prompt"] = ti.pop("prompt_head")
        if "model" not in ti and "model_override" in ti:
            model = ti.pop("model_override")
            if model:
                ti["model"] = model
    return ti


def normalize_key(case):
    payload = case.get("payload") or {}
    ti = payload.get("tool_input") or {}
    if case.get("guard") == "tier_guard":
        raw = (ti.get("subagent_type", ""), ti.get("prompt", ""))
    else:
        raw = (ti.get("command", ""),)
    return hashlib.sha256(json.dumps(raw, default=str).encode("utf-8")).hexdigest()


def load_cases(path):
    cases = []
    if not path.exists():
        return cases
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def write_cases(path, cases):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.writelines(json.dumps(c, default=str) + "\n" for c in cases)


def merge_new_cases(existing_cases, new_cases):
    seen = {normalize_key(c) for c in existing_cases}
    merged = list(existing_cases)
    for c in new_cases:
        key = normalize_key(c)
        if key in seen:
            continue
        seen.add(key)
        merged.append(c)

    if len(merged) > MAX_CASES:
        # Drop oldest shadow cases first; never drop a hand-curated case.
        # Only "shadow" cases are written by this loop: the curated sets carry
        # other sources too ("seed-widening", "r10-general-risk", ...), and
        # protecting "seed" alone let the cap delete those first.
        seeds = [c for c in merged if c.get("source") != "shadow"]
        shadows = [c for c in merged if c.get("source") == "shadow"]
        keep_shadow_count = max(0, MAX_CASES - len(seeds))
        shadows = shadows[-keep_shadow_count:] if keep_shadow_count else []
        merged = seeds + shadows
    return merged


# --- eval invocation (real Jev calls) --------------------------------------


def run_eval_in_worktree(cases_path=None, with_results=False):
    """Run airlock.eval inside the worktree's own venv-less interpreter,
    with the worktree on sys.path first, and return the parsed summary
    (and the per-case results too, when `with_results`)."""
    cmd = [sys.executable, "-m", "airlock.eval", "--json"]
    if cases_path:
        cmd += ["--cases", str(cases_path)]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(WORKTREE_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(cmd, cwd=str(WORKTREE_DIR), env=env, capture_output=True, text=True, timeout=1800)
    if proc.returncode != 0:
        raise RuntimeError("airlock.eval failed: %s" % proc.stderr[:2000])
    result_file = WORKTREE_DIR / "eval" / "last_result.json"
    with open(result_file) as f:
        data = json.load(f)
    if with_results:
        return data["summary"], data.get("results") or []
    return data["summary"]


def subset_accuracy(results, ids):
    """Label accuracy over the scored cases whose id is in `ids`: the same
    count airlock.eval's summary makes (errors and ambiguous cases left out),
    restricted to one set of cases, so a before and an after figure on the
    same cases can be compared."""
    correct = scored = 0
    for r in results:
        if r.get("id") not in ids or "error" in r or r.get("ambiguous"):
            continue
        scored += 1
        if r.get("label_correct"):
            correct += 1
    return (correct / scored) if scored else 0.0


def overall_accuracy(summary):
    total_correct = 0
    total_judged = 0
    total_false_deny = 0
    for s in summary.values():
        total_judged += s["judged"]
        total_correct += round(s["accuracy"] * s["judged"])
        total_false_deny += s["false_deny"]
    accuracy = (total_correct / total_judged) if total_judged else 0.0
    return accuracy, total_false_deny


# --- main run --------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="bypass the interval backoff check")
    parser.add_argument("--min-rows", type=int, default=DEFAULT_MIN_ROWS)
    parser.add_argument(
        "--print-judge-bin", action="store_true",
        help="resolve the judge binary, print it, and exit 0; exit 1 with the "
             "places searched if none resolves (doctor.sh uses this so it "
             "cannot disagree with the run itself)",
    )
    args = parser.parse_args()

    _refresh_paths()

    if args.print_judge_bin:
        judge_bin, searched = resolve_judge_bin()
        if judge_bin:
            print(judge_bin)
            return 0
        print("no judge binary found; searched:", file=sys.stderr)
        for place in searched:
            print("  %s" % place, file=sys.stderr)
        return 1

    run_start = time.time()
    state = load_state()

    if DISABLED_FILE.exists() or TUNING_DISABLED_FILE.exists():
        log("disabled via %s or %s; exiting" % (DISABLED_FILE, TUNING_DISABLED_FILE))
        _record(CATEGORY_DID_NOT_RUN, "disabled by kill switch", new_rows=0)
        return 0

    now_epoch = int(time.time())
    last_run_epoch = int(state.get("last_run_epoch", 0) or 0)
    interval_min = int(state.get("interval_min", MIN_INTERVAL_MIN) or MIN_INTERVAL_MIN)

    if not args.force:
        elapsed_min = (now_epoch - last_run_epoch) / 60.0
        if elapsed_min < interval_min:
            log("interval not elapsed (%.1f/%d min); exiting" % (elapsed_min, interval_min))
            _record(
                CATEGORY_DID_NOT_RUN,
                "interval not elapsed (%.1f/%d min)" % (elapsed_min, interval_min),
                new_rows=0,
            )
            return 0

    # Resolve the judge BEFORE any work: a missing binary is the difference
    # between "tuning is healthy and had nothing to do" and "tuning has never
    # once run", and the two must never look the same in the log.
    judge_bin, searched = resolve_judge_bin()
    if judge_bin is None:
        log("no judge binary found. Searched, in order:")
        for place in searched:
            log("  %s" % place)
        log("set AIRLOCK_TUNE_CLAUDE_BIN in $AIRLOCK_CONFIG_DIR/tune.env "
            "(install/install.sh --tuning writes it) and re-run.")
        _record(CATEGORY_COULD_NOT_RUN, "judge binary not found", new_rows=0)
        return 0
    log("judge binary: %s (model=%s effort=%s)" % (judge_bin, judge_model(), judge_effort()))

    main_repo = resolve_main_repo(Path(__file__).resolve().parent)
    if main_repo is None:
        log("no repository resolved (no AIRLOCK_TUNE_REPO, no repo.path pointer, and this "
            "checkout has no .git); tuning is optional, exiting without touching state")
        _record(CATEGORY_COULD_NOT_RUN, "no repository resolved", new_rows=0)
        return 0

    all_rows = read_shadow_rows()
    new_rows = new_rows_since(all_rows, state.get("last_processed_ts", ""))

    if len(new_rows) < args.min_rows:
        log("only %d new shadow rows (< %d); exiting without touching interval" % (len(new_rows), args.min_rows))
        _record(
            CATEGORY_RAN_NOTHING,
            "too few new rows (%d < %d)" % (len(new_rows), args.min_rows),
            new_rows=len(new_rows),
        )
        return 0

    # newest first (the cursor is advanced from this, independently of what
    # the sample picks)
    new_rows_sorted = sorted(new_rows, key=lambda r: str(r.get("ts", "")), reverse=True)

    # Sample: half newest-judgeable, half uniformly random over every
    # judgeable row, with every non-judgeable row counted by reason. See
    # tuning/sampling.py for why "the newest 20 rows" was not a measurement
    # of anything.
    candidate_rows, sample_report = sampling.select(
        new_rows_sorted, MAX_JUDGE_ROWS,
        seed=_int_env("AIRLOCK_TUNE_SAMPLE_SEED"),
    )
    log("sampling: %d of %d new row(s) judgeable; sampled %d (%d recent, %d random, seed=%s)"
        % (sample_report["judgeable"], sample_report["considered"],
           sample_report["sampled"], sample_report["sampled_recent"],
           sample_report["sampled_random"], sample_report["seed"]))
    for reason, count in sorted((sample_report["skipped_by_reason"] or {}).items()):
        log("sampling: skipped %d row(s) as %s" % (count, reason))
    _RUN_EXTRA["sample"] = {
        k: v for k, v in sample_report.items() if k != "rules"
    }
    _RUN_EXTRA["sample_rules"] = sample_report["rules"]

    # A row that still carries secret-shaped text is dropped from THIS batch,
    # counted, and the run carries on with the rest. One suspect row must not
    # cost the whole run, which is what used to happen.
    judge_rows = []
    redaction_skipped = 0
    for r in candidate_rows:
        residue = redaction_residue(r)
        if residue:
            redaction_skipped += 1
            continue
        judge_rows.append(r)
    if redaction_skipped:
        log("redaction sanity: skipped %d of %d row(s); %d sent to the judge"
            % (redaction_skipped, len(candidate_rows), len(judge_rows)))

    newest_ts = new_rows_sorted[0].get("ts", "") if new_rows_sorted else state.get("last_processed_ts", "")

    if not judge_rows:
        log("every candidate row failed the redaction sanity check; nothing to judge")
        state["last_processed_ts"] = newest_ts
        _finish(state, interval_min, committed=False, new_rows=len(new_rows), judged=0, wrong=0,
                error_rate=0.0, accuracy_before=None, accuracy_after=None, tokens_jev=0,
                wall_s=time.time() - run_start,
                reason="all %d candidate row(s) failed redaction sanity check" % redaction_skipped,
                category=CATEGORY_RAN_NOTHING, redaction_skipped=redaction_skipped)
        return 0

    try:
        ensure_tune_worktree(main_repo)
    except Exception as exc:
        log("worktree setup failed: %s" % exc)
        _finish(state, interval_min, committed=False, new_rows=len(new_rows), judged=0, wrong=0,
                error_rate=0.0, accuracy_before=None, accuracy_after=None, tokens_jev=0,
                wall_s=time.time() - run_start, reason="worktree setup failed: %s" % exc,
                category=CATEGORY_COULD_NOT_RUN, redaction_skipped=redaction_skipped)
        return 0

    # Advance the "new rows" cursor now, even if this run doesn't end up
    # committing anything -- rows are judged once; a discard just means no
    # change was warranted, not that we should re-judge them forever.

    # --- 3. label with a headless Claude judge -----------------------------
    try:
        judge_prompt = build_judge_prompt(judge_rows)
        judge_output = _run_claude(
            judge_prompt, effort=judge_effort(), model=judge_model(), bin_path=judge_bin
        )
        judgements = _extract_json(judge_output)
        if not isinstance(judgements, list):
            raise ValueError("judge output is not a JSON array")
    except Exception as exc:
        log("judge call failed or returned invalid JSON: %s" % exc)
        state["last_processed_ts"] = newest_ts
        _finish(state, interval_min, committed=False, new_rows=len(new_rows), judged=0, wrong=0,
                error_rate=0.0, accuracy_before=None, accuracy_after=None, tokens_jev=0,
                wall_s=time.time() - run_start, reason="judge call invalid: %s" % exc,
                category=CATEGORY_RAN_REJECTED, redaction_skipped=redaction_skipped)
        return 0

    run_verdicts = []
    wrong = []
    for index, (row, verdict) in enumerate(zip(judge_rows, judgements)):
        normalised = normalise_verdict(verdict, row, index)
        run_verdicts.append(normalised)
        if normalised["wrong"]:
            wrong.append({"row": row, "verdict": normalised})

    # Persist the per-row verdicts BEFORE anything else can discard the run.
    # A run whose only surviving output is "wrong: 17" cannot be questioned,
    # which is how the 0.85 stood for as long as it did.
    rate_table = sampling.rates(run_verdicts)
    verdict_path = verdict_store.write_run(
        STATE_DIR, run_verdicts,
        meta={
            "run_ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "judge_model": judge_model(),
            "judge_effort": judge_effort(),
            "sample": sample_report,
            "rates": rate_table,
            "policy_fingerprint": (
                _policy_text.policy_fingerprint() if _policy_text is not None else None
            ),
        },
    )
    if verdict_path is None:
        log("could not persist per-row verdicts (continuing; the run is still valid)")
    else:
        log("per-row verdicts: %s" % verdict_path)
    log("rates: %s" % sampling.rate_sentence(sample_report, rate_table))
    _RUN_EXTRA["rates_by_sample_rule"] = rate_table
    _RUN_EXTRA["cannot_tell"] = rate_table["_all_sampled"]["cannot_tell"]
    _RUN_EXTRA["verdicts_file"] = str(verdict_path) if verdict_path else None
    _RUN_EXTRA["rate_sentence"] = sampling.rate_sentence(sample_report, rate_table)

    judged_count = rate_table["_all_sampled"]["judged"]
    cannot_tell_count = rate_table["_all_sampled"]["cannot_tell"]
    wrong_count = len(wrong)
    # Denominator is the rows the judge could actually decide. A cannot_tell
    # is neither right nor wrong and belongs in neither half of the ratio.
    error_rate = (wrong_count / judged_count) if judged_count else 0.0
    if cannot_tell_count:
        log("judge answered cannot_tell on %d of %d sampled row(s)"
            % (cannot_tell_count, len(run_verdicts)))

    if not wrong:
        log("judge found no wrong rows; nothing to tune")
        state["last_processed_ts"] = newest_ts
        _finish(state, interval_min, committed=False, new_rows=len(new_rows), judged=judged_count, wrong=0,
                error_rate=error_rate, accuracy_before=None, accuracy_after=None, tokens_jev=0,
                wall_s=time.time() - run_start, reason="no wrong rows",
                category=CATEGORY_RAN_NOTHING, redaction_skipped=redaction_skipped)
        return 0

    # --- 4. turn wrong rows into new eval cases -----------------------------
    cases_path = WORKTREE_DIR / "eval" / "cases.jsonl"
    existing_cases = load_cases(cases_path)
    existing_ids = {c.get("id") for c in existing_cases}

    new_cases = []
    for item in wrong:
        row = item["row"]
        verdict = item["verdict"]
        guard = row.get("guard")
        if verdict.get("label_correct") is not False:
            # The action was wrong but the label was right (or undecided).
            # There is no label expectation to add, and inventing one teaches
            # the eval the opposite of what the judge found.
            continue
        expected = expected_case_fields(row, guard, verdict.get("correct_label"))
        if expected is None:
            continue
        cid = "shadow-%s" % hashlib.sha256(json.dumps(row, default=str).encode("utf-8")).hexdigest()[:16]
        if cid in existing_ids:
            continue
        new_cases.append({
            "id": cid,
            "guard": guard,
            "payload": {
                "session_id": row.get("session_id"),
                "cwd": row.get("cwd"),
                "tool_name": row.get("tool_name"),
                "tool_input": case_tool_input(row, guard),
            },
            "expected": expected,
            "source": "shadow",
            "note": verdict.get("reason", ""),
            "sample_rule": verdict.get("sample_rule"),
        })

    if not new_cases:
        log("all wrong rows already have cases; nothing new to add")
        state["last_processed_ts"] = newest_ts
        _finish(state, interval_min, committed=False, new_rows=len(new_rows), judged=judged_count, wrong=wrong_count,
                error_rate=error_rate, accuracy_before=None, accuracy_after=None, tokens_jev=0,
                wall_s=time.time() - run_start, reason="no new cases after dedupe",
                category=CATEGORY_RAN_NOTHING, redaction_skipped=redaction_skipped)
        return 0

    merged_cases = merge_new_cases(existing_cases, new_cases)
    baseline_ids = {c.get("id") for c in existing_cases}

    # --- baseline eval, BEFORE any edits, on the full (existing + new) set --
    write_cases(cases_path, merged_cases)
    tokens_jev = 0
    try:
        before_summary, before_results = run_eval_in_worktree(with_results=True)
        acc_before, false_deny_before = overall_accuracy(before_summary)
        # The regression check below compares the cases that existed before
        # this run, before and after. The merged-set figure above includes
        # the new cases, every one of which the guard just got wrong, so it
        # is lower and let a real regression on the old cases pass.
        acc_before_on_old = subset_accuracy(before_results, baseline_ids)
        tokens_jev += sum(s.get("total_tokens", 0) for s in before_summary.values())
    except Exception as exc:
        log("baseline eval failed: %s" % exc)
        worktree_discard_changes()
        state["last_processed_ts"] = newest_ts
        _finish(state, interval_min, committed=False, new_rows=len(new_rows), judged=judged_count, wrong=wrong_count,
                error_rate=error_rate, accuracy_before=None, accuracy_after=None, tokens_jev=tokens_jev,
                wall_s=time.time() - run_start, reason="baseline eval failed: %s" % exc,
                category=CATEGORY_RAN_REJECTED, redaction_skipped=redaction_skipped)
        return 0

    # --- 5. ask for replacement criteria text ------------------------------
    questions_path = WORKTREE_DIR / "airlock" / "questions.py"
    try:
        current_source = questions_path.read_text()
        criteria_prompt = build_criteria_prompt(current_source, [w["row"] for w in wrong], DOCS_GUIDANCE_SUMMARY)
        criteria_output = _run_claude(
            criteria_prompt, effort=judge_effort(), model=judge_model(), bin_path=judge_bin
        )
        replacement = _extract_json(criteria_output)
        if not isinstance(replacement, dict):
            raise ValueError("criteria output is not a JSON object")
        new_source, applied, skipped = apply_criteria_replacement(current_source, replacement)
        if skipped:
            log("criteria rewrite skipped %d off-schema entr(y/ies): %s" % (len(skipped), skipped))
        if applied:
            questions_path.write_text(new_source)
        else:
            log("criteria rewrite applied nothing (all entries skipped); no questions.py change")
    except Exception as exc:
        log("criteria rewrite failed or invalid: %s" % exc)
        worktree_discard_changes()
        state["last_processed_ts"] = newest_ts
        _finish(state, interval_min, committed=False, new_rows=len(new_rows), judged=judged_count, wrong=wrong_count,
                error_rate=error_rate, accuracy_before=acc_before, accuracy_after=None, tokens_jev=tokens_jev,
                wall_s=time.time() - run_start, reason="criteria rewrite failed: %s" % exc,
                category=CATEGORY_RAN_REJECTED, redaction_skipped=redaction_skipped)
        return 0

    # --- 6. gate ------------------------------------------------------------
    changed_files = worktree_diff_files()
    allowed_paths = {"airlock/questions.py", "eval/cases.jsonl"}
    if not set(changed_files) <= allowed_paths:
        log("gate failed: unexpected files changed: %s" % changed_files)
        worktree_discard_changes()
        state["last_processed_ts"] = newest_ts
        _finish(state, interval_min, committed=False, new_rows=len(new_rows), judged=judged_count, wrong=wrong_count,
                error_rate=error_rate, accuracy_before=acc_before, accuracy_after=None, tokens_jev=tokens_jev,
                wall_s=time.time() - run_start, reason="unexpected files changed: %s" % changed_files,
                category=CATEGORY_RAN_REJECTED, redaction_skipped=redaction_skipped)
        return 0

    test_proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=str(WORKTREE_DIR), capture_output=True, text=True,
    )
    if test_proc.returncode != 0:
        log("gate failed: unit tests failed")
        worktree_discard_changes()
        state["last_processed_ts"] = newest_ts
        _finish(state, interval_min, committed=False, new_rows=len(new_rows), judged=judged_count, wrong=wrong_count,
                error_rate=error_rate, accuracy_before=acc_before, accuracy_after=None, tokens_jev=tokens_jev,
                wall_s=time.time() - run_start, reason="unit tests failed: %s" % test_proc.stdout[-2000:],
                category=CATEGORY_RAN_REJECTED, redaction_skipped=redaction_skipped)
        return 0

    try:
        after_summary, after_results = run_eval_in_worktree(with_results=True)
        acc_after, false_deny_after = overall_accuracy(after_summary)
        tokens_jev += sum(s.get("total_tokens", 0) for s in after_summary.values())

        # The cases that existed before this run, scored the same way as
        # acc_before_on_old. Each case is judged on its own, so reading them
        # out of the full run equals a separate run over just those cases.
        acc_after_on_old = subset_accuracy(after_results, baseline_ids)
    except Exception as exc:
        log("post-change eval failed: %s" % exc)
        worktree_discard_changes()
        state["last_processed_ts"] = newest_ts
        _finish(state, interval_min, committed=False, new_rows=len(new_rows), judged=judged_count, wrong=wrong_count,
                error_rate=error_rate, accuracy_before=acc_before, accuracy_after=None, tokens_jev=tokens_jev,
                wall_s=time.time() - run_start, reason="post-change eval failed: %s" % exc,
                category=CATEGORY_RAN_REJECTED, redaction_skipped=redaction_skipped)
        return 0

    gate_ok = (
        acc_after_on_old >= acc_before_on_old
        and acc_after > acc_before
        and false_deny_after <= false_deny_before
    )

    if not gate_ok:
        log(
            "gate failed: acc_before=%.3f acc_after=%.3f acc_before_on_old=%.3f acc_after_on_old=%.3f "
            "false_deny_before=%d false_deny_after=%d"
            % (acc_before, acc_after, acc_before_on_old, acc_after_on_old, false_deny_before, false_deny_after)
        )
        worktree_discard_changes()
        state["last_processed_ts"] = newest_ts
        interval_min = min(interval_min * 2, MAX_INTERVAL_MIN) if error_rate <= 0.10 else MIN_INTERVAL_MIN
        _finish(state, interval_min, committed=False, new_rows=len(new_rows), judged=judged_count, wrong=wrong_count,
                error_rate=error_rate, accuracy_before=acc_before, accuracy_after=acc_after, tokens_jev=tokens_jev,
                wall_s=time.time() - run_start,
                reason="gate failed: before=%.3f after=%.3f before_on_old=%.3f after_on_old=%.3f"
                % (acc_before, acc_after, acc_before_on_old, acc_after_on_old),
                category=CATEGORY_RAN_REJECTED, redaction_skipped=redaction_skipped)
        return 0

    commit_msg = (
        "Auto-tune: %d wrong row(s) reclassified, criteria updated\n\n"
        "accuracy overall: %.3f -> %.3f (on previously-existing cases: %.3f)\n"
        "false_deny: %d -> %d\n"
        "judged=%d wrong=%d error_rate=%.1f%%\n"
    ) % (wrong_count, acc_before, acc_after, acc_after_on_old, false_deny_before, false_deny_after,
         judged_count, wrong_count, error_rate * 100)

    run(["git", "-C", str(WORKTREE_DIR), "add", "airlock/questions.py", "eval/cases.jsonl"])
    run(["git", "-C", str(WORKTREE_DIR), "commit", "-m", commit_msg])

    state["last_processed_ts"] = newest_ts
    _finish(state, MIN_INTERVAL_MIN, committed=True, new_rows=len(new_rows), judged=judged_count, wrong=wrong_count,
            error_rate=error_rate, accuracy_before=acc_before, accuracy_after=acc_after, tokens_jev=tokens_jev,
            wall_s=time.time() - run_start, reason="committed",
            category=CATEGORY_RAN_COMMITTED, redaction_skipped=redaction_skipped)
    return 0


def summary_line(entry):
    """One human-readable line per run, the thing a person actually reads."""
    return "run summary: %s (%s) -- %s" % (
        entry.get("category", "unknown"),
        CATEGORY_BLURB.get(entry.get("category"), "unrecognised category"),
        entry.get("reason", ""),
    )


def _record(category, reason, new_rows=0, **extra):
    """Append a log entry WITHOUT touching tune_state.json.

    Used for the outcomes that must not reset the backoff clock: the timer
    firing inside the interval, the kill switch, a missing judge binary, too
    few rows. Writing state here would push last_run_epoch forward on every
    timer firing and the interval would never elapse at all."""
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "category": category,
        "reason": reason,
        "new_rows": new_rows,
        "committed": False,
    }
    entry.update(extra)
    append_tune_log(entry)
    log(summary_line(entry))
    return entry


def _finish(state, next_interval_min, committed, new_rows, judged, wrong, error_rate,
            accuracy_before, accuracy_after, tokens_jev, wall_s, reason,
            category=None, redaction_skipped=0):
    if category is None:
        category = CATEGORY_RAN_COMMITTED if committed else CATEGORY_RAN_REJECTED
    state["interval_min"] = next_interval_min
    state["last_run_epoch"] = int(time.time())
    save_state(state)
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "category": category,
        "new_rows": new_rows,
        "judged": judged,
        "wrong": wrong,
        # NOT "the error rate". It is the rate over the rows this run
        # sampled, and `sample` below names the rule that drew them.
        "error_rate_of_sampled": error_rate,
        "error_rate": error_rate,
        "accuracy_before": accuracy_before,
        "accuracy_after": accuracy_after,
        "committed": committed,
        "interval_min_next": next_interval_min,
        "tokens_jev": tokens_jev,
        "wall_time_s": wall_s,
        "redaction_skipped": redaction_skipped,
        "reason": reason,
    }
    entry.update(_RUN_EXTRA)
    append_tune_log(entry)
    log(summary_line(entry))
    log("run finished: %s" % json.dumps(entry, default=str))
    return entry


if __name__ == "__main__":
    sys.exit(main())
