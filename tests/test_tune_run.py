import tests  # noqa: F401, I001 -- MUST be the first import; see tests/__init__.py.

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from tuning import tune


@contextmanager
def temp_env(**overrides):
    """Set/unset environment variables for the duration of the block."""
    saved = {k: os.environ.get(k) for k in overrides}
    try:
        for k, v in overrides.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ---------------------------------------------------------------------------
# 1. judge binary resolution
# ---------------------------------------------------------------------------


class TestResolveJudgeBin(unittest.TestCase):
    def _make_bin(self, directory, name="claude"):
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o755)
        return path

    def test_explicit_env_absolute_path_wins(self):
        with tempfile.TemporaryDirectory() as td:
            wanted = self._make_bin(Path(td) / "custom")
            with temp_env(AIRLOCK_TUNE_CLAUDE_BIN=str(wanted), AIRLOCK_CLAUDE_BIN=None):
                found, searched = tune.resolve_judge_bin()
        self.assertEqual(found, str(wanted))
        self.assertTrue(any("AIRLOCK_TUNE_CLAUDE_BIN" in s for s in searched))

    def test_alias_env_var_also_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            wanted = self._make_bin(Path(td) / "custom")
            with temp_env(AIRLOCK_TUNE_CLAUDE_BIN=None, AIRLOCK_CLAUDE_BIN=str(wanted)):
                found, _ = tune.resolve_judge_bin()
        self.assertEqual(found, str(wanted))

    def test_non_executable_override_falls_through_to_path(self):
        with tempfile.TemporaryDirectory() as td:
            dud = Path(td) / "not-executable"
            dud.write_text("")
            on_path = self._make_bin(Path(td) / "bin")
            with temp_env(
                AIRLOCK_TUNE_CLAUDE_BIN=str(dud),
                AIRLOCK_CLAUDE_BIN=None,
                PATH=str(on_path.parent),
            ):
                found, _ = tune.resolve_judge_bin()
        self.assertEqual(found, str(on_path))

    def test_falls_back_to_npm_global_prefix_when_path_is_systemd_minimal(self):
        """The actual live failure: a systemd user unit's PATH is
        /usr/bin:/bin, which contains no npm global prefix, so `claude`
        resolved by name is not found. It must still be found under
        ~/.npm-global/bin."""
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            wanted = self._make_bin(home / ".npm-global" / "bin")
            with temp_env(
                HOME=str(home),
                AIRLOCK_TUNE_CLAUDE_BIN=None,
                AIRLOCK_CLAUDE_BIN=None,
                PATH="/usr/bin:/bin",
                NVM_DIR=str(home / ".nvm"),
            ):
                tune._refresh_paths()  # HOME changed; candidate dirs follow it
                found, searched = tune.resolve_judge_bin()
                self.assertEqual(found, str(wanted))
                self.assertTrue(any(s.startswith("PATH=") for s in searched))
        tune._refresh_paths()

    def test_finds_nvm_versioned_bin_without_sourcing_a_shell(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            nvm = home / ".nvm"
            wanted = self._make_bin(nvm / "versions" / "node" / "v22.1.0" / "bin")
            with temp_env(
                HOME=str(home),
                AIRLOCK_TUNE_CLAUDE_BIN=None,
                AIRLOCK_CLAUDE_BIN=None,
                PATH="/nonexistent-dir-for-this-test",
                NVM_DIR=str(nvm),
            ):
                tune._refresh_paths()
                found, _ = tune.resolve_judge_bin()
                self.assertEqual(found, str(wanted))
        tune._refresh_paths()

    def test_returns_none_and_names_everything_searched(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            with temp_env(
                HOME=str(home),
                AIRLOCK_TUNE_CLAUDE_BIN=None,
                AIRLOCK_CLAUDE_BIN=None,
                PATH="/nonexistent-dir-for-this-test",
                NVM_DIR=str(home / ".nvm"),
            ):
                tune._refresh_paths()
                found, searched = tune.resolve_judge_bin()
                self.assertIsNone(found)
                self.assertTrue(any(".npm-global/bin/claude" in s for s in searched))
                self.assertTrue(any(".local/bin/claude" in s for s in searched))
        tune._refresh_paths()

    def test_run_claude_raises_naming_the_search_when_nothing_resolves(self):
        with mock.patch.object(tune, "resolve_judge_bin", return_value=(None, ["PATH=/usr/bin"])):
            with self.assertRaises(RuntimeError) as ctx:
                tune._run_claude("hello", effort="low")
        self.assertIn("no judge binary found", str(ctx.exception))


# ---------------------------------------------------------------------------
# 2. redaction sanity check
# ---------------------------------------------------------------------------


class TestRedactionSanity(unittest.TestCase):
    """Synthetic rows only. Never a row copied from a real shadow log."""

    def test_benign_hyphenated_word_containing_sk_is_not_residue(self):
        # The old check was a substring search for "sk-", so every occurrence
        # of this project's own scope vocabulary tripped it.
        row = {"guard": "tool_choice_guard",
               "input_summary": {"command": "grep -rn foo /  # a disk-wide find"}}
        self.assertEqual(tune.redaction_residue(row), [])
        self.assertTrue(tune._looks_redacted(row))

    def test_redaction_pattern_text_is_not_residue(self):
        # The exact shape that killed three live runs: the row contains the
        # SOURCE of a redaction command, so "apikey_" appears while nothing
        # secret does.
        row = {"guard": "tool_choice_guard", "input_summary": {
            "command": "systemctl --user status 2>&1 | sed 's/apikey_[A-Za-z0-9_]*/[REDACTED]/g'"}}
        self.assertEqual(tune.redaction_residue(row), [])

    def test_already_redacted_placeholder_is_not_residue(self):
        row = {"input_summary": {"prompt": "the key is [REDACTED] now"}}
        self.assertEqual(tune.redaction_residue(row), [])

    def test_genuinely_unredacted_key_is_residue(self):
        row = {"input_summary": {"command": "export X=sk-" + "a" * 40}}
        self.assertTrue(tune.redaction_residue(row))
        self.assertFalse(tune._looks_redacted(row))

    def test_missing_redactor_is_treated_as_unproven_not_as_clean(self):
        with mock.patch.object(tune, "_redact", None):
            self.assertTrue(tune.redaction_residue({"a": "b"}))

    def test_redactor_raising_is_treated_as_unproven(self):
        def boom(_text):
            raise ValueError("nope")

        with mock.patch.object(tune, "_redact", boom):
            self.assertTrue(tune.redaction_residue({"a": "b"}))


# ---------------------------------------------------------------------------
# 3. criteria rewrite validated against each question's real schema
# ---------------------------------------------------------------------------


class TestCriteriaSchema(unittest.TestCase):
    def setUp(self):
        self.source = Path("airlock/questions.py").read_text()

    def test_allowed_options_read_from_questions_source(self):
        allowed = tune.allowed_criteria_options(self.source)
        self.assertIn("task_kind", allowed)
        self.assertIn("search_intent", allowed)
        self.assertIn("lookup", allowed["task_kind"])
        self.assertIn("not_a_search", allowed["search_intent"])
        self.assertNotIn("not_for", allowed["search_intent"])

    def test_allowed_options_on_unparseable_source_is_empty_not_a_raise(self):
        self.assertEqual(tune.allowed_criteria_options("def broken("), {})

    def test_prompt_tells_the_judge_the_exact_keys(self):
        prompt = tune.build_criteria_prompt(self.source, [], tune.DOCS_GUIDANCE_SUMMARY)
        self.assertIn("The ONLY keys you may use", prompt)
        for option in tune.allowed_criteria_options(self.source)["search_intent"]:
            self.assertIn(option, prompt)

    def test_unknown_option_is_dropped_not_raised(self):
        """`unknown option 'not_for' for question 'search_intent'` is the
        real log line that lost a run."""
        new_source, applied, skipped = tune.apply_criteria_replacement(
            self.source,
            {"search_intent": {"not_for": "invented", "not_a_search": "REAL NEW TEXT"}},
        )
        self.assertIn(("search_intent", "not_a_search"), applied)
        self.assertEqual(
            [(q, o) for q, o, _why in skipped], [("search_intent", "not_for")]
        )
        ns = {}
        exec(compile(new_source, "<test>", "exec"), ns)
        self.assertEqual(
            ns["bash_questions"]()["search_intent"]["criteria"]["not_a_search"],
            "REAL NEW TEXT",
        )

    def test_unknown_question_id_is_dropped_not_raised(self):
        _new_source, applied, skipped = tune.apply_criteria_replacement(
            self.source, {"invented_question": {"x": "y"}}
        )
        self.assertEqual(applied, set())
        self.assertEqual(skipped, [("invented_question", None, "unknown question id")])


# ---------------------------------------------------------------------------
# 4. run categories, with the judge mocked
# ---------------------------------------------------------------------------


class TestRunCategories(unittest.TestCase):
    """Drive main() end to end against throwaway directories, with the judge
    replaced by a stub. Nothing here makes a real API call."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        self.state = self.root / "state"
        self.config = self.root / "config"
        self.state.mkdir()
        self.config.mkdir()
        self.shadow = self.state / "shadow.jsonl"
        self.addCleanup(self._td.cleanup)
        self.addCleanup(tune._refresh_paths)
        # Keep the suite's output readable: these tests drive whole runs, each
        # of which narrates itself to stderr by design.
        quiet = mock.patch.object(tune, "log", lambda _msg: None)
        quiet.start()
        self.addCleanup(quiet.stop)

    def _env(self, **extra):
        env = {
            "AIRLOCK_TUNE_STATE_DIR": str(self.state),
            "AIRLOCK_CONFIG_DIR": str(self.config),
            "AIRLOCK_TUNE_SHADOW_LOG": str(self.shadow),
            "AIRLOCK_TUNE_WORKTREE_DIR": str(self.root / "worktree"),
        }
        env.update(extra)
        return env

    def _write_rows(self, rows):
        with open(self.shadow, "w") as f:
            f.writelines(json.dumps(r) + "\n" for r in rows)

    def _synthetic_rows(self, n, secret=False):
        rows = []
        for i in range(n):
            command = "rg --files -g '*.py' # a disk-wide find, row %d" % i
            if secret:
                command = "export TOKEN=sk-" + ("b" * 40)
            rows.append({
                "ts": "2026-01-01T00:%02d:00Z" % i,
                "guard": "tool_choice_guard",
                "tool_name": "Bash",
                "cwd": "/tmp/project",
                "session_id": "synthetic-%d" % i,
                "would_deny": False,
                "scope": "disk_wide",
                "margin": 1.0,
                # A row with no `answers` block carries no Jev answer and is
                # not judgeable (see tuning/sampling.py). Every fixture row
                # here is one Jev really answered, because that is the only
                # kind a run is allowed to sample.
                "answers": {"search_intent": {
                    "type": "choice", "choice": "filename_search", "confidence": 1.0,
                    "probabilities": {"filename_search": 1.0, "not_a_search": 0.0},
                }},
                "input_summary": {"command": command},
            })
        return rows

    def _verdicts(self, n, label_correct=True, correct_label="filename_search"):
        """Judge output in the CURRENT schema: a label verdict and an action
        verdict, separately, with an explicit cannot_tell."""
        return json.dumps([
            {"id": "row-%d" % i, "guard": "tool_choice_guard",
             "correct_label": correct_label, "label_correct": label_correct,
             "action_correct": True, "cannot_tell": False, "reason": "fine"}
            for i in range(n)
        ])

    def _last_entry(self):
        path = self.state / "tune_log.jsonl"
        rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
        return rows[-1]

    def _run_main(self, argv, env):
        with temp_env(**env):
            with mock.patch.object(sys, "argv", ["tune.py"] + argv):
                rc = tune.main()
        return rc

    def test_did_not_run_when_interval_has_not_elapsed(self):
        (self.state / "tune_state.json").write_text(
            json.dumps({"interval_min": 30, "last_run_epoch": int(__import__("time").time()),
                        "last_processed_ts": ""})
        )
        rc = self._run_main([], self._env())
        self.assertEqual(rc, 0)
        entry = self._last_entry()
        self.assertEqual(entry["category"], tune.CATEGORY_DID_NOT_RUN)
        self.assertIn("interval not elapsed", entry["reason"])

    def test_did_not_run_does_not_push_the_backoff_clock_forward(self):
        """Regression guard: if the interval-not-elapsed path wrote state,
        last_run_epoch would move on every timer firing and the interval
        would never elapse at all."""
        state_file = self.state / "tune_state.json"
        state_file.write_text(json.dumps(
            {"interval_min": 30, "last_run_epoch": 1000, "last_processed_ts": ""}))
        self._run_main([], self._env())
        self.assertEqual(json.loads(state_file.read_text())["last_run_epoch"], 1000)

    def test_did_not_run_when_kill_switch_present(self):
        (self.config / "tuning-disabled").write_text("")
        rc = self._run_main([], self._env())
        self.assertEqual(rc, 0)
        self.assertEqual(self._last_entry()["category"], tune.CATEGORY_DID_NOT_RUN)

    def test_could_not_run_when_no_judge_binary(self):
        env = self._env(
            AIRLOCK_TUNE_CLAUDE_BIN=str(self.root / "nope"),
            AIRLOCK_CLAUDE_BIN=None,
            HOME=str(self.root / "empty-home"),
            PATH="/nonexistent-dir-for-this-test",
            NVM_DIR=str(self.root / "empty-home" / ".nvm"),
        )
        rc = self._run_main(["--force"], env)
        self.assertEqual(rc, 0)
        entry = self._last_entry()
        self.assertEqual(entry["category"], tune.CATEGORY_COULD_NOT_RUN)
        self.assertEqual(entry["reason"], "judge binary not found")

    def test_could_not_run_when_no_repository_resolves(self):
        with mock.patch.object(tune, "resolve_judge_bin", return_value=("/bin/true", [])):
            with mock.patch.object(tune, "resolve_main_repo", return_value=None):
                rc = self._run_main(["--force"], self._env())
        self.assertEqual(rc, 0)
        self.assertEqual(self._last_entry()["category"], tune.CATEGORY_COULD_NOT_RUN)
        self.assertEqual(self._last_entry()["reason"], "no repository resolved")

    def test_ran_nothing_when_too_few_rows(self):
        self._write_rows(self._synthetic_rows(3))
        with mock.patch.object(tune, "resolve_judge_bin", return_value=("/bin/true", [])):
            with mock.patch.object(tune, "resolve_main_repo", return_value=Path("/tmp")):
                rc = self._run_main(["--force"], self._env())
        self.assertEqual(rc, 0)
        entry = self._last_entry()
        self.assertEqual(entry["category"], tune.CATEGORY_RAN_NOTHING)
        self.assertIn("too few new rows", entry["reason"])

    def test_ran_nothing_when_judge_finds_no_wrong_rows(self):
        rows = self._synthetic_rows(12)
        self._write_rows(rows)
        verdicts = self._verdicts(len(rows))
        with mock.patch.object(tune, "resolve_judge_bin", return_value=("/bin/true", [])), \
             mock.patch.object(tune, "resolve_main_repo", return_value=Path("/tmp")), \
             mock.patch.object(tune, "ensure_tune_worktree"), \
             mock.patch.object(tune, "_run_claude", return_value=verdicts) as judge:
            rc = self._run_main(["--force"], self._env())
        self.assertEqual(rc, 0)
        self.assertEqual(judge.call_count, 1)
        entry = self._last_entry()
        self.assertEqual(entry["category"], tune.CATEGORY_RAN_NOTHING)
        self.assertEqual(entry["reason"], "no wrong rows")
        self.assertEqual(entry["judged"], 12)
        self.assertEqual(entry["redaction_skipped"], 0)

    def test_ran_rejected_when_judge_returns_junk(self):
        self._write_rows(self._synthetic_rows(12))
        with mock.patch.object(tune, "resolve_judge_bin", return_value=("/bin/true", [])), \
             mock.patch.object(tune, "resolve_main_repo", return_value=Path("/tmp")), \
             mock.patch.object(tune, "ensure_tune_worktree"), \
             mock.patch.object(tune, "_run_claude", return_value="not json at all"):
            rc = self._run_main(["--force"], self._env())
        self.assertEqual(rc, 0)
        self.assertEqual(self._last_entry()["category"], tune.CATEGORY_RAN_REJECTED)

    def test_one_unredacted_row_is_skipped_and_the_run_carries_on(self):
        """The old behaviour abandoned the whole run on the first suspect
        row. It must now skip that row, count it, and judge the rest."""
        rows = self._synthetic_rows(11) + self._synthetic_rows(1, secret=True)
        for i, r in enumerate(rows):
            r["ts"] = "2026-01-01T00:%02d:00Z" % i
            r["session_id"] = "synthetic-%d" % i
        self._write_rows(rows)
        verdicts = self._verdicts(11)
        with mock.patch.object(tune, "resolve_judge_bin", return_value=("/bin/true", [])), \
             mock.patch.object(tune, "resolve_main_repo", return_value=Path("/tmp")), \
             mock.patch.object(tune, "ensure_tune_worktree"), \
             mock.patch.object(tune, "_run_claude", return_value=verdicts) as judge:
            rc = self._run_main(["--force"], self._env())
        self.assertEqual(rc, 0)
        entry = self._last_entry()
        self.assertEqual(entry["category"], tune.CATEGORY_RAN_NOTHING)
        self.assertEqual(entry["redaction_skipped"], 1)
        self.assertEqual(entry["judged"], 11)
        # and the secret row never reached the judge prompt
        sent = judge.call_args[0][0]
        self.assertNotIn("sk-bbbb", sent)

    def test_every_row_unredacted_is_ran_nothing_not_a_crash(self):
        rows = self._synthetic_rows(12, secret=True)
        for i, r in enumerate(rows):
            r["ts"] = "2026-01-01T00:%02d:00Z" % i
        self._write_rows(rows)
        with mock.patch.object(tune, "resolve_judge_bin", return_value=("/bin/true", [])), \
             mock.patch.object(tune, "resolve_main_repo", return_value=Path("/tmp")), \
             mock.patch.object(tune, "_run_claude") as judge:
            rc = self._run_main(["--force"], self._env())
        self.assertEqual(rc, 0)
        judge.assert_not_called()
        entry = self._last_entry()
        self.assertEqual(entry["category"], tune.CATEGORY_RAN_NOTHING)
        self.assertEqual(entry["redaction_skipped"], 12)

    def test_every_category_has_a_human_blurb(self):
        for category in (tune.CATEGORY_DID_NOT_RUN, tune.CATEGORY_COULD_NOT_RUN,
                         tune.CATEGORY_RAN_NOTHING, tune.CATEGORY_RAN_REJECTED,
                         tune.CATEGORY_RAN_COMMITTED):
            self.assertIn(category, tune.CATEGORY_BLURB)
            self.assertIn(
                tune.CATEGORY_BLURB[category],
                tune.summary_line({"category": category, "reason": "r"}),
            )

    def test_print_judge_bin_exits_nonzero_when_nothing_resolves(self):
        env = self._env(
            AIRLOCK_TUNE_CLAUDE_BIN=None, AIRLOCK_CLAUDE_BIN=None,
            HOME=str(self.root / "empty-home"),
            PATH="/nonexistent-dir-for-this-test",
            NVM_DIR=str(self.root / "empty-home" / ".nvm"),
        )
        rc = self._run_main(["--print-judge-bin"], env)
        self.assertEqual(rc, 1)

    def test_print_judge_bin_prints_the_path_when_one_resolves(self):
        with tempfile.TemporaryDirectory() as td:
            binary = Path(td) / "claude"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            buf = io.StringIO()
            with mock.patch.object(sys, "stdout", buf):
                rc = self._run_main(
                    ["--print-judge-bin"], self._env(AIRLOCK_TUNE_CLAUDE_BIN=str(binary))
                )
        self.assertEqual(rc, 0)
        self.assertEqual(buf.getvalue().strip(), str(binary))


# ---------------------------------------------------------------------------
# the shipped shell wiring
# ---------------------------------------------------------------------------


class TestShellWiring(unittest.TestCase):
    def test_tune_sh_sources_tune_env_before_running_tune_py(self):
        text = Path("tuning/tune.sh").read_text()
        self.assertIn('. "$CONFIG_DIR/tune.env"', text)
        self.assertLess(text.index("tune.env"), text.index('python3 "$SCRIPT_DIR/tune.py"'))

    def test_installer_writes_tune_env_600(self):
        text = Path("install/install.sh").read_text()
        self.assertIn("tune.env", text)
        self.assertIn('chmod 600 "$TUNE_ENV"', text)
        self.assertIn("AIRLOCK_TUNE_CLAUDE_BIN=", text)

    def test_tune_env_values_are_quoted_for_sourcing(self):
        # A path with a space was written bare, and tune.sh (set -e) then
        # ran the second word as a command when it sourced the file.
        text = Path("install/install.sh").read_text()
        self.assertNotRegex(text, r"printf 'AIRLOCK_TUNE_[A-Z_]+=%s")
        value = "/mnt/c/Program Files/claude $HOME"
        out = subprocess.run(
            ["bash", "-c", 'set -e; f=$(mktemp); printf "V=%q\\n" "$1" > "$f"; '
             '. "$f"; rm -f "$f"; printf %s "$V"', "_", value],
            capture_output=True, text=True, timeout=10)
        self.assertEqual((out.returncode, out.stdout), (0, value))

    def test_doctor_fails_when_no_judge_binary_resolves(self):
        text = Path("install/doctor.sh").read_text()
        self.assertIn("--print-judge-bin", text)
        self.assertIn("no judge binary resolves", text)
        # and it must be a FAIL, not a skip
        self.assertIn('fail "no judge binary resolves', text)

    def test_shell_scripts_parse(self):
        for script in ("tuning/tune.sh", "install/install.sh", "install/doctor.sh"):
            proc = subprocess.run(["bash", "-n", script], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, "%s: %s" % (script, proc.stderr))


if __name__ == "__main__":
    unittest.main()
