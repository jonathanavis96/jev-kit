"""install/_wire.py: wiring a settings.json's airlock PreToolUse hook.

Two things this file exists to prove:

  1. REPOINTING an existing hook command never drops the pinned interpreter.
     The bug that shipped once: the pattern replaced the WHOLE command
     string, so `"/usr/bin/python3 <old path>"` became `"<new path>"` and a
     machine that deliberately names /usr/bin/python3 rather than relying on
     the shebang and the file's mode bit got a broken hook.

  2. ADDING a missing hook actually adds it. A FIRST install has nothing to
     repoint -- there is no airlock hook command in settings.json yet -- and
     the old script's response to that ("no airlock.py hook command found,
     skipping") left a fresh machine unwired despite `--apply`. `--apply`
     must add the PreToolUse entry (and, opted in per flag, the belay Stop
     hook and the function-hooks env var), idempotently, always backing up
     an existing file first, and never touching an unrelated key or hook.
"""

import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WIRE = REPO_ROOT / "install" / "_wire.py"

NEW_HOOK = "/opt/airlock/current/hooks/airlock.py"
PYTHON3 = "/usr/bin/python3"
NEW_HOOK_COMMAND = "%s %s" % (PYTHON3, NEW_HOOK)


def _run(path, apply_=False, belay=False, function_hooks=False,
         belay_wrapper="/nonexistent/airlock-belay-run",
         session_check=False, session_hook=None,
         browse_unlock=False, browse_hook=None):
    env = dict(os.environ)
    env["NEW_HOOK"] = NEW_HOOK
    env["NEW_HOOK_COMMAND"] = NEW_HOOK_COMMAND
    env["APPLY"] = "1" if apply_ else "0"
    env["BELAY"] = "1" if belay else "0"
    env["BELAY_WRAPPER"] = belay_wrapper
    env["FUNCTION_HOOKS"] = "1" if function_hooks else "0"
    # Off unless a test asks for it, so every pre-existing assertion here is
    # still about the PreToolUse entry alone.
    env["SESSION_CHECK"] = "1" if session_check else "0"
    env["SESSION_CHECK_HOOK"] = session_hook or ""
    env["SESSION_CHECK_COMMAND"] = (
        "%s %s" % (PYTHON3, session_hook)) if session_hook else ""
    # Same again for the PostToolUse browse unlock: off unless a test asks.
    env["BROWSE_UNLOCK"] = "1" if browse_unlock else "0"
    env["BROWSE_UNLOCK_HOOK"] = browse_hook or ""
    env["BROWSE_UNLOCK_COMMAND"] = (
        "%s %s" % (PYTHON3, browse_hook)) if browse_hook else ""
    return subprocess.run([sys.executable, str(WIRE), str(path)],
                          capture_output=True, text=True, env=env, timeout=30)


def _settings(command):
    return json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": 5}]}]}})


class WireTestBase(unittest.TestCase):
    def _file(self, text):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        tmp.write(text)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return tmp.name

    def _missing_path(self):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        tmp.close()
        os.unlink(tmp.name)
        self.addCleanup(lambda: os.path.exists(tmp.name) and os.unlink(tmp.name))
        return tmp.name

    def _data(self, path):
        return json.loads(Path(path).read_text())

    def _command(self, path):
        data = self._data(path)
        return data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]

    def _backups(self, path):
        return list(Path(path).parent.glob(Path(path).name + ".bak.*"))


class TestInterpreterPrefix(WireTestBase):
    def test_a_pinned_interpreter_survives(self):
        path = self._file(_settings("/usr/bin/python3 /old/checkout/hooks/airlock.py"))
        _run(path, apply_=True)
        self.assertEqual(self._command(path), "/usr/bin/python3 " + NEW_HOOK)

    def test_a_bare_path_stays_bare(self):
        path = self._file(_settings("/old/checkout/hooks/airlock.py"))
        _run(path, apply_=True)
        self.assertEqual(self._command(path), NEW_HOOK)

    def test_every_old_hook_name_is_matched_too(self):
        for old in ("plumbline", "jev_guard"):
            with self.subTest(old=old):
                path = self._file(_settings(
                    "/usr/bin/python3 /old/checkout/hooks/%s.py" % old))
                _run(path, apply_=True)
                self.assertEqual(self._command(path), "/usr/bin/python3 " + NEW_HOOK)


class TestSafety(WireTestBase):
    def test_print_changes_nothing(self):
        text = _settings("/usr/bin/python3 /old/hooks/airlock.py")
        path = self._file(text)
        proc = _run(path, apply_=False)
        self.assertEqual(Path(path).read_text(), text)
        self.assertIn("would repoint", proc.stdout)

    def test_apply_backs_the_file_up_first(self):
        path = self._file(_settings("/usr/bin/python3 /old/hooks/airlock.py"))
        _run(path, apply_=True)
        backups = self._backups(path)
        self.addCleanup(lambda: [b.unlink() for b in backups])
        self.assertEqual(len(backups), 1)
        self.assertIn("/old/hooks/airlock.py", backups[0].read_text())

    def test_it_never_writes_invalid_json(self):
        path = self._file(_settings("/usr/bin/python3 /old/hooks/airlock.py"))
        _run(path, apply_=True)
        json.loads(Path(path).read_text())

    def test_an_already_wired_file_is_left_alone(self):
        text = _settings("/usr/bin/python3 " + NEW_HOOK)
        path = self._file(text)
        proc = _run(path, apply_=True)
        self.assertEqual(Path(path).read_text(), text)
        self.assertIn("already wired", proc.stdout)

    def test_other_hooks_in_the_file_are_untouched(self):
        data = {"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [
                {"type": "command", "command": "/usr/bin/python3 /old/hooks/airlock.py"}]},
            {"matcher": "Bash", "hooks": [
                {"type": "command", "command": "/usr/bin/python3 /home/x/.claude/other-guard.py"}]},
        ]}}
        path = self._file(json.dumps(data))
        _run(path, apply_=True)
        out = json.loads(Path(path).read_text())
        self.assertEqual(out["hooks"]["PreToolUse"][1]["hooks"][0]["command"],
                         "/usr/bin/python3 /home/x/.claude/other-guard.py")


class TestInvalidJson(WireTestBase):
    def test_invalid_json_is_refused_with_no_write(self):
        text = "{not valid json"
        path = self._file(text)
        proc = _run(path, apply_=True)
        self.assertEqual(Path(path).read_text(), text)
        self.assertIn("not valid JSON", proc.stderr)

    def test_invalid_json_is_refused_in_print_mode_too(self):
        text = "{not valid json"
        path = self._file(text)
        proc = _run(path, apply_=False)
        self.assertEqual(Path(path).read_text(), text)
        self.assertIn("not valid JSON", proc.stderr)


class TestMissingFile(WireTestBase):
    """Bug: a FIRST install has no settings.json at all yet. --apply must
    create one with just the hook entries this run adds, not skip it."""

    def test_print_reports_what_would_be_created_and_writes_nothing(self):
        path = self._missing_path()
        proc = _run(path, apply_=False)
        self.assertFalse(os.path.exists(path))
        self.assertIn("would create", proc.stdout)
        self.assertIn(NEW_HOOK_COMMAND, proc.stdout)

    def test_apply_creates_it_with_just_the_pretooluse_entry(self):
        path = self._missing_path()
        proc = _run(path, apply_=True)
        self.assertTrue(os.path.exists(path))
        self.assertIn("created", proc.stdout)
        data = self._data(path)
        self.assertEqual(data, {"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [
                {"type": "command", "command": NEW_HOOK_COMMAND, "timeout": 5}]}]}})

    def test_apply_is_idempotent_on_a_freshly_created_file(self):
        path = self._missing_path()
        _run(path, apply_=True)
        first = Path(path).read_text()
        proc = _run(path, apply_=True)
        self.assertEqual(Path(path).read_text(), first)
        self.assertIn("already wired", proc.stdout)


class TestAddMissingHook(WireTestBase):
    """Bug: a settings.json that HAS hooks, just not airlock's, was left
    completely unwired ("no airlock.py hook command found, skipping")."""

    def test_a_file_with_no_airlock_hook_gets_one_added(self):
        text = json.dumps({"model": "sonnet"})
        path = self._file(text)
        proc = _run(path, apply_=True)
        self.assertIn("added PreToolUse", proc.stdout)
        data = self._data(path)
        self.assertEqual(data["model"], "sonnet")
        self.assertEqual(
            data["hooks"]["PreToolUse"][0]["hooks"][0]["command"], NEW_HOOK_COMMAND)

    def test_print_previews_the_add_and_writes_nothing(self):
        text = json.dumps({"model": "sonnet"})
        path = self._file(text)
        proc = _run(path, apply_=False)
        self.assertEqual(Path(path).read_text(), text)
        self.assertIn("added PreToolUse", proc.stdout)

    def test_backs_up_before_adding(self):
        text = json.dumps({"model": "sonnet"})
        path = self._file(text)
        _run(path, apply_=True)
        backups = self._backups(path)
        self.addCleanup(lambda: [b.unlink() for b in backups])
        self.assertEqual(len(backups), 1)
        self.assertEqual(json.loads(backups[0].read_text()), {"model": "sonnet"})

    def test_an_existing_unrelated_hook_survives_the_add(self):
        data = {"hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [
                {"type": "command", "command": "/home/x/.claude/other-guard.py"}]},
        ]}}
        path = self._file(json.dumps(data))
        _run(path, apply_=True)
        out = self._data(path)
        self.assertEqual(len(out["hooks"]["PreToolUse"]), 2)
        matchers = {e["matcher"] for e in out["hooks"]["PreToolUse"]}
        self.assertEqual(matchers, {"Bash", "*"})
        bash_entry = next(e for e in out["hooks"]["PreToolUse"] if e["matcher"] == "Bash")
        self.assertEqual(bash_entry["hooks"][0]["command"], "/home/x/.claude/other-guard.py")

    def test_an_existing_matcher_star_pretooluse_block_is_reused_not_duplicated(self):
        data = {"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [
                {"type": "command", "command": "/home/x/.claude/other-star-guard.py"}]},
        ]}}
        path = self._file(json.dumps(data))
        _run(path, apply_=True)
        out = self._data(path)
        self.assertEqual(len(out["hooks"]["PreToolUse"]), 1)
        commands = [h["command"] for h in out["hooks"]["PreToolUse"][0]["hooks"]]
        self.assertEqual(
            set(commands), {"/home/x/.claude/other-star-guard.py", NEW_HOOK_COMMAND})

    def test_adding_is_idempotent(self):
        text = json.dumps({"model": "sonnet"})
        path = self._file(text)
        _run(path, apply_=True)
        first = Path(path).read_text()
        proc = _run(path, apply_=True)
        self.assertEqual(Path(path).read_text(), first)
        self.assertTrue("nothing to add or repoint" in proc.stdout or "already wired" in proc.stdout)


class TestBelayFlag(WireTestBase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.wrapper = os.path.join(self._tmp.name, "airlock-belay-run")
        with open(self.wrapper, "w") as f:
            f.write("#!/usr/bin/env bash\necho stub\n")
        os.chmod(self.wrapper, 0o755)

    def test_belay_stop_hook_is_added_when_the_wrapper_exists(self):
        text = json.dumps({"model": "sonnet"})
        path = self._file(text)
        proc = _run(path, apply_=True, belay=True, belay_wrapper=self.wrapper)
        self.assertIn("added Stop (belay)", proc.stdout)
        out = self._data(path)
        stop = out["hooks"]["Stop"][0]
        self.assertEqual(stop["matcher"], "*")
        self.assertEqual(stop["hooks"][0]["command"], self.wrapper)
        self.assertEqual(stop["hooks"][0]["timeout"], 25)

    def test_belay_is_skipped_without_the_wrapper(self):
        text = json.dumps({"model": "sonnet"})
        path = self._file(text)
        proc = _run(path, apply_=True, belay=True,
                     belay_wrapper="/nonexistent/airlock-belay-run")
        out = self._data(path)
        self.assertNotIn("Stop", out.get("hooks", {}))
        self.assertIn("skipping Stop hook", proc.stdout)

    def test_belay_add_is_idempotent(self):
        text = json.dumps({"model": "sonnet"})
        path = self._file(text)
        _run(path, apply_=True, belay=True, belay_wrapper=self.wrapper)
        first = Path(path).read_text()
        proc = _run(path, apply_=True, belay=True, belay_wrapper=self.wrapper)
        self.assertEqual(Path(path).read_text(), first)
        self.assertTrue("nothing to add or repoint" in proc.stdout or "already wired" in proc.stdout)

    def test_missing_file_created_with_belay_when_wrapper_exists(self):
        path = self._missing_path()
        _run(path, apply_=True, belay=True, belay_wrapper=self.wrapper)
        data = self._data(path)
        self.assertEqual(data["hooks"]["Stop"][0]["hooks"][0]["command"], self.wrapper)


class TestFunctionHooksFlag(WireTestBase):
    def test_env_var_is_added(self):
        text = json.dumps({"model": "sonnet"})
        path = self._file(text)
        proc = _run(path, apply_=True, function_hooks=True)
        self.assertIn('env.CLAUDE_CODE_ENABLE_FUNCTION_HOOKS = "1"', proc.stdout)
        out = self._data(path)
        self.assertEqual(out["env"]["CLAUDE_CODE_ENABLE_FUNCTION_HOOKS"], "1")

    def test_existing_env_keys_survive(self):
        data = {"model": "sonnet", "env": {"SOME_OTHER_VAR": "x"}}
        path = self._file(json.dumps(data))
        _run(path, apply_=True, function_hooks=True)
        out = self._data(path)
        self.assertEqual(out["env"]["SOME_OTHER_VAR"], "x")
        self.assertEqual(out["env"]["CLAUDE_CODE_ENABLE_FUNCTION_HOOKS"], "1")

    def test_function_hooks_add_is_idempotent(self):
        text = json.dumps({"model": "sonnet"})
        path = self._file(text)
        _run(path, apply_=True, function_hooks=True)
        first = Path(path).read_text()
        proc = _run(path, apply_=True, function_hooks=True)
        self.assertEqual(Path(path).read_text(), first)
        self.assertTrue("nothing to add or repoint" in proc.stdout or "already wired" in proc.stdout)


if __name__ == "__main__":
    unittest.main()


class TestSessionCheckEntry(WireTestBase):
    """The SessionStart session check: a DEFAULT component, so wiring it has
    to be as careful as wiring the guard itself.

    It is added on a first install, it is idempotent, it lands under
    SessionStart and nowhere else, it never disturbs the PreToolUse entry, and
    a pointer at a file that is not there is SKIPPED rather than registered --
    a SessionStart hook that fails would print an error at the top of every
    single session, which is the exact opposite of what this component is for.
    """

    def _session_hook(self):
        """A real file, because _wire.py refuses to register a missing one."""
        tmp = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
        tmp.write("# stand-in for hooks/airlock_session_check.py\n")
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        # The pattern is anchored on the real name, so the path has to end in
        # it for the repoint/idempotency checks to see it at all.
        target = os.path.join(os.path.dirname(tmp.name), "hooks")
        os.makedirs(target, exist_ok=True)
        path = os.path.join(target, "airlock_session_check.py")
        with open(path, "w") as f:
            f.write("# stand-in\n")
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def _session_commands(self, path):
        data = self._data(path)
        out = []
        for entry in (data.get("hooks") or {}).get("SessionStart") or []:
            for h in entry.get("hooks") or []:
                out.append(h["command"])
        return out

    def test_a_first_install_adds_it(self):
        hook = self._session_hook()
        path = self._file(_settings(NEW_HOOK_COMMAND))
        _run(path, apply_=True, session_check=True, session_hook=hook)
        self.assertEqual(self._session_commands(path), ["%s %s" % (PYTHON3, hook)])

    def test_the_pretooluse_entry_is_untouched(self):
        hook = self._session_hook()
        path = self._file(_settings(NEW_HOOK_COMMAND))
        _run(path, apply_=True, session_check=True, session_hook=hook)
        self.assertEqual(self._command(path), NEW_HOOK_COMMAND)

    def test_it_is_idempotent(self):
        hook = self._session_hook()
        path = self._file(_settings(NEW_HOOK_COMMAND))
        _run(path, apply_=True, session_check=True, session_hook=hook)
        before = Path(path).read_text()
        result = _run(path, apply_=True, session_check=True, session_hook=hook)
        self.assertEqual(Path(path).read_text(), before)
        self.assertIn("already wired", result.stdout)

    def test_apply_backs_the_file_up_first(self):
        hook = self._session_hook()
        path = self._file(_settings(NEW_HOOK_COMMAND))
        _run(path, apply_=True, session_check=True, session_hook=hook)
        self.assertEqual(len(self._backups(path)), 1)

    def test_print_changes_nothing_but_says_what_it_would_do(self):
        hook = self._session_hook()
        path = self._file(_settings(NEW_HOOK_COMMAND))
        before = Path(path).read_text()
        result = _run(path, session_check=True, session_hook=hook)
        self.assertEqual(Path(path).read_text(), before)
        self.assertIn("SessionStart", result.stdout)

    def test_unrelated_hooks_and_keys_survive(self):
        hook = self._session_hook()
        path = self._file(json.dumps({
            "model": "opus",
            "hooks": {
                "PreToolUse": [{"matcher": "*", "hooks": [
                    {"type": "command", "command": NEW_HOOK_COMMAND, "timeout": 5}]}],
                "SessionStart": [{"matcher": "*", "hooks": [
                    {"type": "command", "command": "/usr/local/bin/mine"}]}],
            }}))
        _run(path, apply_=True, session_check=True, session_hook=hook)
        data = self._data(path)
        self.assertEqual(data["model"], "opus")
        self.assertIn("/usr/local/bin/mine", self._session_commands(path))
        self.assertIn("%s %s" % (PYTHON3, hook), self._session_commands(path))

    def test_a_missing_hook_file_is_skipped_not_registered(self):
        path = self._file(_settings(NEW_HOOK_COMMAND))
        result = _run(path, apply_=True, session_check=True,
                      session_hook="/nonexistent/hooks/airlock_session_check.py")
        self.assertEqual(self._session_commands(path), [])
        self.assertIn("skipping", result.stdout)

    def test_a_stale_session_check_path_is_repointed(self):
        hook = self._session_hook()
        path = self._file(json.dumps({"hooks": {
            "PreToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": NEW_HOOK_COMMAND, "timeout": 5}]}],
            "SessionStart": [{"matcher": "*", "hooks": [
                {"type": "command",
                 "command": "%s /old/release/hooks/airlock_session_check.py" % PYTHON3,
                 "timeout": 5}]}],
        }}))
        _run(path, apply_=True, session_check=True, session_hook=hook)
        self.assertEqual(self._session_commands(path), ["%s %s" % (PYTHON3, hook)])

    def test_repointing_the_guard_does_not_touch_the_session_check(self):
        # The two patterns must not overlap: `hooks/airlock_session_check.py`
        # does not end in `hooks/airlock.py`.
        hook = self._session_hook()
        session_cmd = "%s %s" % (PYTHON3, hook)
        path = self._file(json.dumps({"hooks": {
            "PreToolUse": [{"matcher": "*", "hooks": [
                {"type": "command",
                 "command": "%s /old/hooks/airlock.py" % PYTHON3, "timeout": 5}]}],
            "SessionStart": [{"matcher": "*", "hooks": [
                {"type": "command", "command": session_cmd, "timeout": 5}]}],
        }}))
        _run(path, apply_=True, session_check=True, session_hook=hook)
        self.assertEqual(self._command(path), NEW_HOOK_COMMAND)
        self.assertEqual(self._session_commands(path), [session_cmd])

    def test_a_brand_new_settings_file_gets_both_entries(self):
        hook = self._session_hook()
        path = self._missing_path()
        _run(path, apply_=True, session_check=True, session_hook=hook)
        data = self._data(path)
        self.assertEqual(
            data["hooks"]["PreToolUse"][0]["hooks"][0]["command"], NEW_HOOK_COMMAND)
        self.assertEqual(self._session_commands(path), ["%s %s" % (PYTHON3, hook)])

    def test_session_check_off_adds_nothing(self):
        hook = self._session_hook()
        path = self._file(_settings(NEW_HOOK_COMMAND))
        _run(path, apply_=True, session_check=False, session_hook=hook)
        self.assertEqual(self._session_commands(path), [])


class TestSessionCheckOnWindows(WireTestBase):
    """The Windows shape, by injection -- HOOK_COMMAND_QUOTED=1, the launcher
    spelling, and PowerShell's call operator."""

    WIN_LAUNCHER = "C:\\Users\\Someone\\AppData\\Local\\airlock\\airlock-hook.py"
    WIN_SESSION = "C:\\Users\\Someone\\AppData\\Local\\airlock\\airlock-session-check.py"
    WIN_PY = "C:\\Windows\\py.exe"

    def _win_run(self, path, session_hook, apply_=True, session_check=True):
        env = dict(os.environ)
        env["NEW_HOOK"] = self.WIN_LAUNCHER
        env["NEW_HOOK_COMMAND"] = '"%s" "%s"' % (self.WIN_PY, self.WIN_LAUNCHER)
        env["APPLY"] = "1" if apply_ else "0"
        env["BELAY"] = "0"
        env["BELAY_WRAPPER"] = ""
        env["FUNCTION_HOOKS"] = "0"
        env["HOOK_COMMAND_QUOTED"] = "1"
        env["SESSION_CHECK"] = "1" if session_check else "0"
        env["SESSION_CHECK_HOOK"] = session_hook
        env["SESSION_CHECK_COMMAND"] = '& "%s" "%s"' % (self.WIN_PY, session_hook)
        return subprocess.run([sys.executable, str(WIRE), str(path)],
                              capture_output=True, text=True, env=env, timeout=30)

    def _session_commands(self, path):
        data = self._data(path)
        out = []
        for entry in (data.get("hooks") or {}).get("SessionStart") or []:
            for h in entry.get("hooks") or []:
                out.append(h["command"])
        return out

    def test_the_windows_command_shape_is_added_verbatim(self):
        # The file has to exist for _wire.py to register it, so point at one
        # that does while keeping the Windows-shaped NAME.
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmpdir, ignore_errors=True))
        session_hook = os.path.join(tmpdir, "airlock-session-check.py")
        with open(session_hook, "w") as f:
            f.write("# stand-in\n")
        path = self._file(json.dumps({"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [
                {"type": "command",
                 "command": '"%s" "%s"' % (self.WIN_PY, self.WIN_LAUNCHER),
                 "timeout": 5}]}]}}))
        self._win_run(path, session_hook)
        self.assertEqual(self._session_commands(path),
                         ['& "%s" "%s"' % (self.WIN_PY, session_hook)])

    def test_it_is_idempotent_on_windows_too(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmpdir, ignore_errors=True))
        session_hook = os.path.join(tmpdir, "airlock-session-check.py")
        with open(session_hook, "w") as f:
            f.write("# stand-in\n")
        path = self._file(json.dumps({"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [
                {"type": "command",
                 "command": '"%s" "%s"' % (self.WIN_PY, self.WIN_LAUNCHER),
                 "timeout": 5}]}]}}))
        self._win_run(path, session_hook)
        before = Path(path).read_text()
        self._win_run(path, session_hook)
        self.assertEqual(Path(path).read_text(), before)


class TestWindowsShellShapeFollowsTheInstall(WireTestBase):
    """Git for Windows installed (or removed) after airlock: a re-wire must
    switch the call operator, or bash reads `& ...` as a syntax error, exits 2
    and blocks every tool call."""

    WIN_LAUNCHER = "C:\\Users\\Someone\\AppData\\Local\\airlock\\airlock-hook.py"
    WIN_PY = "C:\\Windows\\py.exe"

    def _run_win(self, path, command, apply_=True):
        env = dict(os.environ, NEW_HOOK=self.WIN_LAUNCHER, NEW_HOOK_COMMAND=command,
                   APPLY="1" if apply_ else "0", BELAY="0", BELAY_WRAPPER="",
                   FUNCTION_HOOKS="0", HOOK_COMMAND_QUOTED="1", SESSION_CHECK="0",
                   BROWSE_UNLOCK="0")
        return subprocess.run([sys.executable, str(WIRE), str(path)],
                              capture_output=True, text=True, env=env, timeout=30)

    def _command(self, path):
        return self._data(path)["hooks"]["PreToolUse"][0]["hooks"][0]["command"]

    def test_the_call_operator_is_dropped_once_git_bash_is_there(self):
        bare = '"%s" "%s"' % (self.WIN_PY, self.WIN_LAUNCHER)
        path = self._file(_settings("& " + bare))
        self._run_win(path, bare)
        self.assertEqual(self._command(path), bare)

    def test_the_call_operator_is_added_once_git_bash_is_gone(self):
        bare = '"%s" "%s"' % (self.WIN_PY, self.WIN_LAUNCHER)
        path = self._file(_settings(bare))
        self._run_win(path, "& " + bare)
        self.assertEqual(self._command(path), "& " + bare)

    def test_the_right_shape_is_left_alone(self):
        bare = '"%s" "%s"' % (self.WIN_PY, self.WIN_LAUNCHER)
        path = self._file(_settings(bare))
        before = Path(path).read_text()
        out = self._run_win(path, bare)
        self.assertEqual(Path(path).read_text(), before)
        self.assertIn("already wired", out.stdout)


class TestOneBadFile(WireTestBase):
    def test_an_unwritable_file_is_reported_and_the_rest_still_wired(self):
        blocker = self._file("not a directory")
        bad = os.path.join(blocker, "settings.json")
        good = self._missing_path()
        self.addCleanup(lambda: os.path.exists(good) and os.unlink(good))
        env = dict(os.environ, NEW_HOOK=NEW_HOOK, NEW_HOOK_COMMAND=NEW_HOOK_COMMAND,
                   APPLY="1", BELAY="0", FUNCTION_HOOKS="0", SESSION_CHECK="0",
                   BROWSE_UNLOCK="0")
        proc = subprocess.run([sys.executable, str(WIRE), bad, good],
                              capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("could not wire", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertTrue(os.path.exists(good))


class TestBrowseUnlockEntry(WireTestBase):
    """The PostToolUse browse-unlock entry: added, repointed, idempotent, and
    never merged into a matcher="*" block. It is the only hook here with a
    real matcher, because it has exactly one tool to watch."""

    MATCHER = "mcp__browse__browse"

    def _hook_file(self, name="airlock_browse_unlock.py"):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmpdir, ignore_errors=True))
        path = os.path.join(tmpdir, "hooks")
        os.makedirs(path)
        hook = os.path.join(path, name)
        with open(hook, "w") as f:
            f.write("# stand-in\n")
        return hook

    def _post_entries(self, path):
        return (self._data(path).get("hooks") or {}).get("PostToolUse") or []

    def _failure_entries(self, path):
        return (self._data(path).get("hooks") or {}).get("PostToolUseFailure") or []

    def _post_commands(self, path, entries=None):
        out = []
        for entry in (self._post_entries(path) if entries is None else entries):
            for h in entry.get("hooks") or []:
                out.append(h.get("command"))
        return out

    def test_a_fresh_settings_file_gets_the_entry(self):
        hook = self._hook_file()
        path = self._missing_path()
        _run(path, apply_=True, browse_unlock=True, browse_hook=hook)
        entries = self._post_entries(path)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["matcher"], self.MATCHER)
        self.assertEqual(entries[0]["hooks"][0]["command"],
                         "%s %s" % (PYTHON3, hook))
        self.assertEqual(entries[0]["hooks"][0]["timeout"], 5)
        # And again under PostToolUseFailure, where an errored call lands.
        failure = self._failure_entries(path)
        self.assertEqual(len(failure), 1)
        self.assertEqual(failure[0]["matcher"], self.MATCHER)
        self.assertEqual(failure[0]["hooks"][0]["command"],
                         "%s %s" % (PYTHON3, hook))

    def test_an_older_install_gets_the_failure_entry_added(self):
        """A settings file wired before PostToolUseFailure was: the
        PostToolUse entry is kept as it is and the missing one is added."""
        hook = self._hook_file()
        existing = "/usr/bin/python3.11 %s" % hook
        path = self._file(json.dumps({"hooks": {
            "PreToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": NEW_HOOK_COMMAND, "timeout": 5}]}],
            "PostToolUse": [{"matcher": self.MATCHER, "hooks": [
                {"type": "command", "command": existing, "timeout": 5}]}]}}))
        out = _run(path, apply_=True, browse_unlock=True, browse_hook=hook)
        self.assertEqual(self._post_commands(path), [existing])
        self.assertEqual(self._post_commands(path, self._failure_entries(path)),
                         ["%s %s" % (PYTHON3, hook)])
        self.assertIn("PostToolUseFailure", out.stdout)
        before = Path(path).read_text()
        out = _run(path, apply_=True, browse_unlock=True, browse_hook=hook)
        self.assertEqual(Path(path).read_text(), before)
        self.assertIn("already wired", out.stdout)

    def test_it_is_added_to_a_file_that_already_wires_the_guard(self):
        hook = self._hook_file()
        path = self._file(_settings(NEW_HOOK_COMMAND))
        _run(path, apply_=True, browse_unlock=True, browse_hook=hook)
        self.assertEqual(self._post_commands(path), ["%s %s" % (PYTHON3, hook)])
        # The PreToolUse entry it found is untouched.
        self.assertEqual(self._command(path), NEW_HOOK_COMMAND)

    def test_it_is_idempotent(self):
        hook = self._hook_file()
        path = self._file(_settings(NEW_HOOK_COMMAND))
        _run(path, apply_=True, browse_unlock=True, browse_hook=hook)
        before = Path(path).read_text()
        out = _run(path, apply_=True, browse_unlock=True, browse_hook=hook)
        self.assertEqual(Path(path).read_text(), before)
        self.assertIn("already wired", out.stdout)

    def test_a_stale_path_is_repointed_and_the_interpreter_kept(self):
        hook = self._hook_file()
        old = "/opt/airlock/releases/20250101/hooks/airlock_browse_unlock.py"
        path = self._file(json.dumps({"hooks": {
            "PreToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": NEW_HOOK_COMMAND, "timeout": 5}]}],
            "PostToolUse": [{"matcher": self.MATCHER, "hooks": [
                {"type": "command", "command": "/usr/bin/python3.11 %s" % old,
                 "timeout": 5}]}]}}))
        out = _run(path, apply_=True, browse_unlock=True, browse_hook=hook)
        self.assertEqual(self._post_commands(path),
                         ["/usr/bin/python3.11 %s" % hook])
        self.assertIn("repointed", out.stdout)

    def test_it_never_joins_a_star_matcher_block(self):
        """Merged into a "*" entry it would run after every tool call in the
        session, which is the one thing a PostToolUse hook must not do."""
        hook = self._hook_file()
        path = self._file(json.dumps({"hooks": {
            "PreToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": NEW_HOOK_COMMAND, "timeout": 5}]}],
            "PostToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": "/usr/bin/true", "timeout": 5}]}]}}))
        _run(path, apply_=True, browse_unlock=True, browse_hook=hook)
        entries = self._post_entries(path)
        self.assertEqual([e["matcher"] for e in entries], ["*", self.MATCHER])
        self.assertEqual([h["command"] for h in entries[0]["hooks"]], ["/usr/bin/true"])

    def test_a_missing_hook_file_is_skipped_and_said_so(self):
        path = self._file(_settings(NEW_HOOK_COMMAND))
        out = _run(path, apply_=True, browse_unlock=True,
                   browse_hook="/nonexistent/hooks/airlock_browse_unlock.py")
        self.assertEqual(self._post_commands(path), [])
        self.assertIn("skipping PostToolUse entry", out.stdout)

    def test_off_means_no_entry(self):
        hook = self._hook_file()
        path = self._file(_settings(NEW_HOOK_COMMAND))
        _run(path, apply_=True, browse_unlock=False, browse_hook=hook)
        self.assertEqual(self._post_commands(path), [])
        self.assertEqual(self._failure_entries(path), [])

    def test_print_mode_touches_nothing(self):
        hook = self._hook_file()
        path = self._file(_settings(NEW_HOOK_COMMAND))
        before = Path(path).read_text()
        out = _run(path, apply_=False, browse_unlock=True, browse_hook=hook)
        self.assertEqual(Path(path).read_text(), before)
        self.assertIn("browse unlock", out.stdout)
