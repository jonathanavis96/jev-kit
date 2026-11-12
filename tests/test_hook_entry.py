
import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import glob
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from airlock import platform_compat

HOOK_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks", "airlock.py")

_spec = importlib.util.spec_from_file_location("airlock_hook_entry", HOOK_PATH)
assert _spec is not None and _spec.loader is not None
hook_entry = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hook_entry)


def _leftover_payload_files():
    return set(glob.glob(os.path.join(tempfile.gettempdir(), "airlock-*.json")))


def _remove_quietly(path):
    """Delete a file, never complaining. Used where subprocess.Popen is
    mocked: the real worker then never runs, so it never consumes and deletes
    the payload file the hook wrote, and one would be left behind in %TEMP%
    (or /tmp) on every run of the suite."""
    try:
        import os as _os
        _os.remove(path)
    except Exception:
        pass


class TestHookEntry(unittest.TestCase):
    def setUp(self):
        # main() writes a real (mode-600) temp payload file before handing off
        # to subprocess.Popen. When a test mocks Popen, nothing ever consumes
        # or deletes that file, so track and remove whatever appears.
        self._before_tmp = _leftover_payload_files()

    def tearDown(self):
        for path in _leftover_payload_files() - self._before_tmp:
            try:
                os.remove(path)
            except OSError:
                pass

    def test_kill_switch_env_var_no_spawn(self):
        with mock.patch.dict(os.environ, {"AIRLOCK_DISABLE": "1"}):
            with mock.patch("subprocess.Popen") as popen:
                self.assertTrue(hook_entry._disabled())
                popen.assert_not_called()

    def test_kill_switch_disable_file_no_spawn(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AIRLOCK_DISABLE", None)
            with mock.patch("os.path.exists", return_value=True):
                self.assertTrue(hook_entry._disabled())

    def test_no_kill_switch_present(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AIRLOCK_DISABLE", None)
            with mock.patch("os.path.exists", return_value=False):
                self.assertFalse(hook_entry._disabled())

    def test_no_rule_matches_does_not_spawn(self):
        """After the all-tools widening the hook is registered for every tool,
        so the filter is the rules table, not the tool name: a Read of an
        ordinary file matches no rule and must not spawn anything."""
        payload = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/tmp/plain.txt"}})
        with mock.patch("sys.stdin.read", return_value=payload), \
             mock.patch.object(hook_entry, "_disabled", return_value=False), \
             mock.patch("subprocess.Popen") as popen:
            hook_entry.main()
            popen.assert_not_called()

    def test_garbage_stdin_fails_open_silently(self):
        with mock.patch("sys.stdin.read", return_value="not json{{{"), \
             mock.patch("subprocess.Popen") as popen:
            hook_entry.main()  # must not raise
            popen.assert_not_called()

    def test_bash_payload_spawns_detached_worker(self):
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "grep -r foo ."}})
        # Pin the mode: this box's ~/.config/airlock/mode says "enforce",
        # and only shadow mode spawns the detached worker.
        with mock.patch("sys.stdin.read", return_value=payload), \
             mock.patch.object(hook_entry, "_resolve_mode", return_value="shadow"), \
             mock.patch.object(hook_entry, "_disabled", return_value=False), \
             mock.patch("subprocess.Popen") as popen:
            hook_entry.main()
            popen.assert_called_once()
            args, kwargs = popen.call_args
            self.addCleanup(_remove_quietly, args[0][-1])
            # The detached-child mechanism is platform-specific:
            # start_new_session on POSIX, the DETACHED_PROCESS |
            # CREATE_NEW_PROCESS_GROUP creation flags on Windows. Both are
            # asserted directly in tests/test_windows_platform.py; here the
            # assertion is just that the hook used whichever this platform
            # has, rather than hard-coding one of them.
            expected = platform_compat.detached_popen_kwargs()
            for key, value in expected.items():
                self.assertEqual(kwargs.get(key), value)
            self.assertEqual(kwargs.get("stdin"), subprocess.DEVNULL)
            self.assertEqual(kwargs.get("stdout"), subprocess.DEVNULL)
            self.assertEqual(kwargs.get("stderr"), subprocess.DEVNULL)

    def test_popen_failure_is_swallowed(self):
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "grep -r foo ."}})
        with mock.patch("sys.stdin.read", return_value=payload), \
             mock.patch.object(hook_entry, "_resolve_mode", return_value="shadow"), \
             mock.patch.object(hook_entry, "_disabled", return_value=False), \
             mock.patch("subprocess.Popen", side_effect=OSError("nope")):
            hook_entry.main()  # must not raise

    def test_entry_point_is_fast(self):
        """The hook must return well under 100ms -- it only reads stdin,
        writes a temp file and spawns a detached process; it never waits on
        the network.

        This spawns a REAL detached worker (to prove the whole entry path,
        including the actual fork, is fast), but points HOME at an empty temp
        dir and strips TYPESAFE_API_KEY so the worker finds no API key and
        exits immediately without any real network call or write to the real
        shadow log -- this is a unit test, not tests/live_smoke.py.

        The budget is higher on Windows, and honestly so. Almost all of it is
        CPython interpreter start-up plus the antivirus filter that sits in
        front of every CreateProcess there: measured at roughly 450ms on the
        Windows 11 workstation this was tested on, against roughly 40ms on
        Linux, for the same code doing the same work. No change to this
        repository moves that number -- it is the cost of starting Python on
        Windows at all, which is paid by every PreToolUse hook on the machine,
        not just this one. What the budget still catches is the thing it was
        written for: an import or a filesystem walk creeping into the hot path.
        """
        payload = json.dumps(
            {
                "session_id": "s1",
                "cwd": "/tmp",
                "tool_name": "Agent",
                "tool_input": {"subagent_type": "fable", "description": "d", "prompt": "p" * 500},
            }
        )
        with tempfile.TemporaryDirectory() as fake_home:
            env = dict(os.environ)
            env.pop("TYPESAFE_API_KEY", None)
            env["HOME"] = fake_home
            # HOME alone isolates nothing on Windows: airlock/paths.py
            # resolves config, state and releases from %APPDATA% and
            # %LOCALAPPDATA%, so the real detached worker this test spawns
            # would write its shadow log into the user's actual profile.
            # Observed doing exactly that on the Windows machine this was
            # tested on, which is why all four are pinned.
            env["USERPROFILE"] = fake_home
            env["APPDATA"] = os.path.join(fake_home, "AppData", "Roaming")
            env["LOCALAPPDATA"] = os.path.join(fake_home, "AppData", "Local")
            start = time.monotonic()
            proc = subprocess.run(
                [sys.executable, HOOK_PATH],
                input=payload,
                capture_output=True,
                text=True,
                timeout=5,
                env=env,
            )
            elapsed_ms = (time.monotonic() - start) * 1000
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        budget_ms = 800 if sys.platform == "win32" else 100
        self.assertLess(elapsed_ms, budget_ms,
                        "hook entry point took %.1fms (budget %dms on %s)"
                        % (elapsed_ms, budget_ms, sys.platform))


class TestModeDispatch(unittest.TestCase):
    def setUp(self):
        self._before_tmp = _leftover_payload_files()

    def tearDown(self):
        for path in _leftover_payload_files() - self._before_tmp:
            try:
                os.remove(path)
            except OSError:
                pass

    def test_shadow_mode_still_detaches_and_prints_nothing(self):
        """Byte-for-byte unchanged (Part A item 7): explicit shadow mode still
        spawns the detached worker and never writes to stdout."""
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "grep -r foo ."}})
        with mock.patch.dict(os.environ, {"AIRLOCK_MODE": "shadow"}), \
             mock.patch("sys.stdin.read", return_value=payload), \
             mock.patch.object(hook_entry, "_disabled", return_value=False), \
             mock.patch("subprocess.Popen") as popen, \
             mock.patch("sys.stdout.write") as write:
            hook_entry.main()
            popen.assert_called_once()
            write.assert_not_called()

    def test_default_mode_with_no_env_or_file_is_shadow(self):
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "grep -r foo ."}})
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AIRLOCK_MODE", None)
            with mock.patch("sys.stdin.read", return_value=payload), \
                 mock.patch.object(hook_entry, "_disabled", return_value=False), \
                 mock.patch.object(hook_entry, "_resolve_mode", return_value="shadow"), \
                 mock.patch("subprocess.Popen") as popen:
                hook_entry.main()
                popen.assert_called_once()

    def test_off_mode_does_nothing(self):
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "grep -r foo ."}})
        with mock.patch("sys.stdin.read", return_value=payload), \
             mock.patch.object(hook_entry, "_disabled", return_value=False), \
             mock.patch.object(hook_entry, "_resolve_mode", return_value="off"), \
             mock.patch("subprocess.Popen") as popen:
            hook_entry.main()
            popen.assert_not_called()

    def test_enforce_mode_calls_enforce_handle_not_worker(self):
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "grep -r foo ."}})
        with mock.patch("sys.stdin.read", return_value=payload), \
             mock.patch.object(hook_entry, "_disabled", return_value=False), \
             mock.patch.object(hook_entry, "_resolve_mode", return_value="enforce"), \
             mock.patch("subprocess.Popen") as popen:
            from airlock import enforce as enforce_mod
            with mock.patch.object(enforce_mod, "handle", return_value=False) as handle:
                hook_entry.main()
                handle.assert_called_once()
            popen.assert_not_called()

    def test_bench_force_mode_bypasses_kill_switch(self):
        """The A/B bench's escape hatch: AIRLOCK_BENCH_FORCE_MODE skips the
        shared kill switch entirely, so a bench trial can force this
        worktree's hook into enforce mode even while AIRLOCK_DISABLE=1 is
        set to silence the live main-checkout copy of the same hook."""
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "grep -r foo ."}})
        with mock.patch.dict(os.environ, {"AIRLOCK_DISABLE": "1", "AIRLOCK_BENCH_FORCE_MODE": "enforce"}), \
             mock.patch("sys.stdin.read", return_value=payload), \
             mock.patch.object(hook_entry, "_disabled") as disabled:
            from airlock import enforce as enforce_mod
            with mock.patch.object(enforce_mod, "handle", return_value=False) as handle:
                hook_entry.main()
                handle.assert_called_once()
            disabled.assert_not_called()

    def test_bench_force_mode_with_invalid_value_falls_back_to_kill_switch(self):
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "grep -r foo ."}})
        with mock.patch.dict(os.environ, {"AIRLOCK_BENCH_FORCE_MODE": "bogus"}), \
             mock.patch("sys.stdin.read", return_value=payload), \
             mock.patch.object(hook_entry, "_disabled", return_value=True) as disabled, \
             mock.patch("subprocess.Popen") as popen:
            hook_entry.main()
            disabled.assert_called_once()
            popen.assert_not_called()

    def test_kill_switch_wins_even_in_enforce_mode(self):
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "grep -r foo ."}})
        with mock.patch("sys.stdin.read", return_value=payload), \
             mock.patch.object(hook_entry, "_disabled", return_value=True), \
             mock.patch.object(hook_entry, "_resolve_mode", return_value="enforce") as resolve_mode:
            from airlock import enforce as enforce_mod
            with mock.patch.object(enforce_mod, "handle") as handle:
                hook_entry.main()
                handle.assert_not_called()
            resolve_mode.assert_not_called()


    def test_utf8_payload_read_through_a_code_page_stdin_is_still_judged(self):
        """Native Windows decodes a piped stdin with the ANSI code page. A
        UTF-8 payload holding a byte cp1252 leaves undefined (0x81 in 'Á')
        used to raise in read() and the hook skipped the call unjudged."""
        import io
        payload = json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": "grep -r \u00c1 ."}},
            ensure_ascii=False).encode("utf-8")
        fake_stdin = io.TextIOWrapper(io.BytesIO(payload), encoding="cp1252")
        with mock.patch("sys.stdin", fake_stdin), \
             mock.patch.object(hook_entry, "_disabled", return_value=False), \
             mock.patch.object(hook_entry, "_resolve_mode", return_value="enforce"):
            from airlock import enforce as enforce_mod
            with mock.patch.object(enforce_mod, "handle", return_value=False) as handle:
                hook_entry.main()
                handle.assert_called_once()
                self.assertEqual(handle.call_args[0][0]["tool_input"]["command"],
                                 "grep -r \u00c1 .")


if __name__ == "__main__":
    unittest.main()
