"""The native-Windows installer, doctor helpers, uninstaller and Everything
detection -- all exercised on Linux.

The installer is run for real against a throwaway directory tree with
AIRLOCK_FORCE_WINDOWS_INSTALL=1, which is the single escape hatch
windows_common.require_windows() offers. Everything that genuinely needs
Windows (the `mklink /J` junction, `schtasks`) is allowed to fail and is
asserted to fail SOFTLY -- that is the actual requirement: the text pointer
has to carry the install when the junction cannot be made.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL_DIR = os.path.join(REPO_ROOT, "install")
if INSTALL_DIR not in sys.path:
    sys.path.insert(0, INSTALL_DIR)

import windows_common as wc
import windows_install
import windows_uninstall

from airlock import everything


class _Sink:
    """Swallow the installer's own reporting: the test asserts on the files it
    produced, and 40 copies of the prerequisite advice make a test run
    unreadable."""

    def write(self, _text):
        return None

    def flush(self):
        return None


class TestEverythingDetection(unittest.TestCase):
    """Detection only. This module must never install anything."""

    def test_the_module_never_shells_out_to_an_installer(self):
        with open(os.path.join(REPO_ROOT, "airlock", "everything.py")) as f:
            source = f.read()
        for forbidden in ("winget", "choco", "msiexec", "Invoke-WebRequest",
                          "urlretrieve", "curl "):
            self.assertNotIn(forbidden, source)

    def test_an_explicit_override_is_tried_first(self):
        env = {"AIRLOCK_ES_PATH": "D:\\tools\\es.exe", "PATH": "C:\\Windows"}
        self.assertEqual(everything.candidate_paths(env)[0], "D:\\tools\\es.exe")

    def test_path_then_the_usual_install_directories(self):
        # PATH is split on os.pathsep, which is ";" on Windows -- passed
        # explicitly here because this test runs on Linux, where os.pathsep
        # is ":" and `C:\bin` would be split at the drive letter.
        env = {"PATH": "C:\\bin;C:\\Windows",
               "ProgramFiles": "C:\\Program Files"}
        candidates = everything.candidate_paths(env, pathsep=";")
        self.assertIn(os.path.join("C:\\bin", "es.exe"), candidates)
        self.assertIn(os.path.join("C:\\Program Files", "Everything", "es.exe"),
                      candidates)

    def test_find_es_returns_the_first_that_exists(self):
        env = {"PATH": "C:\\bin", "ProgramFiles": "C:\\Program Files"}
        wanted = os.path.join("C:\\Program Files", "Everything", "es.exe")
        found = everything.find_es(env=env, exists=lambda p: p == wanted)
        self.assertEqual(found, wanted)

    def test_find_es_returns_none_when_it_is_simply_not_there(self):
        self.assertIsNone(everything.find_es(env={"PATH": "C:\\bin"},
                                             exists=lambda _p: False))

    def test_service_running_reads_sc_query(self):
        def runner(argv):
            if argv[0] == "sc":
                return 0, "SERVICE_NAME: Everything\n        STATE : 4  RUNNING"
            return 1, ""
        self.assertIs(everything.service_running(runner=runner), True)

    def test_a_per_user_install_has_no_service_so_tasklist_decides(self):
        def runner(argv):
            if argv[0] == "sc":
                return 1060, "The specified service does not exist"
            return 0, "Everything.exe   1234 Console  1  50,000 K"
        self.assertIs(everything.service_running(runner=runner), True)

    def test_installed_but_not_running(self):
        def runner(argv):
            if argv[0] == "sc":
                return 1060, "The specified service does not exist"
            return 0, "INFO: No tasks are running which match the specified criteria."
        self.assertIs(everything.service_running(runner=runner), False)

    def test_neither_probe_runnable_is_unknown_not_false(self):
        """On Linux neither command exists. "I could not tell" is a different
        answer from "no", and the doctor reports it as skip rather than FAIL."""
        self.assertIsNone(everything.service_running(
            runner=lambda _argv: (1, "No such file or directory")))

    def test_status_advice_names_the_separate_download(self):
        status = everything.status(env={"PATH": ""}, runner=lambda _a: (1, "x"),
                                   exists=lambda _p: False)
        self.assertIsNone(status["es_path"])
        self.assertFalse(status["ok"])
        self.assertIn("SEPARATE download", status["advice"])
        self.assertIn("voidtools.com", status["advice"])
        self.assertIn("will not install it for you", status["advice"])

    def test_status_advice_when_the_index_is_not_running(self):
        status = everything.status(
            env={"PATH": "C:\\bin"}, pathsep=";",
            runner=lambda argv: (0, "No tasks are running") if argv[0] == "tasklist"
            else (1060, "does not exist"),
            exists=lambda p: p.endswith("es.exe"))
        self.assertIsNotNone(status["es_path"])
        self.assertFalse(status["ok"])
        self.assertIn("index does not appear to be running", status["advice"])


class TestHookCommandShape(unittest.TestCase):
    """The hook command is one of two shapes and they are not interchangeable.

    Claude Code's settings reference on a command hook's `shell`: "Defaults to
    `bash`, or to `powershell` on Windows when Git Bash isn't installed."
    `"a" "b"` runs in bash and does NOT run in PowerShell, which needs the
    call operator.
    """

    PY = "C:\\Windows\\py.exe"
    LAUNCHER = "C:\\Users\\alice\\AppData\\Local\\airlock\\airlock-hook.py"

    def test_with_git_bash_it_is_two_quoted_words(self):
        cmd = wc.hook_command(self.PY, self.LAUNCHER, git_bash="C:\\Git\\bin\\bash.exe")
        self.assertEqual(cmd, '"%s" "%s"' % (self.PY, self.LAUNCHER))
        self.assertFalse(cmd.startswith("&"))

    def test_without_git_bash_it_gets_the_powershell_call_operator(self):
        cmd = wc.hook_command(self.PY, self.LAUNCHER, git_bash=None)
        self.assertTrue(cmd.startswith("& "))
        self.assertIn('"%s"' % self.LAUNCHER, cmd)

    def test_a_profile_with_a_space_is_quoted_either_way(self):
        launcher = "C:\\Users\\Jane Smith\\AppData\\Local\\airlock\\airlock-hook.py"
        for git_bash in ("C:\\Git\\bin\\bash.exe", None):
            cmd = wc.hook_command(self.PY, launcher, git_bash)
            self.assertIn('"%s"' % launcher, cmd)

    def test_the_path_is_absolute_never_a_tilde_or_a_variable(self):
        cmd = wc.hook_command(self.PY, self.LAUNCHER, None)
        self.assertNotIn("~", cmd)
        self.assertNotIn("%", cmd)
        self.assertNotIn("$", cmd)

    def test_git_bash_detection_honours_the_documented_setting(self):
        env = {"CLAUDE_CODE_GIT_BASH_PATH": "D:\\Git\\bin\\bash.exe"}
        with mock.patch("os.path.isfile", side_effect=lambda p: p == env[
                "CLAUDE_CODE_GIT_BASH_PATH"]):
            self.assertEqual(wc.find_git_bash(env), env["CLAUDE_CODE_GIT_BASH_PATH"])

    def test_the_microsoft_store_python_stub_is_never_chosen(self):
        """The stub on PATH is not an interpreter; picking it produces a hook
        command that opens the Store instead of running the guard."""
        env = {"PATH": "C:\\Users\\alice\\AppData\\Local\\Microsoft\\WindowsApps",
               "SystemRoot": "C:\\Windows"}
        with mock.patch("os.path.isfile", return_value=True), \
             mock.patch.object(wc.sys, "executable",
                               "C:\\Users\\a\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe"):
            found = wc.find_python(env)
        self.assertIsNotNone(found)
        self.assertNotIn("windowsapps", found.lower())


class TestInstallerEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="airlock-win-install-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.profile = os.path.join(self.tmp, "profile")
        self.env = {
            "AIRLOCK_FORCE_WINDOWS_INSTALL": "1",
            "AIRLOCK_HOME": os.path.join(self.tmp, "home"),
            "AIRLOCK_CONFIG_DIR": os.path.join(self.tmp, "cfg"),
            "AIRLOCK_STATE_DIR": os.path.join(self.tmp, "state"),
            "USERPROFILE": self.profile,
        }
        self.settings = os.path.join(self.profile, ".claude", "settings.json")

    def _install(self, *argv):
        with mock.patch.dict(os.environ, self.env, clear=False), \
             mock.patch("sys.stdout", new_callable=_Sink):
            return windows_install.main(list(argv) + ["--source", REPO_ROOT])

    def _uninstall(self, *argv):
        with mock.patch.dict(os.environ, self.env, clear=False), \
             mock.patch("sys.stdout", new_callable=_Sink):
            return windows_uninstall.main(list(argv))

    def _read_settings(self):
        with open(self.settings) as f:
            return json.load(f)

    def _hook_command(self):
        return self._read_settings()["hooks"]["PreToolUse"][0]["hooks"][0]["command"]

    def test_check_only_changes_nothing_at_all(self):
        self.assertEqual(self._install("--check-only"), 0)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "home")))
        self.assertFalse(os.path.exists(self.settings))

    def test_install_without_wire_never_touches_settings_json(self):
        self.assertEqual(self._install(), 0)
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, "home", "airlock-hook.py")))
        self.assertFalse(os.path.exists(self.settings))

    def test_a_release_a_pointer_and_a_launcher(self):
        self._install()
        home = os.path.join(self.tmp, "home")
        with open(os.path.join(home, "current.txt")) as f:
            release = f.read().strip()
        self.assertTrue(os.path.isdir(release))
        self.assertTrue(os.path.isfile(os.path.join(release, "hooks", "airlock.py")))
        self.assertTrue(os.path.isfile(os.path.join(home, "airlock-hook.py")))

    def test_the_pointer_resolves_whether_or_not_a_junction_was_made(self):
        """This is the whole reason there are two mechanisms.

        On Linux `mklink` does not exist, which is the same outcome as a
        non-NTFS or network volume on Windows: no junction, and the text
        pointer has to carry the install on its own. On Windows the junction
        normally succeeds. Either way `current` must resolve and `current.txt`
        must be written, so that is what is asserted rather than which of the
        two happened to be available."""
        self._install()
        home = os.path.join(self.tmp, "home")
        self.assertTrue(os.path.isfile(os.path.join(home, "current.txt")))
        with mock.patch.dict(os.environ, self.env, clear=False):
            resolved = wc.resolve_current()
        self.assertIsNotNone(resolved)
        self.assertTrue(os.path.isfile(os.path.join(resolved, "hooks", "airlock.py")))

    def test_a_rollback_in_current_txt_wins_over_the_junction(self):
        """The documented rollback is one edit of current.txt. Read after the
        junction, it changed nothing on a machine that had a junction."""
        home = os.path.join(self.tmp, "home")
        old_release = os.path.join(home, "releases", "old")
        new_release = os.path.join(home, "current")  # stands in for the junction
        os.makedirs(old_release)
        os.makedirs(new_release)
        with open(os.path.join(home, "current.txt"), "w") as f:
            f.write(old_release + "\n")
        with mock.patch.dict(os.environ, self.env, clear=False):
            self.assertEqual(wc.resolve_current(), old_release)
        ns = {"__file__": os.path.join(home, "airlock-hook.py")}
        exec(compile(wc.LAUNCHER_SOURCE.replace('if __name__ == "__main__":', "if False:"),
                     "launcher", "exec"), ns)
        self.assertEqual(ns["_release_root"](), old_release)
        os.remove(os.path.join(home, "current.txt"))
        self.assertEqual(ns["_release_root"](), new_release)

    def test_the_release_copy_leaves_the_repository_noise_behind(self):
        self._install()
        with open(os.path.join(self.tmp, "home", "current.txt")) as f:
            release = f.read().strip()
        for noise in (".git", "graphify-out", "__pycache__"):
            self.assertFalse(os.path.exists(os.path.join(release, noise)), noise)

    def test_the_mode_file_says_shadow(self):
        self._install()
        with open(os.path.join(self.tmp, "cfg", "mode")) as f:
            self.assertEqual(f.read().strip(), "shadow")

    def test_an_existing_mode_is_never_reset(self):
        """A machine someone armed must not be silently disarmed by a
        reinstall."""
        os.makedirs(os.path.join(self.tmp, "cfg"), exist_ok=True)
        with open(os.path.join(self.tmp, "cfg", "mode"), "w") as f:
            f.write("enforce\n")
        self._install()
        with open(os.path.join(self.tmp, "cfg", "mode")) as f:
            self.assertEqual(f.read().strip(), "enforce")

    def test_wire_creates_settings_json_with_the_hook(self):
        self._install("--wire")
        command = self._hook_command()
        self.assertIn("airlock-hook.py", command)
        self.assertEqual(self._read_settings()["hooks"]["PreToolUse"][0]["matcher"], "*")

    def test_wire_backs_up_before_editing_an_existing_file(self):
        os.makedirs(os.path.dirname(self.settings), exist_ok=True)
        with open(self.settings, "w") as f:
            json.dump({"hooks": {"Stop": [{"matcher": "*", "hooks": [
                {"type": "command", "command": "somebody-elses-hook"}]}]}}, f)
        self._install("--wire")
        backups = [n for n in os.listdir(os.path.dirname(self.settings))
                   if ".bak." in n]
        self.assertTrue(backups)

    def test_an_unrelated_hook_survives_wiring(self):
        os.makedirs(os.path.dirname(self.settings), exist_ok=True)
        with open(self.settings, "w") as f:
            json.dump({"hooks": {"Stop": [{"matcher": "*", "hooks": [
                {"type": "command", "command": "somebody-elses-hook"}]}]},
                "env": {"KEEP": "me"}}, f)
        self._install("--wire")
        data = self._read_settings()
        self.assertEqual(data["env"], {"KEEP": "me"})
        self.assertEqual(data["hooks"]["Stop"][0]["hooks"][0]["command"],
                         "somebody-elses-hook")

    def test_wiring_twice_is_a_no_op(self):
        self._install("--wire")
        first = self._read_settings()
        self._install("--wire")
        self.assertEqual(self._read_settings(), first)
        self.assertEqual(len(self._read_settings()["hooks"]["PreToolUse"]), 1)

    def test_no_scheduled_task_unless_it_was_asked_for(self):
        with mock.patch.object(wc, "create_health_task") as create:
            self._install()
            create.assert_not_called()

    def test_the_task_is_created_only_with_the_explicit_flag(self):
        with mock.patch.object(wc, "create_health_task",
                               return_value=(True, "")) as create:
            self._install("--schedule-health")
            create.assert_called_once()

    def test_nothing_is_written_outside_the_directories_we_were_given(self):
        self._install("--wire")
        for path in (os.path.join(self.tmp, "home"), os.path.join(self.tmp, "cfg"),
                     os.path.join(self.tmp, "state"), self.profile):
            self.assertTrue(os.path.isdir(path), path)


class TestReleasePruning(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_a_copied_release_is_stamped_now_not_with_the_source_mtime(self):
        src = os.path.join(self.tmp, "src")
        os.makedirs(src)
        os.utime(src, (1000000000, 1000000000))
        dest = wc.copy_release(src, os.path.join(self.tmp, "rel"))
        self.assertGreater(os.path.getmtime(dest), 1000000000 + 86400)

    def test_equal_mtimes_keep_the_newest_stamps(self):
        releases = os.path.join(self.tmp, "releases")
        names = ["20261101T000000", "20261102T000000", "20261103T000000", "20261104T000000"]
        for n in names:
            os.makedirs(os.path.join(releases, n))
            os.utime(os.path.join(releases, n), (1000000000, 1000000000))
        pruned = wc.prune_releases(releases, keep=2)
        self.assertEqual(sorted(os.listdir(releases)), names[2:])
        self.assertEqual(sorted(os.path.basename(p) for p in pruned), names[:2])


class TestUninstall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="airlock-win-uninstall-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.profile = os.path.join(self.tmp, "profile")
        self.env = {
            "AIRLOCK_FORCE_WINDOWS_INSTALL": "1",
            "AIRLOCK_HOME": os.path.join(self.tmp, "home"),
            "AIRLOCK_CONFIG_DIR": os.path.join(self.tmp, "cfg"),
            "AIRLOCK_STATE_DIR": os.path.join(self.tmp, "state"),
            "USERPROFILE": self.profile,
        }
        self.settings = os.path.join(self.profile, ".claude", "settings.json")
        with mock.patch.dict(os.environ, self.env, clear=False), \
             mock.patch("sys.stdout", new_callable=_Sink):
            windows_install.main(["--wire", "--source", REPO_ROOT])

    def _uninstall(self, *argv):
        with mock.patch.dict(os.environ, self.env, clear=False), \
             mock.patch("sys.stdout", new_callable=_Sink):
            return windows_uninstall.main(list(argv))

    def test_check_only_removes_nothing(self):
        self._uninstall("--check-only")
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, "home", "airlock-hook.py")))
        with open(self.settings) as f:
            self.assertIn("airlock-hook.py", f.read())

    def test_it_reverses_the_install(self):
        self._uninstall()
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "home", "airlock-hook.py")))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "home", "current.txt")))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "home", "releases")))
        with open(self.settings) as f:
            self.assertNotIn("airlock-hook.py", f.read())

    def test_config_and_state_survive_by_default(self):
        """Config holds the key file and state holds the shadow log: the one
        record of what the guard would have done."""
        self._uninstall()
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, "cfg")))
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, "state")))

    def test_purge_removes_them(self):
        self._uninstall("--purge")
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "cfg")))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "state")))

    def test_purge_says_it_kept_the_shared_kit_key_file(self):
        kit = os.path.join(self.tmp, "kit")
        os.makedirs(kit)
        with open(os.path.join(kit, "env"), "w") as f:
            f.write("TYPESAFE_API_KEY=x\n")
        out = io.StringIO()
        with mock.patch.dict(os.environ, dict(self.env, JEVKIT_CONFIG_DIR=kit), clear=False), \
             mock.patch("sys.stdout", out):
            windows_uninstall.main(["--purge"])
        self.assertTrue(os.path.isfile(os.path.join(kit, "env")))
        self.assertNotIn("INCLUDING THE KEY FILE", out.getvalue())
        self.assertIn("kept the kit key file", out.getvalue())

    def test_only_airlocks_own_hook_is_removed(self):
        with open(self.settings) as f:
            data = json.load(f)
        data["hooks"]["PreToolUse"][0]["hooks"].append(
            {"type": "command", "command": "C:\\tools\\somebody-elses-guard.py"})
        data["hooks"]["Stop"] = [{"matcher": "*", "hooks": [
            {"type": "command", "command": "C:\\tools\\their-stop-hook.py"}]}]
        with open(self.settings, "w") as f:
            json.dump(data, f)
        self._uninstall()
        with open(self.settings) as f:
            after = json.load(f)
        self.assertEqual(after["hooks"]["PreToolUse"][0]["hooks"],
                         [{"type": "command", "command": "C:\\tools\\somebody-elses-guard.py"}])
        self.assertEqual(after["hooks"]["Stop"][0]["hooks"][0]["command"],
                         "C:\\tools\\their-stop-hook.py")

    def test_a_settings_file_that_is_not_valid_json_is_left_alone(self):
        with open(self.settings, "w") as f:
            f.write("{ not json")
        self._uninstall()
        with open(self.settings) as f:
            self.assertEqual(f.read(), "{ not json")

    def test_it_backs_up_before_editing(self):
        self._uninstall()
        backups = [n for n in os.listdir(os.path.dirname(self.settings)) if ".bak." in n]
        self.assertTrue(backups)

    def test_strip_hook_recognises_every_entry_point_name_airlock_has_used(self):
        for command in ('& "C:\\py.exe" "C:\\x\\airlock-hook.py"',
                        '"C:\\py.exe" "C:\\x\\hooks\\airlock.py"',
                        'python3 /home/a/hooks/plumbline.py',
                        'python3 /home/a/hooks/jev_guard.py'):
            data = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": command}]}]}}
            self.assertEqual(len(windows_uninstall.strip_hook(data, None)), 1, command)

    def test_strip_hook_never_removes_something_that_merely_mentions_python(self):
        data = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": "python3 /home/a/hooks/their_guard.py"}]}]}}
        self.assertEqual(windows_uninstall.strip_hook(data, None), [])


class TestRefusesToRunOnTheWrongPlatform(unittest.TestCase):
    def test_the_installer_says_so_and_stops(self):
        env = dict(os.environ)
        env.pop("AIRLOCK_FORCE_WINDOWS_INSTALL", None)
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(wc, "is_windows", return_value=False), \
             mock.patch("sys.stderr"):
            self.assertEqual(windows_install.main(["--check-only"]), 2)


if __name__ == "__main__":
    unittest.main()
