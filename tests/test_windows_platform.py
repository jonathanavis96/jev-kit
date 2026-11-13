"""Windows behaviour, exercised on Linux.

Not one test here needs a Windows machine. Every platform decision in the
package is behind an injectable `windows` argument (airlock/platform_compat.py
explains why), so the Windows code path is reachable from an ordinary Linux
test run -- which is the only way it can be part of the suite that gates a
deploy.

The tests are split the way the code is:
  TestIsWindows            the detection itself
  TestDetachedPopenKwargs  the shadow worker's creation flags
  TestLocking              flock vs the Windows byte-range lock
  TestPermissions          chmod vs the per-user ACL, reported honestly
  TestUnixSockets          the daemon is skipped, not failed
  TestWindowsPaths         %APPDATA% / %LOCALAPPDATA%, overrides, no /tmp
  TestWindowsKeyFile       %APPDATA%\\jev-kit\\env, then %APPDATA%\\airlock\\env
  TestKitConfigDir         the kit-level directory on both platforms
  TestWinPath              the three spellings of one directory
"""
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from airlock import client, enforce, keyfile, paths, platform_compat, winpath
from tests import posix_only


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


class TestIsWindows(unittest.TestCase):
    def test_platform_string_decides(self):
        self.assertTrue(platform_compat.is_windows(platform="win32"))
        self.assertFalse(platform_compat.is_windows(platform="linux"))
        self.assertFalse(platform_compat.is_windows(platform="darwin"))

    def test_cygwin_is_not_windows(self):
        """A Cygwin CPython is POSIX: it has fcntl, AF_UNIX and real modes."""
        self.assertFalse(platform_compat.is_windows(platform="cygwin"))

    def test_explicit_argument_beats_the_platform(self):
        self.assertTrue(platform_compat.is_windows(True, platform="linux"))
        self.assertFalse(platform_compat.is_windows(False, platform="win32"))


class TestDetachedPopenKwargs(unittest.TestCase):
    def test_posix_is_unchanged(self):
        self.assertEqual(platform_compat.detached_popen_kwargs(windows=False),
                         {"start_new_session": True})

    def test_windows_uses_creation_flags(self):
        kwargs = platform_compat.detached_popen_kwargs(windows=True)
        self.assertNotIn("start_new_session", kwargs)
        flags = kwargs["creationflags"]
        self.assertTrue(flags & platform_compat.DETACHED_PROCESS)
        self.assertTrue(flags & platform_compat.CREATE_NEW_PROCESS_GROUP)
        self.assertTrue(flags & platform_compat.CREATE_NO_WINDOW)

    def test_hook_passes_them_straight_to_popen(self):
        """The shadow path must use whatever this returns, not its own copy."""
        import json
        import subprocess
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "hook_entry_win",
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "hooks", "airlock.py"))
        hook = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hook)
        payload = json.dumps({"tool_name": "Bash",
                              "tool_input": {"command": "grep -r foo ."}})
        with mock.patch("sys.stdin.read", return_value=payload), \
             mock.patch.object(hook, "_resolve_mode", return_value="shadow"), \
             mock.patch.object(hook, "_disabled", return_value=False), \
             mock.patch.object(platform_compat, "detached_popen_kwargs",
                               return_value={"creationflags": 0x208}), \
             mock.patch("subprocess.Popen") as popen:
            hook.main()
            popen.assert_called_once()
            args, kwargs = popen.call_args
            self.addCleanup(_remove_quietly, args[0][-1])
            self.assertEqual(kwargs.get("creationflags"), 0x208)
            self.assertNotIn("start_new_session", kwargs)
            self.assertEqual(kwargs.get("stdin"), subprocess.DEVNULL)


class TestLocking(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix="airlock-lock-test-")
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(self.path) and os.remove(self.path))

    def _open(self):
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(lambda: self._close(fd))
        return fd

    def _close(self, fd):
        try:
            os.close(fd)
        except Exception:
            pass

    @posix_only("flock; the Windows path is asserted separately below")
    def test_posix_lock_and_unlock_round_trip(self):
        fd = self._open()
        self.assertTrue(platform_compat.lock_file(fd, platform_compat.LOCK_EXCLUSIVE,
                                                  windows=False))
        self.assertTrue(platform_compat.unlock_file(fd, windows=False))

    @posix_only("fcntl does not exist on Windows")
    def test_shared_lock_is_a_real_shared_lock_on_posix(self):
        import fcntl
        fd = self._open()
        with mock.patch("fcntl.flock") as flock:
            platform_compat.lock_file(fd, platform_compat.LOCK_SHARED, windows=False)
            flock.assert_called_once_with(fd, fcntl.LOCK_SH)

    def test_windows_uses_msvcrt_past_end_of_file(self):
        """The lock byte sits past any plausible EOF: Windows byte-range locks
        are mandatory, so locking live data would make an unrelated read in
        another process fail rather than wait."""
        fd = self._open()
        os.write(fd, b"some real data")
        seen = {}
        fake = mock.Mock()
        fake.LK_LOCK = 1
        fake.LK_UNLCK = 0

        def _locking(_fd, mode, nbytes):
            seen["offset"] = os.lseek(_fd, 0, os.SEEK_CUR)
            seen["mode"] = mode
            seen["nbytes"] = nbytes
        fake.locking = _locking

        before = os.lseek(fd, 5, os.SEEK_SET)
        with mock.patch.dict("sys.modules", {"msvcrt": fake}):
            self.assertTrue(platform_compat.lock_file(
                fd, platform_compat.LOCK_EXCLUSIVE, windows=True))
        self.assertEqual(seen["offset"], platform_compat._WIN_LOCK_OFFSET)
        self.assertEqual(seen["nbytes"], 1)
        self.assertGreater(platform_compat._WIN_LOCK_OFFSET, 1 << 32)
        # The caller's file position is restored, or every write after a lock
        # would land in the wrong place.
        self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), before)

    def test_windows_shared_degrades_to_exclusive_not_to_nothing(self):
        fd = self._open()
        modes = []
        fake = mock.Mock()
        fake.LK_LOCK = 1
        fake.LK_UNLCK = 0
        fake.locking = lambda _fd, mode, _n: modes.append(mode)
        with mock.patch.dict("sys.modules", {"msvcrt": fake}):
            platform_compat.lock_file(fd, platform_compat.LOCK_SHARED, windows=True)
        self.assertEqual(modes, [1])

    @posix_only("patches fcntl.flock, which does not exist on Windows; the "
                "Windows\n            failure path is the same blanket except")
    def test_a_lock_that_cannot_be_taken_is_false_never_an_exception(self):
        """Every caller treats False as "carry on unlocked": a log write is
        never allowed to fail because a lock could not be acquired."""
        fd = self._open()
        with mock.patch("fcntl.flock", side_effect=OSError("no locks available")):
            self.assertFalse(platform_compat.lock_file(fd, windows=False))
        with mock.patch("fcntl.flock", side_effect=OSError("boom")):
            self.assertFalse(platform_compat.unlock_file(fd, windows=False))


class TestPermissions(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix="airlock-perm-test-")
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(self.path) and os.remove(self.path))

    @posix_only("asserts a real POSIX mode")
    def test_posix_applies_the_mode(self):
        os.chmod(self.path, 0o644)
        self.assertTrue(platform_compat.restrict_path(self.path, 0o600, windows=False))
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    @posix_only("the assertion is that a mode was NOT changed, which needs a\n"
                "            filesystem that has modes to change")
    def test_windows_never_chmods(self):
        """os.chmod on Windows only toggles the read-only attribute. Applying
        it would make the file harder to rewrite and give no privacy at all,
        so nothing is applied and the caller is told so."""
        os.chmod(self.path, 0o644)
        with mock.patch("os.chmod") as chmod:
            self.assertFalse(platform_compat.restrict_path(self.path, 0o600, windows=True))
            chmod.assert_not_called()
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o644)

    @posix_only("asserts a real POSIX mode")
    def test_posix_description_reports_a_real_mode(self):
        os.chmod(self.path, 0o600)
        ok, text = platform_compat.describe_permissions(self.path, windows=False)
        self.assertTrue(ok)
        self.assertIn("owner only", text)
        os.chmod(self.path, 0o644)
        ok, text = platform_compat.describe_permissions(self.path, windows=False)
        self.assertFalse(ok)
        self.assertIn("group or other", text)

    def test_windows_description_is_an_acl_claim_not_a_mode_claim(self):
        profile = os.path.dirname(self.path)
        with mock.patch.dict(os.environ, {"USERPROFILE": profile}):
            ok, text = platform_compat.describe_permissions(self.path, windows=True)
        self.assertTrue(ok)
        self.assertIn("ACL", text)
        self.assertNotIn("mode", text.split("ACL")[0])

    def test_a_sibling_of_the_profile_is_not_inside_it(self):
        with mock.patch.dict(os.environ, {"USERPROFILE": "C:\\Users\\al"}):
            ok, _ = platform_compat.describe_permissions(
                "C:\\Users\\alice\\AppData\\Roaming\\airlock\\env", windows=True)
            self.assertFalse(ok)
            ok, _ = platform_compat.describe_permissions(
                "c:/users/AL/AppData/Roaming/airlock/env", windows=True)
            self.assertTrue(ok)

    def test_windows_description_flags_a_path_outside_the_profile(self):
        with mock.patch.dict(os.environ, {"USERPROFILE": "C:\\Users\\someone-else"}):
            ok, text = platform_compat.describe_permissions(self.path, windows=True)
        self.assertFalse(ok)
        self.assertIn("USERPROFILE", text)


class TestUnixSockets(unittest.TestCase):
    def test_windows_has_none(self):
        self.assertFalse(platform_compat.has_unix_sockets(windows=True))

    def test_the_posix_answer_is_the_capability_itself(self):
        """With windows=False the answer is whatever the interpreter actually
        has, never a hard True: a Windows CPython running this branch reports
        no AF_UNIX, and saying otherwise would be a lie the daemon path would
        then act on."""
        import socket
        self.assertEqual(platform_compat.has_unix_sockets(windows=False),
                         hasattr(socket, "AF_UNIX"))

    def test_client_skips_the_daemon_on_windows_without_touching_a_socket(self):
        with mock.patch("socket.socket") as sock:
            self.assertIsNone(client._ask_via_daemon({"state": {}}, 1.0, windows=True))
            sock.assert_not_called()

    def test_ask_falls_back_to_the_direct_https_call_on_windows(self):
        with mock.patch.object(client, "call_jev",
                               return_value=({"answers": {}}, 900)) as direct, \
             mock.patch.object(client.keyfile, "get_api_key", return_value="k"), \
             mock.patch("socket.socket") as sock:
            response, latency = client.ask({"state": {}, "questions": {}}, windows=True)
        self.assertEqual(latency, 900)
        self.assertEqual(response, {"answers": {}})
        direct.assert_called_once()
        sock.assert_not_called()


class TestWindowsPaths(unittest.TestCase):
    ENV = {
        "APPDATA": "C:\\Users\\alice\\AppData\\Roaming",
        "LOCALAPPDATA": "C:\\Users\\alice\\AppData\\Local",
        "USERPROFILE": "C:\\Users\\alice",
    }

    def _clear(self):
        return mock.patch.dict(os.environ, self.ENV, clear=True)

    def test_config_is_appdata(self):
        with self._clear():
            self.assertEqual(str(paths.config_dir(windows=True)),
                             os.path.join(self.ENV["APPDATA"], "airlock"))

    def test_state_is_localappdata_state(self):
        with self._clear():
            self.assertEqual(
                str(paths.state_dir(windows=True)),
                os.path.join(self.ENV["LOCALAPPDATA"], "airlock", "state"))

    def test_install_home_is_localappdata(self):
        with self._clear():
            self.assertEqual(str(paths.install_home(windows=True)),
                             os.path.join(self.ENV["LOCALAPPDATA"], "airlock"))

    def test_state_is_a_sibling_of_releases_not_a_stray_state_directory(self):
        """%LOCALAPPDATA%\\airlock\\state, never %LOCALAPPDATA%\\state\\airlock."""
        with self._clear():
            home = str(paths.install_home(windows=True))
            state = str(paths.state_dir(windows=True))
        self.assertTrue(state.startswith(home))
        self.assertTrue(state.endswith("state"))

    def test_environment_overrides_still_win_on_windows(self):
        env = dict(self.ENV)
        env["AIRLOCK_CONFIG_DIR"] = "D:\\airlock-config"
        env["AIRLOCK_STATE_DIR"] = "D:\\airlock-state"
        env["AIRLOCK_HOME"] = "D:\\airlock-home"
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(str(paths.config_dir(windows=True)), "D:\\airlock-config")
            self.assertEqual(str(paths.state_dir(windows=True)), "D:\\airlock-state")
            self.assertEqual(str(paths.install_home(windows=True)), "D:\\airlock-home")

    def test_missing_appdata_falls_back_inside_the_profile(self):
        with mock.patch.dict(os.environ, {"USERPROFILE": "C:\\Users\\alice"}, clear=True), \
             mock.patch("os.path.expanduser", return_value="C:\\Users\\alice"):
            config = str(paths.config_dir(windows=True))
        self.assertIn("Roaming", config)
        self.assertTrue(config.endswith("airlock"))

    def test_no_tmp_anywhere_in_the_windows_runtime_paths(self):
        with self._clear():
            socket_path = paths.runtime_socket(windows=True)
            socket_dir = paths.runtime_socket_dir(windows=True)
        for value in (socket_path, socket_dir):
            self.assertNotIn("/tmp", value)
            self.assertNotIn("\\tmp", value.lower())

    @posix_only("pathlib builds a POSIX path only on a POSIX host; on Windows\n"
                "            the same call correctly produces backslashes and the\n"
                "            comparison would be about pathlib, not about airlock")
    def test_linux_paths_are_completely_unchanged(self):
        with mock.patch.dict(os.environ, {"HOME": "/home/alice"}, clear=True), \
             mock.patch("os.path.expanduser", return_value="/home/alice"), \
             mock.patch.object(paths, "_pick", side_effect=lambda new, *_legacy: new):
            self.assertEqual(str(paths.config_dir(windows=False)),
                             "/home/alice/.config/airlock")
            self.assertEqual(str(paths.state_dir(windows=False)),
                             "/home/alice/.local/state/airlock")
            self.assertEqual(str(paths.install_home(windows=False)),
                             "/home/alice/.local/share/airlock")


class TestWindowsKeyFile(unittest.TestCase):
    """Steps 3 and 4 of the resolution order, spelled for Windows.

    The kit default comes first and the guard-era default second, exactly as
    on POSIX. Only the spelling of the two paths differs.
    """

    WIN_ENV = {"APPDATA": "C:\\Users\\alice\\AppData\\Roaming",
               "LOCALAPPDATA": "C:\\Users\\alice\\AppData\\Local",
               "USERPROFILE": "C:\\Users\\alice"}

    def test_windows_defaults_are_kit_then_guard_under_appdata(self):
        with mock.patch.dict(os.environ, self.WIN_ENV, clear=True), \
             mock.patch.object(paths, "_pick", side_effect=lambda new, *_legacy: new):
            self.assertEqual(
                keyfile.default_env_files(windows=True),
                (str(pathlib.Path(self.WIN_ENV["APPDATA"]) / "jev-kit" / "env"),
                 str(pathlib.Path(self.WIN_ENV["APPDATA"]) / "airlock" / "env")))

    def test_windows_guard_era_default_still_honours_the_config_override(self):
        env = dict(self.WIN_ENV)
        env["AIRLOCK_CONFIG_DIR"] = "D:\\airlock-config"
        with mock.patch.dict(os.environ, env, clear=True):
            second = keyfile.default_env_files(windows=True)[1]
        self.assertEqual(second, str(pathlib.Path("D:\\airlock-config") / "env"))

    def test_linux_defaults_are_unchanged(self):
        self.assertEqual(keyfile.default_env_files(windows=False),
                         ("~/.config/jev-kit/env", "~/.config/airlock/env"))
        self.assertEqual(keyfile.default_env_files(windows=False),
                         keyfile.DEFAULT_ENV_FILES)


class TestKitConfigDir(unittest.TestCase):
    """The kit-level directory: ~/.config/jev-kit on POSIX,
    %APPDATA%\\jev-kit on Windows, `JEVKIT_CONFIG_DIR` overriding both.

    It has NO legacy-name fallback on purpose -- it is new in this release and
    never had an older name, so there is nothing to fall back to."""

    def test_posix(self):
        # Compared as Paths, not as strings: on a Windows host `str()` of a
        # WindowsPath uses backslashes, which would make this a test about the
        # host rather than about airlock.
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch("os.path.expanduser", return_value="/home/alice"):
            self.assertEqual(paths.kit_config_dir(windows=False),
                             pathlib.Path("/home/alice/.config/jev-kit"))

    def test_windows(self):
        env = {"APPDATA": "C:\\Users\\alice\\AppData\\Roaming"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(str(paths.kit_config_dir(windows=True)),
                             str(pathlib.Path(env["APPDATA"]) / "jev-kit"))

    def test_windows_without_appdata_falls_back_inside_the_profile(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch("os.path.expanduser", return_value="C:\\Users\\alice"):
            got = str(paths.kit_config_dir(windows=True))
        self.assertTrue(got.endswith("jev-kit"), got)
        self.assertIn("AppData", got)

    def test_the_override_wins_on_both_platforms(self):
        with mock.patch.dict(os.environ, {"JEVKIT_CONFIG_DIR": "/opt/kit"}, clear=True):
            self.assertEqual(paths.kit_config_dir(windows=False), pathlib.Path("/opt/kit"))
            self.assertEqual(paths.kit_config_dir(windows=True), pathlib.Path("/opt/kit"))


class TestBudgetMs(unittest.TestCase):
    """The enforce-mode judgement budget: 1500ms on POSIX/WSL/macOS, 2000ms
    on native Windows (no warm daemon there -- see docs/native-windows.md for
    the measurements that decided it), AIRLOCK_BUDGET_MS and its legacy names
    overriding on every platform."""

    _BUDGET_VARS = ("AIRLOCK_BUDGET_MS", "PLUMBLINE_BUDGET_MS", "JEV_GUARD_BUDGET_MS")

    def _clear_env(self):
        return mock.patch.dict(os.environ, {}, clear=True)

    def test_posix_default_is_1500(self):
        with self._clear_env():
            self.assertEqual(enforce.budget_ms(windows=False), 1500)

    def test_windows_default_is_2000(self):
        with self._clear_env():
            self.assertEqual(enforce.budget_ms(windows=True), 2000)

    def test_real_platform_detection_used_when_not_injected(self):
        # enforce.py does `from .platform_compat import is_windows`, so the
        # spy has to replace enforce's own bound name, not the module
        # attribute -- patching platform_compat.is_windows would not be seen
        # by the already-imported reference.
        with self._clear_env(), mock.patch.object(enforce, "is_windows",
                                                    wraps=platform_compat.is_windows) as spy:
            enforce.budget_ms()
            spy.assert_called_once_with(None)

    def test_env_override_wins_on_posix(self):
        with mock.patch.dict(os.environ, {"AIRLOCK_BUDGET_MS": "999"}, clear=True):
            self.assertEqual(enforce.budget_ms(windows=False), 999)

    def test_env_override_wins_on_windows_too(self):
        with mock.patch.dict(os.environ, {"AIRLOCK_BUDGET_MS": "999"}, clear=True):
            self.assertEqual(enforce.budget_ms(windows=True), 999)

    def test_legacy_env_names_still_override(self):
        for name in ("PLUMBLINE_BUDGET_MS", "JEV_GUARD_BUDGET_MS"):
            with mock.patch.dict(os.environ, {name: "777"}, clear=True):
                self.assertEqual(enforce.budget_ms(windows=True), 777, name)
                self.assertEqual(enforce.budget_ms(windows=False), 777, name)

    def test_same_value_reaches_the_urlopen_timeout(self):
        """budget_ms() feeds client.ask(timeout_s=...), which client.py passes
        straight to urllib.request.urlopen(timeout=...). Assert the wiring,
        not just the constant."""
        with self._clear_env():
            b_ms = enforce.budget_ms(windows=True)
        self.assertEqual(b_ms, 2000)
        with mock.patch.object(client, "call_jev",
                               return_value=({"answers": {}}, 5)) as direct, \
             mock.patch.object(client.keyfile, "get_api_key", return_value="k"), \
             mock.patch("socket.socket"):
            client.ask({"state": {}, "questions": {}}, timeout_s=b_ms / 1000.0, windows=True)
        _api_key, _state, _questions = direct.call_args[0]
        self.assertEqual(direct.call_args[1]["timeout"], 2.0)

    def test_windows_pretooluse_hook_timeout_still_leaves_room(self):
        """The wired settings.json PreToolUse timeout (install/_wire.py:
        PRETOOLUSE_TIMEOUT) is 5s on every platform, including Windows. The
        2000ms Windows budget must leave real headroom under it."""
        # install/_wire.py reads NEW_HOOK from the environment at import
        # time (it is a script invoked by wire.sh, not a library module), so
        # importing it here needs that var present regardless of AIRLOCK_*.
        with mock.patch.dict(os.environ, {"NEW_HOOK": "/dev/null"}):
            from install import _wire
        with self._clear_env():
            b_ms = enforce.budget_ms(windows=True)
        self.assertLess(b_ms, _wire.PRETOOLUSE_TIMEOUT * 1000)
        self.assertGreaterEqual(_wire.PRETOOLUSE_TIMEOUT * 1000 - b_ms, 1000)


class TestWinPath(unittest.TestCase):
    def test_the_three_spellings_are_one_directory(self):
        for spelling in ("C:\\Users\\alice\\code",
                         "C:/Users/alice/code",
                         "/c/Users/alice/code",
                         "/cygdrive/c/Users/alice/code",
                         "c:\\users\\ALICE\\code\\"):
            self.assertTrue(winpath.same_path(spelling, "C:\\Users\\alice\\code"),
                            spelling)

    def test_canonical_form(self):
        self.assertEqual(winpath.canonical("/c/Users/alice"), "C:\\Users\\alice")
        self.assertEqual(winpath.canonical("c:/users"), "C:\\users")
        self.assertEqual(winpath.canonical("C:"), "C:\\")
        self.assertEqual(winpath.canonical("C:\\"), "C:\\")
        self.assertEqual(winpath.canonical("C:\\code\\"), "C:\\code")
        self.assertEqual(winpath.canonical("C:\\\\code\\\\sub"), "C:\\code\\sub")

    def test_drive_and_share_roots_are_whole_volumes(self):
        for root in ("C:\\", "C:", "/c", "/c/", "d:\\", "\\\\server\\share",
                     "/cygdrive/e"):
            self.assertTrue(winpath.is_drive_root(root), root)
        for not_root in ("C:\\Users", "/c/Users", "\\\\server\\share\\dir"):
            self.assertFalse(winpath.is_drive_root(not_root), not_root)

    def test_bare_separator_is_disk_wide(self):
        """`find / -name x` typed at a Git Bash prompt on Windows."""
        self.assertTrue(winpath.is_drive_root("/"))

    def test_is_under_is_case_insensitive_and_not_a_prefix_match(self):
        self.assertTrue(winpath.is_under("C:\\Users\\Alice\\code", "c:\\users\\alice"))
        self.assertTrue(winpath.is_under("C:\\Users\\alice", "C:\\Users\\alice"))
        self.assertFalse(winpath.is_under("C:\\Users\\alice2", "C:\\Users\\alice"))

    def test_percent_and_ps_env_variables_expand(self):
        env = {"USERPROFILE": "C:\\Users\\alice"}
        self.assertEqual(winpath.expand_vars("%USERPROFILE%\\code", env),
                         "C:\\Users\\alice\\code")
        self.assertEqual(winpath.expand_vars("$env:USERPROFILE\\code", env),
                         "C:\\Users\\alice\\code")

    def test_an_unknown_variable_is_left_alone_not_blanked(self):
        """Blanking it would turn a single-directory search into one that
        looks rooted at a drive."""
        self.assertEqual(winpath.expand_vars("%NOPE%\\code", {}), "%NOPE%\\code")

    def test_home_prefers_userprofile(self):
        self.assertEqual(winpath.home({"USERPROFILE": "C:\\Users\\alice",
                                       "HOME": "/c/Users/bob"}),
                         "C:\\Users\\alice")
        self.assertEqual(winpath.home({"HOMEDRIVE": "C:", "HOMEPATH": "\\Users\\alice"}),
                         "C:\\Users\\alice")

    def test_canonical_never_raises(self):
        for odd in (None, "", "   ", 12345, "\\\\", "::::"):
            winpath.canonical(odd)


if __name__ == "__main__":
    unittest.main()
