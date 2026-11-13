
import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import os
import subprocess
import pathlib
import tempfile
import unittest

from tests import posix_only
from unittest import mock

from airlock import keyfile


class TestKeyfile(unittest.TestCase):
    def test_env_var_wins(self):
        with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "from-env"}):
            self.assertEqual(keyfile.get_api_key(), "from-env")

    def test_falls_back_to_env_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f:
            f.write("OTHER_VAR=ignored\n")
            f.write("TYPESAFE_API_KEY=from-file-secret\n")
            path = f.name
        try:
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("TYPESAFE_API_KEY", None)
                with mock.patch.object(keyfile, "key_file", return_value=path):
                    self.assertEqual(keyfile.get_api_key(), "from-file-secret")
        finally:
            os.remove(path)

    def test_quoted_value_in_env_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f:
            f.write('TYPESAFE_API_KEY="quoted-secret"\n')
            path = f.name
        try:
            os.environ.pop("TYPESAFE_API_KEY", None)
            with mock.patch.object(keyfile, "key_file", return_value=path):
                self.assertEqual(keyfile.get_api_key(), "quoted-secret")
        finally:
            os.remove(path)

    def test_missing_file_returns_none(self):
        os.environ.pop("TYPESAFE_API_KEY", None)
        with mock.patch.object(keyfile, "key_file",
                                return_value="/nonexistent/path/env"):
            self.assertIsNone(keyfile.get_api_key())

    def test_no_key_line_returns_none(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f:
            f.write("SOME_OTHER_KEY=value\n")
            path = f.name
        try:
            os.environ.pop("TYPESAFE_API_KEY", None)
            with mock.patch.object(keyfile, "key_file", return_value=path):
                self.assertIsNone(keyfile.get_api_key())
        finally:
            os.remove(path)


@posix_only("the ~/.config default; the Windows default is\n            %APPDATA%\\airlock\\env -- see\n            tests/test_windows_platform.py:TestWindowsKeyFile")
class TestDefaultEnvFile(unittest.TestCase):
    """The default key file is generic so a fresh machine needs no config at
    all, and it is KIT-level (~/.config/jev-kit/env) because every component in
    the kit reads the same key. The guard-era ~/.config/airlock/env is resolved
    straight after it, for good, so an existing install keeps working with no
    action. No other path is baked into the code: a machine that keeps its key
    elsewhere names that path in install/config.env, which reaches the code as
    AIRLOCK_LEGACY_KEY_FILES or as the pointer file the installer writes."""

    def _with_home(self, home):
        return mock.patch.object(os.path, "expanduser",
                                 lambda p: p.replace("~", home, 1))

    def test_kit_path_when_nothing_exists(self):
        with tempfile.TemporaryDirectory() as home, self._with_home(home):
            self.assertEqual(keyfile.default_env_file(),
                             os.path.join(home, ".config/jev-kit/env"))

    def test_kit_path_wins_when_both_defaults_exist(self):
        with tempfile.TemporaryDirectory() as home:
            for rel in (".config/jev-kit", ".config/airlock"):
                os.makedirs(os.path.join(home, rel))
                open(os.path.join(home, rel, "env"), "w").close()
            with self._with_home(home):
                self.assertEqual(keyfile.default_env_file(),
                                 os.path.join(home, ".config/jev-kit/env"))

    def test_guard_era_path_is_still_honoured_on_its_own(self):
        """An install that never moved its key keeps working with no action."""
        with tempfile.TemporaryDirectory() as home:
            os.makedirs(os.path.join(home, ".config/airlock"))
            open(os.path.join(home, ".config/airlock/env"), "w").close()
            env = {k: v for k, v in os.environ.items()
                   if k != "AIRLOCK_LEGACY_KEY_FILES"}
            with self._with_home(home), \
                    mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(keyfile.default_env_file(),
                                 os.path.join(home, ".config/airlock/env"))

    def test_kit_path_wins_when_a_legacy_path_also_exists(self):
        with tempfile.TemporaryDirectory() as home:
            legacy = os.path.join(home, ".config/elsewhere/env")
            for rel in (".config/jev-kit", ".config/elsewhere"):
                os.makedirs(os.path.join(home, rel))
                open(os.path.join(home, rel, "env"), "w").close()
            with self._with_home(home), \
                    mock.patch.dict(os.environ,
                                    {"AIRLOCK_LEGACY_KEY_FILES": legacy}):
                self.assertEqual(keyfile.default_env_file(),
                                 os.path.join(home, ".config/jev-kit/env"))

    def test_configured_legacy_path_is_honoured_when_it_is_the_only_one(self):
        with tempfile.TemporaryDirectory() as home:
            legacy = os.path.join(home, ".config/elsewhere/env")
            os.makedirs(os.path.dirname(legacy))
            open(legacy, "w").close()
            with self._with_home(home), \
                    mock.patch.dict(os.environ,
                                    {"AIRLOCK_LEGACY_KEY_FILES": legacy}):
                self.assertEqual(keyfile.default_env_file(), legacy)

    def test_no_legacy_path_is_baked_in(self):
        """With nothing configured, an existing file elsewhere is ignored."""
        with tempfile.TemporaryDirectory() as home:
            other = os.path.join(home, ".config/elsewhere/env")
            os.makedirs(os.path.dirname(other))
            open(other, "w").close()
            env = {k: v for k, v in os.environ.items()
                   if k != "AIRLOCK_LEGACY_KEY_FILES"}
            with self._with_home(home), \
                    mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(keyfile.default_env_file(),
                                 os.path.join(home, ".config/jev-kit/env"))

    def test_pointer_file_is_used_when_the_default_is_absent(self):
        """The hook runs with a minimal environment, so the installer records
        the path in $AIRLOCK_CONFIG_DIR/keyfile.path and this reads it."""
        with tempfile.TemporaryDirectory() as home:
            recorded = os.path.join(home, ".config/elsewhere/env")
            os.makedirs(os.path.dirname(recorded))
            open(recorded, "w").close()
            config = pathlib.Path(home) / ".config" / "airlock"
            config.mkdir(parents=True)
            config.chmod(0o700)
            (config / "keyfile.path").write_text(recorded + "\n")
            (config / "keyfile.path").chmod(0o600)
            with self._with_home(home), \
                    mock.patch.object(keyfile.paths, "config_file",
                                      lambda name: config / name):
                self.assertEqual(keyfile.default_env_file(), recorded)

    def test_it_never_raises(self):
        with mock.patch.object(os.path, "isfile", side_effect=OSError("boom")):
            self.assertTrue(keyfile.default_env_file())


@posix_only("pointer trust here is a uid check and a chmod check, and Windows\n"
            "            has neither; the Windows half is TestPointerTrustOnWindows below")
class TestPointerTrust(unittest.TestCase):
    """The pointer file chooses which file this process parses for a secret, so
    it is followed only when its own permissions say the owner wrote it. Every
    refusal falls back to the next step of the resolution order (which on these
    fixtures is the non-existent generic default) and records WHY."""

    def setUp(self):
        keyfile.reset_diagnostics()

    def _fixture(self, home, recorded=None, pointer_mode=0o600,
                 dir_mode=0o700, target_mode=0o600, make_target=True):
        """A config dir with a pointer in it, and (optionally) its target."""
        config = pathlib.Path(home) / ".config" / "airlock"
        config.mkdir(parents=True)
        target = os.path.join(home, ".config/elsewhere/env")
        if make_target:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            open(target, "w").close()
            os.chmod(target, target_mode)
        pointer = config / "keyfile.path"
        pointer.write_text((recorded if recorded is not None else target) + "\n")
        pointer.chmod(pointer_mode)
        config.chmod(dir_mode)
        return config, target

    def _patched(self, home, config):
        return (mock.patch.object(os.path, "expanduser",
                                  lambda p: p.replace("~", home, 1)),
                mock.patch.object(keyfile.paths, "config_file",
                                  lambda name: config / name))

    def _target(self, home, **kw):
        config, target = self._fixture(home, **kw)
        expanduser, config_file = self._patched(home, config)
        with expanduser, config_file:
            return keyfile.pointer_target(), target

    def test_good_pointer_is_followed(self):
        with tempfile.TemporaryDirectory() as home:
            got, target = self._target(home)
            self.assertEqual(got, target)
            self.assertEqual(keyfile.pointer_diagnostics(), ())

    def test_group_writable_pointer_is_ignored(self):
        with tempfile.TemporaryDirectory() as home:
            got, _ = self._target(home, pointer_mode=0o660)
            self.assertIsNone(got)
            self.assertTrue(any("group- or world-writable" in d
                                for d in keyfile.pointer_diagnostics()))

    def test_world_writable_pointer_is_ignored(self):
        with tempfile.TemporaryDirectory() as home:
            got, _ = self._target(home, pointer_mode=0o606)
            self.assertIsNone(got)

    def test_group_writable_directory_is_ignored(self):
        """A writable directory means the pointer can be replaced wholesale, so
        the pointer's own mode proves nothing."""
        with tempfile.TemporaryDirectory() as home:
            got, _ = self._target(home, dir_mode=0o770)
            self.assertIsNone(got)
            self.assertTrue(any("pointer directory" in d
                                for d in keyfile.pointer_diagnostics()))

    def test_world_writable_directory_is_ignored(self):
        with tempfile.TemporaryDirectory() as home:
            got, _ = self._target(home, dir_mode=0o707)
            self.assertIsNone(got)

    def test_a_config_dir_reached_through_a_symlink_is_followed(self):
        """migrate-to-airlock.sh leaves the old names as symlinks; a symlink's
        own mode is 777, so checking it refused every such pointer."""
        with tempfile.TemporaryDirectory() as home:
            real, target = self._fixture(home)
            link = pathlib.Path(home) / ".config" / "jev-guard"
            link.symlink_to(real)
            expanduser, config_file = self._patched(home, link)
            with expanduser, config_file:
                self.assertEqual(keyfile.pointer_target(), target)

    def test_a_symlink_to_a_writable_dir_is_still_ignored(self):
        with tempfile.TemporaryDirectory() as home:
            real, _ = self._fixture(home, dir_mode=0o777)
            link = pathlib.Path(home) / ".config" / "jev-guard"
            link.symlink_to(real)
            expanduser, config_file = self._patched(home, link)
            with expanduser, config_file:
                self.assertIsNone(keyfile.pointer_target())

    def test_the_shell_helper_follows_a_symlinked_config_dir(self):
        with tempfile.TemporaryDirectory() as home:
            real, target = self._fixture(home)
            link = pathlib.Path(home) / ".config" / "jev-guard"
            link.symlink_to(real)
            sh = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "install", "keyfile.sh")
            out = subprocess.run(
                ["bash", "-c", '. "$1"; airlock_keyfile_trusted_dir "$2" && echo yes', "_",
                 sh, str(link)], capture_output=True, text=True, timeout=10)
            self.assertEqual(out.stdout.strip(), "yes")
            os.chmod(real, 0o777)
            out = subprocess.run(
                ["bash", "-c", '. "$1"; airlock_keyfile_trusted_dir "$2" && echo yes', "_",
                 sh, str(link)], capture_output=True, text=True, timeout=10)
            os.chmod(real, 0o700)
            self.assertEqual(out.stdout.strip(), "")

    def test_symlinked_pointer_is_ignored(self):
        with tempfile.TemporaryDirectory() as home:
            config = pathlib.Path(home) / ".config" / "airlock"
            config.mkdir(parents=True)
            real = pathlib.Path(home) / "elsewhere.path"
            real.write_text("/etc/passwd\n")
            (config / "keyfile.path").symlink_to(real)
            config.chmod(0o700)
            expanduser, config_file = self._patched(home, config)
            with expanduser, config_file:
                self.assertIsNone(keyfile.pointer_target())
            self.assertTrue(any("not a regular file" in d
                                for d in keyfile.pointer_diagnostics()))

    def test_relative_recorded_path_is_ignored(self):
        with tempfile.TemporaryDirectory() as home:
            got, _ = self._target(home, recorded=".config/elsewhere/env")
            self.assertIsNone(got)
            self.assertTrue(any("not absolute" in d
                                for d in keyfile.pointer_diagnostics()))

    def test_missing_target_falls_back_cleanly(self):
        with tempfile.TemporaryDirectory() as home:
            got, _ = self._target(home, make_target=False)
            self.assertIsNone(got)
            self.assertTrue(any("does not exist" in d
                                for d in keyfile.pointer_diagnostics()))

    def test_directory_target_is_ignored(self):
        with tempfile.TemporaryDirectory() as home:
            got, _ = self._target(home, recorded=home, make_target=False)
            self.assertIsNone(got)

    def test_world_readable_target_warns_but_is_used(self):
        """Refusing it would take the guard offline over a permission the human
        can fix in one command, so this is a warning, not a rejection."""
        with tempfile.TemporaryDirectory() as home:
            got, target = self._target(home, target_mode=0o644)
            self.assertEqual(got, target)
            self.assertTrue(any("world-readable" in d
                                for d in keyfile.pointer_diagnostics()))

    def test_commented_pointer_is_ignored(self):
        with tempfile.TemporaryDirectory() as home:
            got, _ = self._target(home, recorded="# nothing here")
            self.assertIsNone(got)

    def test_unchecked_read_still_returns_an_untrusted_target(self):
        """R1 must protect what an UNTRUSTED pointer names: we refuse to follow
        it, but printing that path still hands a transcript the next file to
        read."""
        with tempfile.TemporaryDirectory() as home:
            config, target = self._fixture(home, dir_mode=0o777)
            expanduser, config_file = self._patched(home, config)
            with expanduser, config_file:
                self.assertIsNone(keyfile.pointer_target())
                self.assertEqual(keyfile.pointer_target(check=False), target)

    def test_a_missing_pointer_is_not_a_diagnostic(self):
        with tempfile.TemporaryDirectory() as home:
            config = pathlib.Path(home) / ".config" / "airlock"
            config.mkdir(parents=True)
            expanduser, config_file = self._patched(home, config)
            with expanduser, config_file:
                self.assertIsNone(keyfile.pointer_target())
            self.assertEqual(keyfile.pointer_diagnostics(), ())

    def test_pointer_target_never_raises(self):
        with mock.patch.object(keyfile, "pointer_file_path",
                               side_effect=OSError("boom")):
            self.assertIsNone(keyfile.pointer_target())

    def test_key_file_resolves_per_call(self):
        """ENV_FILE froze the answer at import, which a long-lived daemon
        outlives; key_file() is what makes a pointer written after deploy
        take effect."""
        with tempfile.TemporaryDirectory() as home:
            config, target = self._fixture(home)
            expanduser, config_file = self._patched(home, config)
            env = {k: v for k, v in os.environ.items()
                   if k not in ("AIRLOCK_KEY_FILE", "JEVKIT_KEY_FILE",
                                "PLUMBLINE_KEY_FILE", "JEV_GUARD_KEY_FILE",
                                "AIRLOCK_LEGACY_KEY_FILES")}
            with expanduser, config_file, \
                    mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(keyfile.key_file(), target)

    def test_explicit_override_beats_the_pointer(self):
        with tempfile.TemporaryDirectory() as home:
            config, _target = self._fixture(home)
            expanduser, config_file = self._patched(home, config)
            with expanduser, config_file, \
                    mock.patch.dict(os.environ,
                                    {"AIRLOCK_KEY_FILE": "/explicit/env"}):
                self.assertEqual(keyfile.key_file(), "/explicit/env")

    def test_jevkit_override_beats_the_pointer(self):
        """The kit-level name for the same override, for anything that thinks
        in kit terms rather than guard terms."""
        with tempfile.TemporaryDirectory() as home:
            config, _target = self._fixture(home)
            expanduser, config_file = self._patched(home, config)
            env = {k: v for k, v in os.environ.items()
                   if k not in ("AIRLOCK_KEY_FILE", "PLUMBLINE_KEY_FILE",
                                "JEV_GUARD_KEY_FILE")}
            env["JEVKIT_KEY_FILE"] = "/kit/env"
            with expanduser, config_file, \
                    mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(keyfile.key_file(), "/kit/env")

    def test_airlock_override_beats_jevkit_override(self):
        """Both are accepted; the documented order puts AIRLOCK_KEY_FILE first
        so a machine mid-cutover that sets both gets one predictable answer."""
        with tempfile.TemporaryDirectory() as home:
            config, _target = self._fixture(home)
            expanduser, config_file = self._patched(home, config)
            with expanduser, config_file, \
                    mock.patch.dict(os.environ,
                                    {"AIRLOCK_KEY_FILE": "/explicit/env",
                                     "JEVKIT_KEY_FILE": "/kit/env"}):
                self.assertEqual(keyfile.key_file(), "/explicit/env")


class TestPointerTrustOnWindows(unittest.TestCase):
    """Windows has no uid and no meaningful st_mode, so the two permission
    checks cannot run there. The module does not pretend they passed and does
    not refuse every pointer either: it follows the pointer and RECORDS what
    was and was not checked. The structural checks still run."""

    def setUp(self):
        keyfile.reset_diagnostics()

    def _fixture(self, home):
        config = pathlib.Path(home) / "AppData" / "Roaming" / "airlock"
        config.mkdir(parents=True)
        target = os.path.join(home, "AppData", "Roaming", "jev-kit", "env")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        open(target, "w").close()
        pointer = config / "keyfile.path"
        pointer.write_text(target + "\n")
        return config, target

    def _target(self, home, **kw):
        config, target = self._fixture(home)
        with mock.patch.object(keyfile.paths, "config_file",
                               lambda name: config / name), \
             mock.patch.dict(os.environ, {"USERPROFILE": home}):
            return keyfile.pointer_target(windows=True, **kw), target

    def test_the_pointer_is_followed(self):
        with tempfile.TemporaryDirectory() as home:
            got, target = self._target(home)
            self.assertEqual(got, target)

    def test_the_diagnostics_say_what_was_and_was_not_checked(self):
        with tempfile.TemporaryDirectory() as home:
            self._target(home)
            blob = " ".join(keyfile.pointer_diagnostics())
        self.assertIn("CHECKED", blob)
        self.assertIn("NOT CHECKED", blob)
        self.assertIn("owner uid", blob)
        self.assertIn("ACL", blob)

    def test_a_group_writable_mode_is_not_used_to_refuse_on_windows(self):
        """The same fixture that POSIX refuses is FOLLOWED on Windows, because
        the mode there is synthesised and means nothing. The diagnostics are
        what carry the honesty, not a refusal."""
        with tempfile.TemporaryDirectory() as home:
            config, target = self._fixture(home)
            (config / "keyfile.path").chmod(0o666)
            with mock.patch.object(keyfile.paths, "config_file",
                                   lambda name: config / name), \
                 mock.patch.dict(os.environ, {"USERPROFILE": home}):
                self.assertEqual(keyfile.pointer_target(windows=True), target)
                keyfile.reset_diagnostics()
                # The POSIX branch refuses the same fixture. (Its DIAGNOSTIC
                # text is asserted in TestPointerTrust, which runs on POSIX
                # only: forced onto the POSIX branch on a real Windows host
                # there is no os.getuid() to call, so the refusal happens one
                # step earlier and says less.)
                self.assertIsNone(keyfile.pointer_target(windows=False))

    def test_the_structural_checks_still_run(self):
        with tempfile.TemporaryDirectory() as home:
            config, _target = self._fixture(home)
            (config / "keyfile.path").write_text("not-an-absolute-path\n")
            with mock.patch.object(keyfile.paths, "config_file",
                                   lambda name: config / name), \
                 mock.patch.dict(os.environ, {"USERPROFILE": home}):
                self.assertIsNone(keyfile.pointer_target(windows=True))
            self.assertTrue(any("not absolute" in d
                                for d in keyfile.pointer_diagnostics()))

    def test_a_missing_target_still_falls_back(self):
        with tempfile.TemporaryDirectory() as home:
            config, target = self._fixture(home)
            os.remove(target)
            with mock.patch.object(keyfile.paths, "config_file",
                                   lambda name: config / name), \
                 mock.patch.dict(os.environ, {"USERPROFILE": home}):
                self.assertIsNone(keyfile.pointer_target(windows=True))

    def test_a_pointer_outside_the_profile_is_followed_but_warned_about(self):
        with tempfile.TemporaryDirectory() as home:
            config, target = self._fixture(home)
            with mock.patch.object(keyfile.paths, "config_file",
                                   lambda name: config / name), \
                 mock.patch.dict(os.environ, {"USERPROFILE": "Z:\\somewhere-else"}):
                self.assertEqual(keyfile.pointer_target(windows=True), target)
            blob = " ".join(keyfile.pointer_diagnostics())
        self.assertIn("USERPROFILE", blob)
        self.assertIn("still followed", blob)


if __name__ == "__main__":
    unittest.main()
