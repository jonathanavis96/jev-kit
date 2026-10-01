
import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import tempfile
import time
import unittest

from tests import posix_only
from pathlib import Path
from unittest import mock

from airlock import state as state_mod


class TestLoopState(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        state_dir = Path(self._tmpdir.name) / "airlock"
        self._patches = [
            mock.patch.object(state_mod, "STATE_DIR", state_dir),
            mock.patch.object(state_mod, "STATE_FILE", state_dir / "loop_state.json"),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)

    def test_no_prior_denial_returns_false(self):
        self.assertFalse(state_mod.was_recently_denied("s1", ("bash", "find / -name x"), 600))

    def test_recorded_denial_is_seen_within_window(self):
        key = ("bash", "find / -name x")
        state_mod.record_denial("s1", key)
        self.assertTrue(state_mod.was_recently_denied("s1", key, 600))

    def test_different_session_not_affected(self):
        key = ("bash", "find / -name x")
        state_mod.record_denial("s1", key)
        self.assertFalse(state_mod.was_recently_denied("s2", key, 600))

    def test_different_key_not_affected(self):
        state_mod.record_denial("s1", ("bash", "find / -name x"))
        self.assertFalse(state_mod.was_recently_denied("s1", ("bash", "find / -name y"), 600))

    def test_wrong_shaped_session_row_does_not_disable_recording(self):
        # A session row that is not a dict used to make _prune raise inside
        # record_denial, which then gave up on every call from then on.
        state_mod.STATE_DIR.mkdir(parents=True, exist_ok=True)
        state_mod.STATE_FILE.write_text('{"old": ["x"], "s1": "bad"}')
        self.assertFalse(state_mod.was_recently_denied("s1", ("bash", "ls"), 600))
        key = ("bash", "find / -name x")
        state_mod.record_denial("s2", key)
        self.assertTrue(state_mod.was_recently_denied("s2", key, 600))
        state_mod.record_denial("s1", key)
        self.assertTrue(state_mod.was_recently_denied("s1", key, 600))

    def test_expired_denial_not_seen(self):
        key = ("agent", "do the thing")
        state_mod.record_denial("s1", key)
        with mock.patch("time.time", return_value=time.time() + 700):
            self.assertFalse(state_mod.was_recently_denied("s1", key, 600))

    @posix_only("a POSIX mode; on Windows privacy comes from the\n"
                "            %LOCALAPPDATA% ACL instead -- see\n"
                "            tests/test_windows_platform.py:TestPermissions")
    def test_file_mode_is_owner_only(self):
        key = ("bash", "find / -name x")
        state_mod.record_denial("s1", key)
        mode = state_mod.STATE_FILE.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_corrupt_state_file_fails_safe(self):
        state_mod._ensure_dir()
        state_mod.STATE_FILE.write_text("not json{{{")
        self.assertFalse(state_mod.was_recently_denied("s1", ("bash", "x"), 600))
        # record_denial must not raise even starting from a corrupt file.
        state_mod.record_denial("s1", ("bash", "x"))
        self.assertTrue(state_mod.was_recently_denied("s1", ("bash", "x"), 600))


if __name__ == "__main__":
    unittest.main()
