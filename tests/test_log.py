
import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import json
import os
import stat
import tempfile
import unittest

from tests import posix_only
from pathlib import Path
from unittest import mock

from airlock import log as jlog


class TestLog(unittest.TestCase):
    def test_append_creates_the_dir_and_the_file(self):
        """Platform-neutral: the log has to be written. WHO can read it is a
        separate question with a different answer per platform, below."""
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "state" / "airlock"
            log_file = log_dir / "shadow.jsonl"
            with mock.patch.object(jlog, "LOG_DIR", log_dir), mock.patch.object(jlog, "LOG_FILE", log_file):
                jlog.append({"a": 1})
            self.assertTrue(log_dir.is_dir())
            self.assertTrue(log_file.is_file())

    @posix_only("a POSIX mode. On Windows os.chmod only toggles the read-only\n"
                "            attribute and privacy comes from the %LOCALAPPDATA% ACL\n"
                "            instead -- see airlock/platform_compat.py:restrict_path\n"
                "            and tests/test_windows_platform.py:TestPermissions")
    def test_the_log_is_owner_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "state" / "airlock"
            log_file = log_dir / "shadow.jsonl"
            with mock.patch.object(jlog, "LOG_DIR", log_dir), mock.patch.object(jlog, "LOG_FILE", log_file):
                jlog.append({"a": 1})

            dir_mode = stat.S_IMODE(os.stat(log_dir).st_mode)
            file_mode = stat.S_IMODE(os.stat(log_file).st_mode)
            self.assertEqual(dir_mode, 0o700)
            self.assertEqual(file_mode, 0o600)

    def test_append_writes_one_json_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "state" / "airlock"
            log_file = log_dir / "shadow.jsonl"
            with mock.patch.object(jlog, "LOG_DIR", log_dir), mock.patch.object(jlog, "LOG_FILE", log_file):
                jlog.append({"a": 1})
                jlog.append({"b": 2})
            lines = log_file.read_text().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0]), {"a": 1})
            self.assertEqual(json.loads(lines[1]), {"b": 2})

    def test_a_lone_surrogate_does_not_drop_the_row(self):
        """A "\\ud800" escape in the hook's JSON input decodes to a lone
        surrogate. Encoding it strictly raised and the row was silently lost."""
        entry = {"command": json.loads('"rm \\ud800 -rf x"'), "enforced": True}
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "state" / "airlock"
            log_file = log_dir / "shadow.jsonl"
            with mock.patch.object(jlog, "LOG_DIR", log_dir), mock.patch.object(jlog, "LOG_FILE", log_file):
                jlog.append(entry)
            lines = log_file.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0]), entry)

    def test_append_never_raises_on_bad_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "state" / "airlock"
            log_file = log_dir / "shadow.jsonl"
            with mock.patch.object(jlog, "LOG_DIR", log_dir), mock.patch.object(jlog, "LOG_FILE", log_file):
                # An entry containing something json.dumps would choke on
                # without default=str -- must not raise.
                class Weird:
                    pass

                jlog.append({"weird": Weird()})

    def test_append_never_raises_on_unwritable_dir(self):
        with mock.patch.object(jlog, "LOG_DIR", Path("/proc/definitely-not-writable/x")):
            jlog.append({"a": 1})  # must not raise


if __name__ == "__main__":
    unittest.main()
