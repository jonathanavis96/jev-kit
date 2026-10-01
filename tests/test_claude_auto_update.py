import tests  # noqa: F401, I001 -- MUST be the first import (see tests/test_repo_path.py).

import os
import pathlib
import subprocess
import tempfile
import unittest

from tests import posix_only

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "claude-update" / "claude-auto-update"


def _write_exe(path, body):
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


@posix_only("bash script, /proc and ps")
@unittest.skipUnless(os.path.isdir("/proc/self"), "needs /proc")
class TestInteractiveSessionProjectDir(unittest.TestCase):
    """An interactive session's transcripts live under its cwd mapped the way
    Claude Code maps it: every non-alphanumeric character becomes "-". A cwd
    with a "." or "_" in it must still be found, or an active session never
    blocks the update."""

    def _run(self, cwd_name):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            home = tmp / "home"
            home.mkdir()
            cwd = tmp / cwd_name
            cwd.mkdir(parents=True)
            prefix = tmp / "prefix"
            (prefix / "bin").mkdir(parents=True)
            _write_exe(prefix / "bin" / "claude", "echo 1.0.0\n")
            fakebin = tmp / "fakebin"
            fakebin.mkdir()
            # A sleeping process stands in for the interactive claude; the
            # fake `ps` reports it with a terminal and a bare `claude` argv.
            sleeper = subprocess.Popen(["sleep", "30"], cwd=str(cwd), env={"PATH": os.environ["PATH"]})
            try:
                _write_exe(fakebin / "pgrep", "exit 1\n")
                _write_exe(fakebin / "ps", "echo '%d pts/0 claude'\n" % sleeper.pid)
                _write_exe(fakebin / "npm", "exit 1\n")
                projects = tmp / "projects"
                mapped = "".join(c if c.isascii() and c.isalnum() else "-" for c in str(cwd))
                (projects / mapped).mkdir(parents=True)
                (projects / mapped / "s.jsonl").write_text("{}\n")
                env = {
                    "PATH": "%s:%s:%s" % (fakebin, prefix / "bin", os.environ["PATH"]),
                    "HOME": str(home),
                    "CLAUDE_UPDATE_PREFIX": str(prefix),
                    "CLAUDE_UPDATE_PROJECTS": str(projects),
                }
                subprocess.run(["bash", str(SCRIPT)], env=env, check=False,
                               capture_output=True, timeout=30)
            finally:
                sleeper.kill()
                sleeper.wait()
            return (home / "logs" / "claude-update" / "auto.log").read_text()

    def test_plain_cwd_blocks_update(self):
        self.assertIn("skip: interactive session", self._run("work/proj"))

    def test_dot_and_underscore_cwd_blocks_update(self):
        self.assertIn("skip: interactive session", self._run(".config/my_app"))


if __name__ == "__main__":
    unittest.main()
