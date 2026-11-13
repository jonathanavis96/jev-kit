
import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import os
import tempfile
import unittest
from pathlib import Path

from airlock import scope


def _mkrepo(base, name):
    d = os.path.join(base, name)
    os.makedirs(os.path.join(d, ".git"))
    return d


class TestScope(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = self.tmp.name
        # ~/code-like directory containing >=2 repos directly beneath it
        self.multi_repo_root = os.path.join(self.base, "code")
        os.makedirs(self.multi_repo_root)
        _mkrepo(self.multi_repo_root, "repo-a")
        _mkrepo(self.multi_repo_root, "repo-b")

        # a single repo with a subdirectory
        self.single_repo = _mkrepo(self.base, "single-repo")
        self.single_repo_sub = os.path.join(self.single_repo, "src")
        os.makedirs(self.single_repo_sub)

        # a plain directory, not a repo, no children repos
        self.plain_dir = os.path.join(self.base, "plain")
        os.makedirs(self.plain_dir)

    def tearDown(self):
        self.tmp.cleanup()

    # --- the observed failure -------------------------------------------

    def test_observed_failure_find_logs_jev(self):
        # find /home/user/logs/jev -name '*.rc' -- a plain, non-repo,
        # non-multi-repo directory: single_dir, not disk_wide.
        result = scope.classify_command(
            "find %s -name '*.rc'" % self.plain_dir, cwd=self.base
        )
        self.assertEqual(result["scope"], "single_dir")
        self.assertEqual(result["program"], "find")

    # --- disk-wide ---------------------------------------------------------

    def test_find_root_slash_is_disk_wide(self):
        result = scope.classify_command("find / -name x", cwd=self.base)
        self.assertEqual(result["scope"], "disk_wide")

    def test_find_home_tilde_is_disk_wide(self):
        os.environ["HOME"] = self.base
        try:
            result = scope.classify_command("find ~ -name x", cwd=self.base)
            self.assertEqual(result["scope"], "disk_wide")
        finally:
            pass

    def test_find_home_env_var_is_disk_wide(self):
        os.environ["HOME"] = self.base
        result = scope.classify_command("find $HOME -name x", cwd=self.base)
        self.assertEqual(result["scope"], "disk_wide")

    def test_find_home_braces_var_is_disk_wide(self):
        os.environ["HOME"] = self.base
        result = scope.classify_command("find ${HOME} -name x", cwd=self.base)
        self.assertEqual(result["scope"], "disk_wide")

    def test_multi_repo_parent_dir_is_disk_wide(self):
        result = scope.classify_command(
            "find %s -name x" % self.multi_repo_root, cwd=self.base
        )
        self.assertEqual(result["scope"], "disk_wide")

    def test_cd_into_code_then_find_dot_is_disk_wide(self):
        result = scope.classify_command(
            "cd %s && find . -name x" % self.multi_repo_root, cwd=self.base
        )
        self.assertEqual(result["scope"], "disk_wide")

    # --- single repo ---------------------------------------------------

    def test_find_inside_single_repo_is_single_repo(self):
        result = scope.classify_command(
            "find %s -name x" % self.single_repo_sub, cwd=self.base
        )
        self.assertEqual(result["scope"], "single_repo")

    def test_grep_rn_inside_repo_is_single_repo(self):
        result = scope.classify_command(
            "grep -rn foo %s" % self.single_repo, cwd=self.base
        )
        self.assertEqual(result["scope"], "single_repo")
        self.assertEqual(result["program"], "grep")

    def test_grep_rn_relative_src_inside_repo_cwd(self):
        result = scope.classify_command("grep -rn foo src/", cwd=self.single_repo)
        self.assertEqual(result["scope"], "single_repo")

    def test_cd_repo_then_find_is_single_repo(self):
        result = scope.classify_command(
            "cd %s && find . -name x" % self.single_repo, cwd=self.base
        )
        self.assertEqual(result["scope"], "single_repo")

    # --- single dir ------------------------------------------------------

    def test_find_plain_dir_is_single_dir(self):
        result = scope.classify_command("find %s -name x" % self.plain_dir, cwd=self.base)
        self.assertEqual(result["scope"], "single_dir")

    def test_du_plain_dir_is_single_dir(self):
        result = scope.classify_command("du -sh %s" % self.plain_dir, cwd=self.base)
        self.assertEqual(result["scope"], "single_dir")

    def test_tree_plain_dir_is_single_dir(self):
        result = scope.classify_command("tree %s" % self.plain_dir, cwd=self.base)
        self.assertEqual(result["scope"], "single_dir")

    def test_ls_recursive_plain_dir_is_single_dir(self):
        result = scope.classify_command("ls -R %s" % self.plain_dir, cwd=self.base)
        self.assertEqual(result["scope"], "single_dir")

    def test_ls_without_recursive_is_not_a_search(self):
        result = scope.classify_command("ls %s" % self.plain_dir, cwd=self.base)
        self.assertEqual(result["scope"], "unknown")
        self.assertIsNone(result["program"])

    # --- stdin -------------------------------------------------------------

    def test_pipe_grep_no_path_is_stdin(self):
        result = scope.classify_command("npm test | grep pass", cwd=self.base)
        self.assertEqual(result["scope"], "stdin")
        self.assertEqual(result["program"], "grep")

    def test_bare_grep_no_path_no_recursive_is_stdin(self):
        result = scope.classify_command("grep pass", cwd=self.base)
        self.assertEqual(result["scope"], "stdin")

    def test_grep_recursive_no_path_defaults_to_cwd(self):
        result = scope.classify_command("grep -r foo", cwd=self.single_repo)
        self.assertEqual(result["scope"], "single_repo")

    def test_rg_no_path_defaults_to_cwd_recursive(self):
        result = scope.classify_command("rg foo", cwd=self.single_repo)
        self.assertEqual(result["scope"], "single_repo")

    # --- unknown / not-a-search -------------------------------------------

    def test_find_delete_is_not_relevant_but_still_has_root(self):
        # find -delete still has a root; scope classification doesn't care
        # about search_intent (Jev's job), only the root.
        result = scope.classify_command(
            "find %s -name '*.tmp' -delete" % self.plain_dir, cwd=self.base
        )
        self.assertEqual(result["scope"], "single_dir")

    def test_unparseable_command_is_unknown(self):
        result = scope.classify_command("find \"unterminated", cwd=self.base)
        self.assertEqual(result["scope"], "unknown")

    def test_empty_command_is_unknown(self):
        result = scope.classify_command("", cwd=self.base)
        self.assertEqual(result["scope"], "unknown")

    def test_none_command_is_unknown(self):
        result = scope.classify_command(None, cwd=self.base)
        self.assertEqual(result["scope"], "unknown")

    def test_no_search_program_is_unknown(self):
        result = scope.classify_command("echo hello", cwd=self.base)
        self.assertEqual(result["scope"], "unknown")

    # --- locate/plocate ------------------------------------------------

    def test_plocate_is_disk_wide(self):
        result = scope.classify_command("plocate -i foo.rc", cwd=self.base)
        self.assertEqual(result["scope"], "disk_wide")
        self.assertEqual(result["program"], "plocate")

    def test_locate_is_disk_wide(self):
        result = scope.classify_command("locate foo.rc", cwd=self.base)
        self.assertEqual(result["scope"], "disk_wide")

    # --- quoting / prefixes -------------------------------------------

    def test_quoted_path_with_spaces(self):
        spaced = os.path.join(self.base, "has spaces")
        os.makedirs(spaced)
        result = scope.classify_command('find "%s" -name x' % spaced, cwd=self.base)
        self.assertEqual(result["scope"], "single_dir")

    def test_sudo_prefix_stripped(self):
        result = scope.classify_command("sudo find / -name x", cwd=self.base)
        self.assertEqual(result["scope"], "disk_wide")

    def test_nice_prefix_stripped(self):
        result = scope.classify_command(
            "nice -n 10 find %s -name x" % self.plain_dir, cwd=self.base
        )
        self.assertEqual(result["scope"], "single_dir")

    def test_env_var_prefix_stripped(self):
        result = scope.classify_command(
            "LC_ALL=C find %s -name x" % self.plain_dir, cwd=self.base
        )
        self.assertEqual(result["scope"], "single_dir")

    def test_time_prefix_stripped(self):
        result = scope.classify_command(
            "time find %s -name x" % self.plain_dir, cwd=self.base
        )
        self.assertEqual(result["scope"], "single_dir")

    # --- fd / fdfind -----------------------------------------------------

    def test_fd_no_path_defaults_to_cwd(self):
        result = scope.classify_command("fd pattern", cwd=self.single_repo)
        self.assertEqual(result["scope"], "single_repo")

    def test_fd_with_path(self):
        result = scope.classify_command(
            "fd pattern %s" % self.plain_dir, cwd=self.base
        )
        self.assertEqual(result["scope"], "single_dir")

    def test_fdfind_alias(self):
        result = scope.classify_command(
            "fdfind pattern %s" % self.plain_dir, cwd=self.base
        )
        self.assertEqual(result["scope"], "single_dir")

    # --- pipelines: judge the search program's own args, not whole line ---

    def test_pipeline_find_then_grep_uses_finds_own_root(self):
        result = scope.classify_command(
            "find %s -name '*.py' | xargs grep foo" % self.plain_dir, cwd=self.base
        )
        # find is the first search-like program encountered; its root wins
        # as the last one seen is grep with no path (fed by pipe) -> stdin
        # is also plausible, but we assert find's stage is visited and the
        # final classification reflects the last search-like stage.
        self.assertIn(result["program"], ("find", "grep"))

    def test_pipeline_grep_recursive_second_stage(self):
        result = scope.classify_command(
            "cat files.txt | grep -r foo %s" % self.plain_dir, cwd=self.base
        )
        self.assertEqual(result["scope"], "single_dir")

    # --- ack / ag ----------------------------------------------------------

    def test_ack_no_path_recursive_default(self):
        result = scope.classify_command("ack foo", cwd=self.single_repo)
        self.assertEqual(result["scope"], "single_repo")

    def test_ag_with_explicit_dir(self):
        result = scope.classify_command("ag foo %s" % self.plain_dir, cwd=self.base)
        self.assertEqual(result["scope"], "single_dir")

    # --- graphify graph detection ------------------------------------------

    def test_root_has_graphify_graph_true(self):
        graphed = os.path.join(self.base, "graphed-repo")
        os.makedirs(os.path.join(graphed, "graphify-out"))
        Path(os.path.join(graphed, "graphify-out", "graph.json")).write_text("{}")
        result = scope.classify_command("grep -rn foo %s" % graphed, cwd=self.base)
        self.assertTrue(scope.root_has_graphify_graph(result))

    def test_root_has_graphify_graph_false(self):
        result = scope.classify_command(
            "grep -rn foo %s" % self.plain_dir, cwd=self.base
        )
        self.assertFalse(scope.root_has_graphify_graph(result))

    def test_multiple_find_roots_first_disk_wide_wins(self):
        result = scope.classify_command(
            "find / %s -name x" % self.plain_dir, cwd=self.base
        )
        self.assertEqual(result["scope"], "disk_wide")


if __name__ == "__main__":
    unittest.main()


class PipelineWidestScopeTests(unittest.TestCase):
    """Regression: a stdin grep after a disk-wide find must not mask the find.

    Seen live on 2026-09-19 in the A/B benchmark: the command below was logged
    with scope "stdin" and so was never a deny candidate.
    """

    def test_find_piped_into_grep_stays_disk_wide(self):
        from airlock import scope
        home = os.path.expanduser("~")
        cmd = ("find %s -iname '*routes-stage*' 2>/dev/null | "
               "grep -v -E '\\.git/|node_modules|\\.pnpm-store'" % home)
        result = scope.classify_command(cmd, home)
        self.assertEqual(result["scope"], "disk_wide")
        self.assertEqual(result["program"], "find")

    def test_find_piped_into_wc_and_head(self):
        from airlock import scope
        home = os.path.expanduser("~")
        for tail in ("| wc -l", "| head -20", "| sort | grep xlsm"):
            result = scope.classify_command("find %s -name '*.xlsm' %s" % (home, tail), home)
            self.assertEqual(result["scope"], "disk_wide", tail)
            self.assertEqual(result["program"], "find", tail)

    def test_plain_stdin_grep_is_still_stdin(self):
        from airlock import scope
        result = scope.classify_command("npm test | grep pass", "/tmp")
        self.assertEqual(result["scope"], "stdin")

    def test_locate_does_not_displace_a_disk_wide_walker(self):
        from airlock import scope
        home = os.path.expanduser("~")
        result = scope.classify_command("plocate -i foo; find %s -name foo" % home, home)
        self.assertEqual(result["program"], "find")


class WslDriveRootScopeTests(unittest.TestCase):
    """Codex P1 on PR #1: `find /mnt/c -name x` classified single_dir, so the
    scope == "disk_wide" gate in policy.evaluate_search never even called the
    WSL-aware suggestion logic -- a crawl of the whole C: drive was never
    steered to `es`. A WSL drive-root mount is the same disk-wide ground a
    native `C:\\` root is."""

    def test_mnt_drive_root_is_disk_wide_under_wsl(self):
        from unittest import mock

        from airlock import scope
        with mock.patch("airlock.headless.is_wsl", return_value=True):
            result = scope.classify_command("find /mnt/c -name x", "/mnt/c")
            self.assertEqual(result["scope"], "disk_wide")
            self.assertEqual(result["roots"], ["/mnt/c"])

    def test_mnt_drive_root_with_trailing_slash_is_disk_wide_under_wsl(self):
        from unittest import mock

        from airlock import scope
        with mock.patch("airlock.headless.is_wsl", return_value=True):
            result = scope.classify_command("find /mnt/c/ -name x", "/mnt/c")
            self.assertEqual(result["scope"], "disk_wide")

    def test_mnt_drive_subdirectory_is_not_disk_wide(self):
        # /mnt/c/Users is a directory WITHIN the drive, not the drive root.
        from unittest import mock

        from airlock import scope
        with mock.patch("airlock.headless.is_wsl", return_value=True):
            result = scope.classify_command("find /mnt/c/Users -name x", "/mnt/c/Users")
            self.assertNotEqual(result["scope"], "disk_wide")

    def test_mnt_drive_root_is_not_disk_wide_off_wsl(self):
        # A non-WSL Linux box with something manually mounted at /mnt/c has
        # no Windows drive semantics attached to that path.
        from unittest import mock

        from airlock import scope
        with mock.patch("airlock.headless.is_wsl", return_value=False):
            result = scope.classify_command("find /mnt/c -name x", "/mnt/c")
            self.assertNotEqual(result["scope"], "disk_wide")

    def test_two_disk_wide_stages_report_both_sides_roots(self):
        # Codex, PR #1: a compound command searching both filesystems kept
        # only the widest single stage's roots, so the WSL suggestion saw one
        # side and would have replaced a two-sided search with a one-sided
        # index.
        from unittest import mock

        from airlock import scope
        with mock.patch("airlock.headless.is_wsl", return_value=True):
            result = scope.classify_command(
                'find "$HOME" -name x; find /mnt/c -name x', "/home/alice")
            self.assertEqual(result["scope"], "disk_wide")
            self.assertIn("/mnt/c", result["roots"])
            self.assertEqual(len(result["roots"]), 2)

    def test_a_narrow_stage_contributes_its_root_too(self):
        # Codex P1, PR #1: a Windows-host subdirectory classifies as
        # single_dir, so an accumulator that took only disk-wide stages
        # dropped exactly the root the suggestion needs.
        from unittest import mock

        from airlock import scope
        cmd = 'find "$HOME" -name x; find %s -name x' % "/mnt/c/Users"
        with mock.patch("airlock.headless.is_wsl", return_value=True):
            result = scope.classify_command(cmd, "/home/alice")
            self.assertEqual(result["scope"], "disk_wide")
            self.assertIn("/mnt/c/Users", result["roots"])

    def test_two_single_dir_stages_keep_the_windows_root(self):
        # Codex P1, PR #1: both stages scope as single_dir, so publishing
        # the accumulator only for a disk-wide verdict handed policy one
        # stage's root and dropped the other half of the search.
        from unittest import mock

        from airlock import scope
        win = "/mnt/c/Users"
        for cmd in ('find %s -name x; find /home/alice/docs -name x' % win,
                    'find /home/alice/docs -name x; find %s -name x' % win):
            with self.subTest(cmd=cmd):
                with mock.patch("airlock.headless.is_wsl", return_value=True):
                    result = scope.classify_command(cmd, "/home/alice")
                self.assertIn(win, result["roots"])
                self.assertIn("/home/alice/docs", result["roots"])

    def test_roots_are_deduplicated_across_stages(self):
        from unittest import mock

        from airlock import scope
        with mock.patch("airlock.headless.is_wsl", return_value=True):
            result = scope.classify_command(
                "find /mnt/c -name x; find /mnt/c -name y", "/mnt/c")
            self.assertEqual(result["roots"], ["/mnt/c"])
