
import tests  # noqa: F401, I001 -- MUST be the first import. `python3 -m unittest
# discover -s tests` runs with start_dir == top_level_dir, so unittest treats
# `tests/` as a flat directory of top-level modules and never executes
# tests/__init__.py as a package init (name == '.' in TestLoader._find_tests).
# Importing it explicitly, here, first, is what actually runs its HOME/
# AIRLOCK_*-isolating fixture before any airlock.* module resolves a real path.

import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

from tuning import tune


def _git(*args, cwd):
    subprocess.run(
        ["git"] + list(args), cwd=str(cwd), check=True,
        capture_output=True, text=True,
        env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                  GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t"),
    )


def _make_repo(path):
    path.mkdir(parents=True, exist_ok=True)
    _git("init", "-q", "-b", "main", cwd=path)
    (path / "README").write_text("hi\n")
    _git("add", "README", cwd=path)
    _git("commit", "-q", "-m", "init", cwd=path)
    return path


class TestResolveMainRepo(unittest.TestCase):
    """tune.py's own resolution, delegating to airlock.repo_path -- the fix
    for the real bug: a deployed release's tuning/tune.py has no .git next to
    it, so deriving 'the repo' from its own location must not be the only
    path, and must give up (None) rather than raise when nothing resolves."""

    def test_resolves_via_own_checkout_when_no_pointer_and_no_env(self):
        with tempfile.TemporaryDirectory() as home:
            repo = _make_repo(pathlib.Path(home) / "repo")
            config = pathlib.Path(home) / ".config" / "airlock"
            config.mkdir(parents=True)
            env = {k: v for k, v in os.environ.items() if k != "AIRLOCK_TUNE_REPO"}
            with mock.patch.dict(os.environ, {**env, "AIRLOCK_CONFIG_DIR": str(config)}, clear=True):
                got = tune.resolve_main_repo(repo / "tuning")
        self.assertEqual(got, repo.resolve())

    def test_deployed_release_with_no_git_resolves_to_none(self):
        with tempfile.TemporaryDirectory() as home:
            deployed = pathlib.Path(home) / "current"
            (deployed / "tuning").mkdir(parents=True)
            config = pathlib.Path(home) / ".config" / "airlock"
            config.mkdir(parents=True)
            env = {k: v for k, v in os.environ.items() if k != "AIRLOCK_TUNE_REPO"}
            with mock.patch.dict(os.environ, {**env, "AIRLOCK_CONFIG_DIR": str(config)}, clear=True):
                got = tune.resolve_main_repo(deployed / "tuning")
        self.assertIsNone(got)

    def test_env_override_wins(self):
        with tempfile.TemporaryDirectory() as home:
            repo = _make_repo(pathlib.Path(home) / "repo")
            other = _make_repo(pathlib.Path(home) / "other")
            config = pathlib.Path(home) / ".config" / "airlock"
            config.mkdir(parents=True)
            with mock.patch.dict(os.environ, {"AIRLOCK_TUNE_REPO": str(other),
                                               "AIRLOCK_CONFIG_DIR": str(config)}):
                got = tune.resolve_main_repo(repo / "tuning")
        self.assertEqual(got, other.resolve())


class TestForeignWorktree(unittest.TestCase):
    """An existing tune-worktree that belongs to a DIFFERENT repository must
    never be reused or deleted: it is moved aside to a .retired-<ts> sibling
    and a fresh worktree is created from the newly-resolved repository."""

    def test_worktree_belongs_to_detects_mismatch(self):
        with tempfile.TemporaryDirectory() as home:
            repo_a = _make_repo(pathlib.Path(home) / "a")
            repo_b = _make_repo(pathlib.Path(home) / "b")
            worktree = pathlib.Path(home) / "wt"
            _git("worktree", "add", "-b", "auto-tune", str(worktree), "main", cwd=repo_a)
            self.assertTrue(tune._worktree_belongs_to(worktree, repo_a))
            self.assertFalse(tune._worktree_belongs_to(worktree, repo_b))

    def test_non_worktree_directory_is_not_a_match(self):
        with tempfile.TemporaryDirectory() as home:
            repo = _make_repo(pathlib.Path(home) / "repo")
            plain = pathlib.Path(home) / "plain"
            plain.mkdir()
            self.assertFalse(tune._worktree_belongs_to(plain, repo))

    def test_retire_moves_worktree_aside_and_preserves_it(self):
        with tempfile.TemporaryDirectory() as home:
            repo_a = _make_repo(pathlib.Path(home) / "a")
            worktree = pathlib.Path(home) / "wt"
            _git("worktree", "add", "-b", "auto-tune", str(worktree), "main", cwd=repo_a)
            marker = worktree / "README"
            self.assertTrue(marker.exists())

            retired = tune.retire_foreign_worktree(worktree)

            self.assertFalse(worktree.exists())
            self.assertTrue(retired.exists())
            self.assertTrue(str(retired).startswith(str(worktree) + ".retired-"))
            self.assertTrue((retired / "README").exists())

    def test_ensure_tune_worktree_retires_foreign_and_creates_fresh(self):
        with tempfile.TemporaryDirectory() as home:
            old_repo = _make_repo(pathlib.Path(home) / "old")
            new_repo = _make_repo(pathlib.Path(home) / "new")
            worktree = pathlib.Path(home) / "tune-worktree"
            _git("worktree", "add", "-b", "auto-tune", str(worktree), "main", cwd=old_repo)

            with mock.patch.object(tune, "WORKTREE_DIR", worktree):
                tune.ensure_tune_worktree(new_repo)

            # old worktree dir gone from its original path, moved aside instead
            retired_candidates = list(pathlib.Path(home).glob("tune-worktree.retired-*"))
            self.assertEqual(len(retired_candidates), 1)
            self.assertTrue((retired_candidates[0] / "README").exists())

            # a fresh worktree now exists at the same path, from new_repo
            self.assertTrue(worktree.exists())
            self.assertTrue(tune._worktree_belongs_to(worktree, new_repo))

    def test_ensure_tune_worktree_reuses_matching_worktree(self):
        with tempfile.TemporaryDirectory() as home:
            repo = _make_repo(pathlib.Path(home) / "repo")
            worktree = pathlib.Path(home) / "tune-worktree"
            _git("worktree", "add", "-b", "auto-tune", str(worktree), "main", cwd=repo)

            with mock.patch.object(tune, "WORKTREE_DIR", worktree), \
                 mock.patch.object(tune, "BASE_BRANCH", "main"):
                # should rebase (no-op, nothing new on main) rather than retire
                tune.ensure_tune_worktree(repo)

            self.assertTrue(worktree.exists())
            self.assertFalse(list(pathlib.Path(home).glob("tune-worktree.retired-*")))


    def test_a_dirty_worktree_left_by_a_crashed_run_does_not_block_the_rebase(self):
        with tempfile.TemporaryDirectory() as home:
            repo = _make_repo(pathlib.Path(home) / "repo")
            worktree = pathlib.Path(home) / "tune-worktree"
            _git("worktree", "add", "-b", "auto-tune", str(worktree), "main", cwd=repo)
            (worktree / "README").write_text("half-written by a run that died\n")
            (repo / "NEW").write_text("x\n")
            _git("add", "NEW", cwd=repo)
            _git("commit", "-q", "-m", "new on main", cwd=repo)

            with mock.patch.object(tune, "WORKTREE_DIR", worktree), \
                 mock.patch.object(tune, "BASE_BRANCH", "main"):
                tune.ensure_tune_worktree(repo)

            self.assertEqual((worktree / "README").read_text(), "hi\n")
            self.assertTrue((worktree / "NEW").exists())

if __name__ == "__main__":
    unittest.main()
