import tests  # noqa: F401, I001 -- MUST be the first import; see test_policy.py.

import os
import tempfile
import unittest
from unittest import mock

from airlock import policy, redact
from airlock import scope as scope_mod

_ABOVE_BAR_CONFIDENCE = 0.9
_ABOVE_BAR_MARGIN = 0.6

# Every fixture root here is under /home/alice, matching winpath.py's
# docstring convention. plocate's home.db covers $HOME and nothing else, so
# whether /home/alice counts as indexed ground depends on HOME (Codex P1,
# PR #1: /opt was being reported as plocate's ground). Pin it for the file.
_HOME = mock.patch.dict(os.environ, {"HOME": "/home/alice"})


# The suggestion now depends on what the machine has: Everything's client
# on PATH, and which plocate database exists. Pin both, so the file asserts
# the policy rather than the box it runs on.
# Captured before the pin below replaces it, so the one test that checks the
# detection itself can still reach the real function.
_REAL_ES_AVAILABLE = policy.es_available

_AVAIL = mock.patch.multiple(policy,
                             es_available=lambda *a, **k: True,
                             plocate_db_kind=lambda *a, **k: "home")


def setUpModule():
    _HOME.start()
    _AVAIL.start()


def tearDownModule():
    _AVAIL.stop()
    _HOME.stop()


class TestFilenameSearchSuggestionWsl(unittest.TestCase):
    def test_wsl_windows_host_root_gets_es_wsl_suggestion(self):
        self.assertEqual(
            policy.filename_search_suggestion(wsl=True, roots=["/mnt/c/Users/x"]),
            policy.ES_WSL_SUGGESTION,
        )

    def test_wsl_linux_home_root_gets_plocate(self):
        self.assertEqual(
            policy.filename_search_suggestion(wsl=True, roots=["/home/alice"]),
            policy.PLOCATE_SUGGESTION,
        )

    def test_wsl_mixed_roots_get_both_indexes(self):
        # The real failing command's roots: a Linux root and a /mnt/c root.
        # Everything cannot search the Linux side and plocate cannot search
        # /mnt, so naming either one alone would silently drop half the search
        # (Codex P1 on PR #1; this test previously asserted the ES-only answer).
        self.assertEqual(
            policy.filename_search_suggestion(
                wsl=True, roots=["/home/alice", "/mnt/c/Users"],
            ),
            policy.ES_WSL_MIXED_SUGGESTION,
        )

    def test_wsl_windows_only_roots_get_es_wsl(self):
        self.assertEqual(
            policy.filename_search_suggestion(
                wsl=True, roots=["/mnt/c/Users", "/mnt/d/data"],
            ),
            policy.ES_WSL_SUGGESTION,
        )

    def test_wsl_no_roots_gets_plocate(self):
        self.assertEqual(
            policy.filename_search_suggestion(wsl=True, roots=None),
            policy.PLOCATE_SUGGESTION,
        )
        self.assertEqual(
            policy.filename_search_suggestion(wsl=True, roots=[]),
            policy.PLOCATE_SUGGESTION,
        )

    def test_native_windows_always_gets_es_suggestion_regardless_of_roots(self):
        self.assertEqual(
            policy.filename_search_suggestion(windows=True, roots=["/mnt/c/Users"]),
            policy.ES_SUGGESTION,
        )
        self.assertEqual(
            policy.filename_search_suggestion(windows=True, roots=None, wsl=True),
            policy.ES_SUGGESTION,
        )

    def test_non_wsl_linux_with_mnt_root_gets_plocate(self):
        # A non-WSL Linux box has no Everything to fall back to.
        self.assertEqual(
            policy.filename_search_suggestion(wsl=False, roots=["/mnt/c/Users"]),
            policy.PLOCATE_SUGGESTION,
        )


class TestRootIsWindowsHost(unittest.TestCase):
    def test_mnt_mount_roots_are_windows_host(self):
        self.assertTrue(policy.root_is_windows_host("/mnt/c/Users/x"))
        self.assertTrue(policy.root_is_windows_host("/mnt/c"))

    def test_native_windows_path_is_windows_host(self):
        self.assertTrue(policy.root_is_windows_host(r"C:\Users\alice",
                                                    windows=True))

    def test_msys_drive_is_a_linux_path_under_wsl(self):
        # /c/projects on WSL is an ordinary Linux directory. Everything
        # cannot search it, so reading it as a drive would deny a working
        # crawl and hand back a query for a path that does not exist.
        self.assertFalse(policy.root_is_windows_host("/c/projects",
                                                     windows=False))
        self.assertTrue(policy.root_is_windows_host("/c/projects",
                                                    windows=True))

    def test_linux_paths_are_not_windows_host(self):
        self.assertFalse(policy.root_is_windows_host("/home/alice"))
        self.assertFalse(policy.root_is_windows_host("/mnt2/c/Users"))

    def test_none_and_empty_never_raise(self):
        self.assertFalse(policy.root_is_windows_host(None))
        self.assertFalse(policy.root_is_windows_host(""))

    def test_any_root_is_windows_host_over_none_list(self):
        self.assertFalse(policy.any_root_is_windows_host(None))
        self.assertFalse(policy.any_root_is_windows_host([]))
        self.assertTrue(policy.any_root_is_windows_host(["/home/alice", "/mnt/c/Users"]))


class TestCommandAlreadyUsesIndexedSearchWsl(unittest.TestCase):
    def test_es_command_recognised_under_wsl(self):
        self.assertTrue(
            policy.command_already_uses_indexed_search(
                'es -path "C:\\Users" -n 50 x', wsl=True,
            )
        )

    def test_same_command_not_recognised_off_wsl_off_windows(self):
        self.assertFalse(
            policy.command_already_uses_indexed_search(
                'es -path "C:\\Users" -n 50 x', wsl=False, windows=False,
            )
        )

    def test_command_already_uses_locate_still_works(self):
        self.assertTrue(policy.command_already_uses_locate("plocate -i foo"))
        self.assertFalse(policy.command_already_uses_locate("grep -r foo ."))


class TestEvaluateSearchWsl(unittest.TestCase):
    def test_disk_wide_filename_search_mnt_root_wsl_denies_with_es_wsl_suggestion(self):
        verdict = policy.evaluate_search(
            scope="disk_wide",
            search_intent="filename_search",
            confidence=_ABOVE_BAR_CONFIDENCE,
            command='find / -iname "*jev-kit*"',
            root_has_graphify_graph=False,
            margin=_ABOVE_BAR_MARGIN,
            roots=["/home/alice", "/mnt/c/Users"],
            wsl=True,
        )
        self.assertTrue(verdict["would_deny"])
        self.assertEqual(verdict["suggestion"], policy.ES_WSL_MIXED_SUGGESTION)

    def _mixed_verdict(self, command):
        return policy.evaluate_search(
            scope="disk_wide",
            search_intent="filename_search",
            confidence=_ABOVE_BAR_CONFIDENCE,
            command=command,
            root_has_graphify_graph=False,
            margin=_ABOVE_BAR_MARGIN,
            roots=["/home/alice", "/mnt/c/Users"],
            wsl=True,
        )

    def test_es_alone_does_not_cover_a_mixed_search(self):
        # Codex P2, PR #1: es indexes the Windows half only, so the crawl of
        # the Linux half is still unanswered and the deny must stand.
        verdict = self._mixed_verdict(
            'find "$HOME" /mnt/c/Users -name x; es -path "C:\\Users" x')
        self.assertTrue(verdict["would_deny"])

    def test_plocate_alone_does_not_cover_a_mixed_search(self):
        verdict = self._mixed_verdict(
            'find "$HOME" /mnt/c/Users -name x; plocate -i x')
        self.assertTrue(verdict["would_deny"])

    def test_both_indexes_named_cover_a_mixed_search(self):
        verdict = self._mixed_verdict(
            'plocate -d ~/.cache/plocate/home.db -i x; es -path "C:\\Users" x')
        self.assertFalse(verdict["would_deny"])

    def test_windows_host_root_denies_even_below_disk_wide(self):
        # Codex P1, PR #1: `find /mnt/c/Users -name x` scopes as single_dir,
        # so the old disk_wide-only gate let a crawl of the Windows
        # filesystem through untouched.
        verdict = policy.evaluate_search(
            scope="single_dir",
            search_intent="filename_search",
            confidence=_ABOVE_BAR_CONFIDENCE,
            command="find /mnt/c/Users -name x",
            root_has_graphify_graph=False,
            margin=_ABOVE_BAR_MARGIN,
            roots=["/mnt/c/Users"],
            wsl=True,
        )
        self.assertTrue(verdict["would_deny"])
        self.assertEqual(verdict["suggestion"], policy.ES_WSL_SUGGESTION)

    def test_a_linux_side_single_dir_search_still_allows(self):
        verdict = policy.evaluate_search(
            scope="single_dir",
            search_intent="filename_search",
            confidence=_ABOVE_BAR_CONFIDENCE,
            command="find /home/alice/notes -name x",
            root_has_graphify_graph=False,
            margin=_ABOVE_BAR_MARGIN,
            roots=["/home/alice/notes"],
            wsl=True,
        )
        self.assertFalse(verdict["would_deny"])



class TestMixedRootsNameBothIndexes(unittest.TestCase):
    """Codex P1 on PR #1: a disk-wide search spanning both filesystems was
    answered with the Everything suggestion alone, because any_root_is_windows_host
    is satisfied by a single /mnt root. Everything cannot search the Linux side,
    so that advice silently drops every result from the $HOME roots."""

    def test_mixed_roots_get_both_commands(self):
        s = policy.filename_search_suggestion(
            windows=False, roots=["/home/alice/notes", "/mnt/c/Users"], wsl=True)
        self.assertIs(s, policy.ES_WSL_MIXED_SUGGESTION)
        self.assertIn("plocate", s)
        self.assertIn("es -path", s)

    def test_windows_only_roots_still_get_everything_alone(self):
        self.assertIs(
            policy.filename_search_suggestion(
                windows=False, roots=["/mnt/c/Users", "/mnt/d/data"], wsl=True),
            policy.ES_WSL_SUGGESTION)

    def test_home_only_roots_still_get_plocate_alone(self):
        self.assertIs(
            policy.filename_search_suggestion(
                windows=False, roots=["/home/alice", "/home/alice/notes"], wsl=True),
            policy.PLOCATE_SUGGESTION)

    def test_a_linux_root_outside_home_is_not_plocate_ground(self):
        # Codex P1, PR #1: home.db indexes $HOME only, so promising plocate
        # for /opt reports every file there as absent.
        #
        # A Linux-only pair gets the Linux form. It used to get the
        # whole-filesystem text, which names `es` for /mnt/<drive> roots
        # this search never touches (review finding, PR #1).
        self.assertIs(
            policy.filename_search_suggestion(
                windows=False, roots=["/home/alice", "/opt"], wsl=True),
            policy.LINUX_MIXED_SUGGESTION)
        self.assertNotIn("es -path", policy.LINUX_MIXED_SUGGESTION)
        # Add a Windows-host root and Everything belongs in the advice.
        self.assertIs(
            policy.filename_search_suggestion(
                windows=False, roots=["/opt", "/mnt/c"], wsl=True),
            policy.ES_WSL_WHOLE_FS_SUGGESTION)

    def test_the_command_that_started_this(self):
        """`find "$HOME" /mnt/c/Users -name x` -- the real failing call."""
        self.assertIs(
            policy.filename_search_suggestion(
                windows=False, roots=["/home/alice/notes", "/mnt/c/Users"], wsl=True),
            policy.ES_WSL_MIXED_SUGGESTION)

    def test_any_root_is_linux_side(self):
        self.assertTrue(policy.any_root_is_linux_side(["/home/x", "/mnt/c"]))
        self.assertTrue(policy.any_root_is_linux_side(["/opt"]))
        self.assertFalse(policy.any_root_is_linux_side(["/mnt/c/Users"]))
        self.assertFalse(policy.any_root_is_linux_side([]))
        self.assertFalse(policy.any_root_is_linux_side(None))


class TestWslFsRootSpansBothIndexes(unittest.TestCase):
    """Codex P1 on PR #1: `find / -name x` under WSL has roots=["/"], which
    any_root_is_windows_host answered False for (it isn't a /mnt/<drive> or
    Windows-looking path), so it fell through to PLOCATE_SUGGESTION alone --
    even though traversing '/' also traverses every mounted Windows drive
    under /mnt, and Everything's ground was silently dropped."""

    def test_fs_root_alone_gets_mixed_suggestion(self):
        self.assertEqual(
            policy.filename_search_suggestion(wsl=True, roots=["/"]),
            policy.ES_WSL_WHOLE_FS_SUGGESTION,
        )

    def test_fs_root_with_other_roots_still_gets_mixed_suggestion(self):
        self.assertEqual(
            policy.filename_search_suggestion(wsl=True, roots=["/", "/mnt/c/Users"]),
            policy.ES_WSL_WHOLE_FS_SUGGESTION,
        )

    def test_fs_root_off_wsl_gets_plocate_alone(self):
        # No Everything to fall back to off WSL.
        self.assertEqual(
            policy.filename_search_suggestion(wsl=False, roots=["/"]),
            policy.PLOCATE_SUGGESTION,
        )

    def test_root_is_wsl_fs_root(self):
        self.assertTrue(policy.root_is_wsl_fs_root("/"))
        self.assertFalse(policy.root_is_wsl_fs_root("/home/alice"))
        self.assertFalse(policy.root_is_wsl_fs_root("/mnt/c"))
        self.assertFalse(policy.root_is_wsl_fs_root(None))
        self.assertFalse(policy.root_is_wsl_fs_root(""))

    def test_evaluate_search_fs_root_wsl_denies_with_mixed_suggestion(self):
        verdict = policy.evaluate_search(
            scope="disk_wide",
            search_intent="filename_search",
            confidence=_ABOVE_BAR_CONFIDENCE,
            command='find / -iname "*jev-kit*"',
            root_has_graphify_graph=False,
            margin=_ABOVE_BAR_MARGIN,
            roots=["/"],
            wsl=True,
        )
        self.assertTrue(verdict["would_deny"])
        self.assertEqual(verdict["suggestion"], policy.ES_WSL_WHOLE_FS_SUGGESTION)


class TestPrefilterLetsWindowsHostRootsThrough(unittest.TestCase):
    """Codex P1 on PR #1: evaluate_search grew a Windows-host branch, but
    compute_search_entry asks deny_possible_bash first and that still said
    no deny was reachable below disk_wide, so the branch never ran live."""

    def test_windows_host_root_below_disk_wide_is_deny_possible(self):
        self.assertTrue(policy.deny_possible_bash(
            "single_dir", "find", False, roots=["/mnt/c/Users"], wsl=True))

    def test_the_same_root_off_wsl_is_not(self):
        self.assertFalse(policy.deny_possible_bash(
            "single_dir", "find", False, roots=["/mnt/c/Users"], wsl=False))

    def test_a_linux_side_single_dir_is_still_skipped(self):
        self.assertFalse(policy.deny_possible_bash(
            "single_dir", "find", False, roots=["/home/alice/notes"], wsl=True))

    def test_a_plocate_command_that_still_crawls_the_host_is_judged(self):
        # Codex P2, PR #1: the program is plocate, so the prefilter skipped
        # the call, but another stage crawls /mnt/c/Users.
        self.assertTrue(policy.deny_possible_bash(
            "disk_wide", "plocate", False,
            roots=["/home/alice", "/mnt/c/Users"], wsl=True))

    def test_an_es_command_is_still_skipped(self):
        self.assertFalse(policy.deny_possible_bash(
            "single_dir", "es", False, roots=["/mnt/c/Users"], wsl=True))


class TestTheAdviceMatchesTheMachine(unittest.TestCase):
    """Found by audit, not by review: every suggestion above names tools
    and a database that this repository's author happens to have. On any
    other machine the deny would block the crawl and hand back a command
    that fails."""

    def test_no_everything_client_means_no_deny_for_a_windows_root(self):
        with mock.patch.object(policy, "es_available", lambda *a, **k: False):
            self.assertIsNone(policy.filename_search_suggestion(
                windows=False, roots=["/mnt/c/Users"], wsl=True,
                has_es=False))
            verdict = policy.evaluate_search(
                scope="disk_wide", search_intent="filename_search",
                confidence=_ABOVE_BAR_CONFIDENCE, command="find /mnt/c -name x",
                root_has_graphify_graph=False, margin=_ABOVE_BAR_MARGIN,
                roots=["/mnt/c"], wsl=True, has_es=False)
            self.assertFalse(verdict["would_deny"])
            self.assertIsNone(verdict["suggestion"])

    def test_no_plocate_database_means_no_deny_on_plain_linux(self):
        self.assertIsNone(policy.filename_search_suggestion(
            windows=False, roots=["/home/alice"], wsl=False, db_kind=None,
            has_es=False))

    def test_a_system_database_names_itself_and_covers_the_linux_side(self):
        self.assertEqual(
            policy.filename_search_suggestion(
                windows=False, roots=["/opt"], wsl=False, db_kind="system"),
            "plocate -i '<pattern>'")
        # /opt IS indexed by the system database, so a mixed search gets
        # the two-index advice rather than the keep-crawling one.
        s = policy.filename_search_suggestion(
            windows=False, roots=["/opt", "/mnt/c"], wsl=True,
            db_kind="system")
        self.assertIn("plocate -i '<pattern>'", s)
        self.assertIn("es -path", s)
        self.assertNotIn("home.db", s)

    def test_locate_without_plocate_is_named_as_locate(self):
        # A machine with locate but no plocate was handed `plocate -i ...`,
        # a command it cannot run.
        self.assertEqual(
            policy.plocate_command("system-locate"), "locate -i '<pattern>'")
        self.assertEqual(
            policy.plocate_command("home-locate"),
            "locate -d ~/.cache/plocate/home.db -i '<pattern>'")
        # The -locate variants cover exactly the ground their base kind does.
        self.assertTrue(policy.root_is_plocate_covered(
            "/opt", db_kind="system-locate"))
        self.assertFalse(policy.root_is_plocate_covered(
            "/opt", home="/home/alice", db_kind="home-locate"))

    def test_probes_do_not_depend_on_what_this_host_has_installed(self):
        # The generated policy and its pinned fingerprint must read the same
        # on a machine with no index at all.
        with mock.patch.object(policy, "plocate_db_kind",
                               lambda *a, **k: None), \
                mock.patch.object(policy, "es_available",
                                  lambda *a, **k: False):
            self.assertEqual(
                policy.filename_search_suggestion(
                    windows=False, roots=["/home/alice"], wsl=False),
                policy.PLOCATE_SUGGESTION)
            verdict = policy.evaluate_search(
                scope="disk_wide", search_intent="filename_search",
                confidence=_ABOVE_BAR_CONFIDENCE, command="find / -name x",
                root_has_graphify_graph=False, margin=_ABOVE_BAR_MARGIN,
                roots=["/"], wsl=False)
            self.assertTrue(verdict["would_deny"])

    def test_find_without_L_does_not_follow_a_symlink_root(self):
        # GNU find examines a symlink root itself; it never enters the
        # target, so the search visits nothing on the Windows host.
        self.assertFalse(policy.command_follows_symlinks("find link -name x"))
        self.assertTrue(policy.command_follows_symlinks("find -L link -name x"))
        self.assertTrue(policy.command_follows_symlinks("find -H link -name x"))
        # Anything that is not find follows what the path resolves to.
        self.assertTrue(policy.command_follows_symlinks("rg -l foo link"))
        self.assertTrue(policy.command_follows_symlinks(None))

    def test_a_stopped_everything_service_is_not_a_usable_index(self):
        # es on PATH with the service stopped returns nothing, so a deny
        # would block a working crawl for a command that finds no files.
        policy._AVAILABILITY_CACHE.clear()
        try:
            with mock.patch.object(policy, "_tool_on_path",
                                   lambda *a, **k: True), \
                    mock.patch("airlock.everything.service_running",
                               lambda *a, **k: False):
                self.assertFalse(_REAL_ES_AVAILABLE(windows=False))
            policy.reset_availability_cache()
            with mock.patch.object(policy, "_tool_on_path",
                                   lambda *a, **k: True), \
                    mock.patch("airlock.everything.service_running",
                               lambda *a, **k: True):
                self.assertTrue(_REAL_ES_AVAILABLE(windows=False))
            # A service state that cannot be determined is NOT usable. It
            # is indistinguishable from a stopped service, and denying on
            # it replaces a working crawl with a query that finds nothing.
            policy.reset_availability_cache()
            with mock.patch.object(policy, "_tool_on_path",
                                   lambda *a, **k: True), \
                    mock.patch("airlock.everything.service_running",
                               lambda *a, **k: None):
                self.assertFalse(_REAL_ES_AVAILABLE(windows=False))
        finally:
            policy.reset_availability_cache()

    def test_a_bare_es_client_counts_under_wsl(self):
        # The documented WSL setup is a client named `es` and no `es.exe`.
        # everything.find_es() searches for es.exe alone, so deciding
        # presence from status() wrote Everything off as missing.
        policy.reset_availability_cache()
        try:
            seen = []

            def only_bare_es(name):
                seen.append(name)
                return name == "es"

            with mock.patch.object(policy, "_tool_on_path", only_bare_es), \
                    mock.patch("airlock.everything.service_running",
                               lambda *a, **k: True):
                self.assertTrue(_REAL_ES_AVAILABLE(windows=False))
            self.assertIn("es", seen)
            self.assertNotIn("es.exe", seen)
        finally:
            policy.reset_availability_cache()

    def test_the_service_probe_uses_the_exe_name_when_bare_fails(self):
        # Under WSL interop runs Windows tools only as `<name>.exe`, so the
        # bare probes could not run and always answered "unknown" -- which
        # is indistinguishable from a stopped service.
        from airlock import everything
        seen = []

        def runner(argv):
            seen.append(argv[0])
            if not argv[0].endswith(".exe"):
                return 1, "No such file or directory: '%s'" % argv[0]
            if argv[0] == "sc.exe":
                return 0, "STATE : 4 RUNNING"
            return 0, "Everything.exe 5836"

        self.assertTrue(everything.service_running(runner=runner))
        self.assertIn("sc", seen)
        self.assertIn("sc.exe", seen)

    def test_a_stopped_service_is_still_reported_stopped(self):
        from airlock import everything

        def runner(argv):
            if not argv[0].endswith(".exe"):
                return 1, "No such file or directory"
            if argv[0] == "sc.exe":
                return 0, "STATE : 1 STOPPED"
            return 0, "INFO: No tasks are running"

        self.assertFalse(everything.service_running(runner=runner))

    def test_no_plocate_database_means_no_mixed_or_whole_fs_deny(self):
        # Both lines of the mixed advice name plocate. With no database the
        # replacement cannot run, and the whole-filesystem form's `find`
        # line covers only Linux paths outside $HOME, so following it drops
        # the home-side results.
        self.assertIsNone(policy.filename_search_suggestion(
            windows=False, roots=["/home/alice", "/mnt/c/Users"], wsl=True,
            db_kind=None, has_es=True))
        self.assertIsNone(policy.filename_search_suggestion(
            windows=False, roots=["/"], wsl=True,
            db_kind=None, has_es=True))
        # A Windows-host root ALONE needs no plocate, so it still denies.
        self.assertEqual(
            policy.filename_search_suggestion(
                windows=False, roots=["/mnt/c/Users"], wsl=True,
                db_kind=None, has_es=True),
            policy.ES_WSL_SUGGESTION)

    def test_find_roots_come_after_its_global_options(self):
        # `find -L /mnt/c/Users -name x` recorded the working directory,
        # so the prefilter saw neither a disk-wide nor a Windows-host
        # search and skipped the judgement entirely.
        from airlock import scope
        for command in ("find -L /mnt/c/Users -name x",
                        "find -H /mnt/c/Users -name x",
                        "find -P /mnt/c/Users -name x",
                        "find -O2 /mnt/c/Users -name x",
                        "find -D search /mnt/c/Users -name x"):
            result = scope.classify_command(command)
            self.assertIn("/mnt/c/Users", result["roots"], command)

    def test_find_accepts_an_end_of_options_marker(self):
        # `find -- /mnt/c/Users -name x` run from a Linux directory was
        # classified with that directory as its root, so the deny named
        # plocate and dropped the Windows-host results.
        from airlock import scope
        self.assertIn("/mnt/c/Users",
                      scope.classify_command("find -- /mnt/c/Users -name x")["roots"])
        self.assertIn("/mnt/c/Users",
                      scope.classify_command("find -L -- /mnt/c/Users -name x")["roots"])

    def test_a_shell_comment_is_not_a_second_command(self):
        # Bash ignores everything after an unquoted `#`, so the `es` here
        # never runs and the crawl still needs steering.
        self.assertFalse(policy.command_covers_roots(
            "find /mnt/c -name x # ; es placeholder",
            roots=["/mnt/c"], windows=False, wsl=True))
        # A `#` inside quotes is part of a filename, not a comment.
        self.assertTrue(policy.command_covers_roots(
            'find /mnt/c -name "a#b"; es x',
            roots=["/mnt/c"], windows=False, wsl=True))
        # An escaped `#` is likewise not a comment.
        self.assertTrue(policy.command_covers_roots(
            "find /mnt/c -name a\\#b; es x",
            roots=["/mnt/c"], windows=False, wsl=True))
        # A comment ends at the newline; a later line still counts.
        self.assertTrue(policy.command_covers_roots(
            "find /mnt/c -name x # comment\nes -path C:/ x",
            roots=["/mnt/c"], windows=False, wsl=True))

    def test_a_commented_out_stage_is_not_a_search_root(self):
        # Only the /opt search runs. Accumulating the commented $HOME root
        # turned a single directory into a disk-wide verdict, which the
        # deny bar then answered with the whole-filesystem suggestion.
        from airlock import scope
        result = scope.classify_command(
            'find /opt -name x # ; find "$HOME" -name x')
        self.assertEqual(result["scope"], "single_dir")
        self.assertEqual(result["roots"], ["/opt"])
        # A quoted `#` is part of a filename, so the stage still counts.
        self.assertEqual(
            scope.classify_command('find /opt -name "a#b"')["roots"], ["/opt"])

    def test_policy_and_scope_share_one_comment_parser(self):
        # The comment fix landed in policy and not in scope, and a
        # commented-out stage was still read as a real search.
        from airlock import policy as _p
        from airlock import scope as _s
        self.assertIs(_p._strip_shell_comment("x # y").__class__, str)
        for command in ('find /opt -name x # ; es y',
                        'find /opt -name "a#b"',
                        "find /opt -name a\\#b",
                        "find /opt -name x # c\nes -path C:/ y"):
            self.assertEqual(_p._strip_shell_comment(command),
                             _s.strip_shell_comment(command), command)

    def test_only_finds_leading_options_decide_dereferencing(self):
        # `-L` after the roots is an argument. In `find link -name -L` it
        # is the pattern -name matches, and scanning the whole stage read
        # it as dereferencing.
        self.assertFalse(policy.command_follows_symlinks("find link -name -L"))
        self.assertFalse(policy.command_follows_symlinks("find link -name -H"))
        # find(1): the last of -H, -L, -P takes effect.
        self.assertTrue(policy.command_follows_symlinks("find -P -L link -name x"))
        self.assertFalse(policy.command_follows_symlinks("find -L -P link -name x"))
        # A global option with a value does not hide the one after it.
        self.assertTrue(policy.command_follows_symlinks("find -O2 -L link -name x"))
        self.assertTrue(policy.command_follows_symlinks("find -D search -L link -name x"))
        self.assertTrue(policy.command_follows_symlinks("find -L -- link -name x"))

    def test_locate_must_be_invoked_not_merely_named(self):
        # `-name plocate` is a filename pattern. Matching it anywhere in
        # the text concluded both indexes were present and left the
        # Linux-side crawl unsteered.
        self.assertFalse(policy.command_covers_roots(
            'find "$HOME" /mnt/c -name plocate; es -path C:/ x',
            roots=[os.path.expanduser("~"), "/mnt/c"],
            windows=False, wsl=True))
        # Actually invoking it still counts.
        self.assertTrue(policy.command_covers_roots(
            'plocate -i x; es -path C:/ x',
            roots=[os.path.expanduser("~"), "/mnt/c"],
            windows=False, wsl=True))

    def test_a_comment_needs_no_space_before_it(self):
        # `;` delimits a word without whitespace, so `x;#` starts a comment.
        from airlock import scope
        self.assertEqual(
            scope.shell_segments("find /mnt/c -name x;# ; es placeholder"),
            [["find", "/mnt/c", "-name", "x"]])
        self.assertFalse(policy.command_covers_roots(
            "find /mnt/c -name x;# ; es placeholder",
            roots=["/mnt/c"], windows=False, wsl=True))

    def test_the_lexer_reads_what_bash_would_run(self):
        # One lexer now answers every construct that took a round each:
        # quoted separators, escaped separators, comments and newlines.
        from airlock import scope
        self.assertEqual(
            scope.shell_segments('find /mnt/c -name "foo; es bar"'),
            [["find", "/mnt/c", "-name", "foo; es bar"]])
        self.assertEqual(
            scope.shell_segments(r"find /mnt/c -name foo\;es"),
            [["find", "/mnt/c", "-name", "foo;es"]])
        self.assertEqual(
            scope.shell_segments("find /mnt/c -name x\nes -path C:/ y"),
            [["find", "/mnt/c", "-name", "x"], ["es", "-path", "C:/", "y"]])
        # A newline INSIDE quotes stays part of the argument.
        self.assertEqual(
            scope.shell_segments('find /mnt/c -name "a\nb"'),
            [["find", "/mnt/c", "-name", "a\nb"]])
        # An unterminated quote cannot be lexed, and says so.
        self.assertIsNone(scope.shell_segments('find /mnt/c -name "x'))

    def test_coverage_check_honours_the_availability_it_is_given(self):
        # command_covers_roots is the sole gate for would_deny, and it was
        # detecting the live database even when the caller had pinned one.
        # The verdict then changed with the host: an explicit db_kind of
        # "system" answered False on a host with a system database and True
        # on a host with only home.db.
        verdicts = set()
        for host_kind in ("system", "home", None):
            with mock.patch.object(policy, "plocate_db_kind",
                                   lambda *a, **k: host_kind):
                verdicts.add(policy.evaluate_search(
                    scope="disk_wide", search_intent="filename_search",
                    confidence=_ABOVE_BAR_CONFIDENCE,
                    command="plocate -i x; find /opt -name y",
                    root_has_graphify_graph=False, margin=_ABOVE_BAR_MARGIN,
                    roots=["/opt"], wsl=True,
                    db_kind="system", has_es=True)["would_deny"])
        self.assertEqual(verdicts, {False})

    def test_coverage_check_never_probes_when_told(self):
        probes = []
        real = policy.plocate_db_kind
        with mock.patch.object(policy, "plocate_db_kind",
                               lambda *a, **k: probes.append(1) or real()):
            policy.evaluate_search(
                scope="disk_wide", search_intent="filename_search",
                confidence=_ABOVE_BAR_CONFIDENCE,
                command="find /home/alice -name x",
                root_has_graphify_graph=False, margin=_ABOVE_BAR_MARGIN,
                roots=["/home/alice"], wsl=True,
                db_kind="home", has_es=True)
        self.assertEqual(probes, [])

    def test_a_prefixed_find_is_still_a_find_stage(self):
        # scope strips these prefixes before naming the program; reading
        # the prefix as the program made the stage look like something
        # other than find, so it counted as following symlinks.
        self.assertFalse(policy.command_follows_symlinks("sudo find link -name x"))
        self.assertFalse(policy.command_follows_symlinks(
            "nice -n 10 find link -name x"))
        self.assertFalse(policy.command_follows_symlinks("env find link -name x"))
        self.assertTrue(policy.command_follows_symlinks("sudo find -L link -name x"))

    def test_symlink_following_is_decided_per_search_stage(self):
        # One stage follows, the other does not. A command-wide answer
        # applies the wrong rule to one of them.
        self.assertFalse(policy.command_follows_symlinks(
            "find -L a -name x; find b -name y"))
        self.assertTrue(policy.command_follows_symlinks(
            "find -L a -name x; find -H b -name y"))
        # A non-find stage never makes the command stop following.
        self.assertTrue(policy.command_follows_symlinks(
            "rg -l foo a; find -L b -name y"))
        self.assertFalse(policy.command_follows_symlinks(
            "rg -l foo a; find b -name y"))
        # `-name find` is an argument, not a second find stage.
        self.assertTrue(policy.command_follows_symlinks(
            "find -L a -name find"))

    def test_the_home_database_does_not_claim_ground_it_lacks(self):
        with mock.patch.object(policy, "plocate_db_kind", lambda *a, **k: "home"):
            self.assertIs(
                policy.filename_search_suggestion(
                    windows=False, roots=["/opt", "/mnt/c"], wsl=True),
                policy.ES_WSL_WHOLE_FS_SUGGESTION)


class TestASymlinkOutOfHomeIsWindowsGround(unittest.TestCase):
    """Found by audit: ~/notes/vault on the author's machine is a symlink
    into /mnt/c. Classifying the unresolved path calls it Linux-side and
    steers to plocate, whose index never followed the symlink -- the same
    "file reported absent" failure this branch was opened to fix."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.link = os.path.join(self.tmp.name, "vault")
        self.target = os.path.join(self.tmp.name, "mnt_c_target")
        os.makedirs(self.target)
        os.symlink(self.target, self.link)

    def test_resolve_root_follows_the_symlink(self):
        self.assertEqual(policy.resolve_root(self.link), self.target)

    def test_resolve_root_survives_a_broken_link(self):
        broken = os.path.join(self.tmp.name, "gone")
        os.symlink(os.path.join(self.tmp.name, "nothing-here"), broken)
        self.assertTrue(policy.resolve_root(broken))

    def test_a_home_path_resolving_onto_the_windows_host_gets_everything(self):
        with mock.patch.object(policy, "resolve_root",
                               lambda r: "/mnt/c/Users/x" if r == "~/notes/vault" else r):
            self.assertIs(
                policy.filename_search_suggestion(
                    windows=False, roots=["~/notes/vault"], wsl=True),
                policy.ES_WSL_SUGGESTION)


class TestEsOnlyInCommandPosition(unittest.TestCase):
    """Codex P2 on PR #1: _ES_RE accepted `es` in any whitespace-delimited
    argument, so `find / -name es` read as already-indexed and suppressed the
    deny it should have produced."""

    def test_es_as_an_argument_is_not_a_command(self):
        self.assertFalse(policy.command_already_uses_indexed_search(
            "find / -name es", windows=False, wsl=True))

    def test_quoted_es_argument_is_not_a_command(self):
        self.assertFalse(policy.command_already_uses_indexed_search(
            'find /mnt/c -name "es"', windows=False, wsl=True))

    def test_es_at_the_start_is_a_command(self):
        self.assertTrue(policy.command_already_uses_indexed_search(
            'es -path "/mnt/c" -n 50 "x"', windows=False, wsl=True))

    def test_es_after_a_separator_is_a_command(self):
        for cmd in ('cd /tmp && es -n 5 "x"', 'ls | es "x"', 'true; es "x"'):
            with self.subTest(cmd=cmd):
                self.assertTrue(policy.command_already_uses_indexed_search(
                    cmd, windows=False, wsl=True))

    def test_es_exe_still_recognised(self):
        self.assertTrue(policy.command_already_uses_indexed_search(
            'es.exe -n 5 "x"', windows=False, wsl=True))

    def test_escaped_separator_is_not_a_command_boundary(self):
        # Codex P2, PR #1: bash reads `foo\;es` as one filename pattern.
        self.assertFalse(policy.command_already_uses_indexed_search(
            r"find /mnt/c -name foo\;es", windows=False, wsl=True))

    def test_escaped_separator_inside_double_quotes_is_not_a_boundary(self):
        self.assertFalse(policy.command_already_uses_indexed_search(
            r'find /mnt/c -name "foo\;es"', windows=False, wsl=True))

    def test_whole_fs_suggestion_keeps_the_linux_ground_neither_index_holds(self):
        for d in ("/etc", "/opt", "/usr"):
            self.assertIn(d, policy.ES_WSL_WHOLE_FS_SUGGESTION)

    def test_es_inside_a_word_is_not_a_command(self):
        self.assertFalse(policy.command_already_uses_indexed_search(
            "grep -r bytes .", windows=False, wsl=True))


class TestEsQuotingIsHonored(unittest.TestCase):
    """Codex P2, round 2 on PR #1: the raw _ES_RE regex ignored quoting, so a
    filename pattern that happens to contain a separator followed by `es`
    was misread as a second command invoking Everything."""

    def test_semicolon_and_es_inside_a_quoted_argument_is_not_a_command(self):
        self.assertFalse(policy.command_already_uses_indexed_search(
            'find /mnt/c -name "foo; es bar"', windows=False, wsl=True))

    def test_pipe_and_es_inside_a_quoted_argument_is_not_a_command(self):
        self.assertFalse(policy.command_already_uses_indexed_search(
            'find /mnt/c -name "foo| es bar"', windows=False, wsl=True))

    def test_ampersand_and_es_inside_a_quoted_argument_is_not_a_command(self):
        self.assertFalse(policy.command_already_uses_indexed_search(
            "find /mnt/c -name 'foo&& es bar'", windows=False, wsl=True))

    def test_a_real_es_command_after_a_quoted_lookalike_is_still_found(self):
        # The first stage's quoted argument LOOKS like a separator+es, but
        # the second stage is a genuine es invocation.
        self.assertTrue(policy.command_already_uses_indexed_search(
            'find /mnt/c -name "foo; es bar"; es -path "/mnt/c" -n 50 "x"',
            windows=False, wsl=True))

    def test_native_windows_also_honors_quoting(self):
        self.assertFalse(policy.command_already_uses_indexed_search(
            'find /mnt/c -name "foo; es bar"', windows=True))


class SonnetReviewRoundOne(unittest.TestCase):
    """Review findings on PR #1: the suggestion for a pure-Linux root no
    index covers, the symlink rule in the paid-call pre-filter, and the
    has_es parameter command_covers_roots accepted without reading."""

    def test_uncovered_linux_only_root_gets_no_suggestion(self):
        # /opt is outside home.db, and Everything cannot see the Linux side.
        # No index can answer it, so the crawl the user typed is the answer.
        for has_es in (True, False):
            with self.subTest(has_es=has_es):
                self.assertIsNone(policy.filename_search_suggestion(
                    windows=False, roots=["/opt"], wsl=True,
                    has_es=has_es, db_kind="home"))

    def test_uncovered_linux_only_root_never_names_everything(self):
        # The old branch returned the whole-filesystem advice here, whose
        # `es` line points at /mnt/<drive> roots this command never touched.
        suggestion = policy.filename_search_suggestion(
            windows=False, roots=["/opt"], wsl=True,
            has_es=True, db_kind="home") or ""
        self.assertNotIn("es -path", suggestion)

    def test_mixed_uncovered_root_still_gets_the_whole_fs_advice(self):
        suggestion = policy.filename_search_suggestion(
            windows=False, roots=["/opt", "/mnt/c/Users"], wsl=True,
            has_es=True, db_kind="home") or ""
        self.assertIn("es -path", suggestion)

    def test_filesystem_root_still_gets_the_whole_fs_advice(self):
        suggestion = policy.filename_search_suggestion(
            windows=False, roots=["/"], wsl=True,
            has_es=True, db_kind="home") or ""
        self.assertIn("es -path", suggestion)

    def test_deny_possible_follows_the_commands_own_symlink_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = os.path.join(tmp, "vault")
            os.symlink("/mnt/c/Users", link)
            plain = "find %s -name x" % link
            follows = "find -L %s -name x" % link
            # A plain find never enters the Windows tree, and
            # evaluate_search will not deny it, so the pre-filter must not
            # buy a Jev call for it.
            self.assertFalse(policy.deny_possible_bash(
                "single_dir", "find", False, roots=[link], wsl=True,
                command=plain))
            self.assertFalse(policy.evaluate_search(
                scope="single_dir", search_intent="filename", confidence=0.99,
                command=plain, root_has_graphify_graph=False,
                roots=[link], wsl=True)["would_deny"])
            # -L does enter it, and that IS deny-eligible.
            self.assertTrue(policy.deny_possible_bash(
                "single_dir", "find", False, roots=[link], wsl=True,
                command=follows))

    def test_deny_possible_resolves_when_no_command_is_given(self):
        # Without the command the pre-filter cannot know, and must stay on
        # the safe side: a needless call costs money, a missed one costs
        # the deny.
        with tempfile.TemporaryDirectory() as tmp:
            link = os.path.join(tmp, "vault")
            os.symlink("/mnt/c/Users", link)
            self.assertTrue(policy.deny_possible_bash(
                "single_dir", "find", False, roots=[link], wsl=True))

    def test_command_covers_roots_honours_has_es(self):
        command = 'es -path "C:/Users" x'
        self.assertTrue(policy.command_covers_roots(
            command, roots=["/mnt/c/Users"], wsl=True,
            db_kind="home", has_es=True))
        # Everything unusable: naming es covers nothing, because the client
        # runs and reports every file as absent.
        self.assertFalse(policy.command_covers_roots(
            command, roots=["/mnt/c/Users"], wsl=True,
            db_kind="home", has_es=False))


class SonnetReviewRoundTwo(unittest.TestCase):
    """Review findings on PR #1: a heredoc body read as a command, the
    truncated command reaching the local parsers, and the Windows
    docstring."""

    def test_heredoc_body_is_not_a_command(self):
        command = ("find / -name secret 2>/dev/null || cat <<EOF\n"
                   "es results here\n"
                   "EOF\n")
        self.assertFalse(policy.command_already_uses_indexed_search(
            command, windows=False, wsl=True))

    def test_quoted_heredoc_delimiter_body_is_not_a_command(self):
        command = "cat <<'EOF'\nplocate -i x\nEOF\nfind / -name y"
        self.assertFalse(policy.command_already_uses_indexed_search(
            command, windows=False, wsl=True))

    def test_dash_heredoc_with_tab_indented_terminator(self):
        command = "cat <<-EOF\n\tes x\n\tEOF\nfind / -name y"
        self.assertFalse(policy.command_already_uses_indexed_search(
            command, windows=False, wsl=True))

    def test_a_real_command_after_a_heredoc_is_still_found(self):
        command = "cat <<EOF\ndata\nEOF\nes -path 'C:/' y"
        self.assertTrue(policy.command_already_uses_indexed_search(
            command, windows=False, wsl=True))

    def test_here_string_opens_no_heredoc(self):
        from airlock import scope
        self.assertEqual(scope.shell_segments('grep a <<< "$x"\nfind / -name y'),
                         [["grep", "a", "<<<", "$x"], ["find", "/", "-name", "y"]])

    def test_heredoc_marker_inside_a_quoted_argument_opens_nothing(self):
        command = 'find /mnt/c -name "a <<EOF b"'
        self.assertFalse(policy.command_already_uses_indexed_search(
            command, windows=False, wsl=True))

    def test_an_es_stage_past_the_truncation_point_still_counts(self):
        # guards.py hands the POLICY parsers the full command. Reading the
        # truncated copy denied a command already using Everything, because
        # the roots came from the full text and the es stage did not.
        padding = "; ".join("echo %d" % i for i in range(260))
        command = ("find /mnt/c/Users/foo -name x; %s; es -path 'C:/' bar"
                   % padding)
        truncated = redact.redact_and_truncate_command(command)
        self.assertGreater(len(command), len(truncated))
        self.assertNotIn("es -path", truncated)
        roots = ["/mnt/c/Users/foo"]
        self.assertTrue(policy.command_covers_roots(
            command, roots=roots, wsl=True))
        verdict = policy.evaluate_search(
            scope="single_dir", search_intent="filename_search",
            confidence=0.99, margin=0.9, command=command,
            root_has_graphify_graph=False, roots=roots, wsl=True)
        self.assertFalse(verdict["would_deny"])

    def test_windows_without_everything_gets_no_suggestion(self):
        # The documented contract, which used to read "always".
        self.assertIsNone(policy.filename_search_suggestion(
            windows=True, has_es=False))
        self.assertIs(policy.filename_search_suggestion(
            windows=True, has_es=True), policy.ES_SUGGESTION)


class IndexedInvocationMustCoverTheRoot(unittest.TestCase):
    """Review finding on PR #1: naming `es` or `plocate` anywhere in the
    command counted as covering every root it searched, so an unrelated
    invocation silenced a real deny."""

    KW = {"scope": "single_dir", "search_intent": "filename_search",
          "confidence": 0.99, "margin": 0.9, "root_has_graphify_graph": False,
          "wsl": True}

    def deny(self, command, roots=("/mnt/c/Users",)):
        return policy.evaluate_search(command=command, roots=list(roots),
                                      **self.KW)["would_deny"]

    def test_a_bare_windows_host_crawl_denies(self):
        self.assertTrue(self.deny('find "/mnt/c/Users" -name x'))

    def test_es_help_does_not_count_as_a_search(self):
        for flag in ("-h", "--help", "-version"):
            with self.subTest(flag=flag):
                self.assertTrue(self.deny(
                    'find "/mnt/c/Users" -name x; es %s' % flag))

    def test_es_scoped_to_another_drive_does_not_cover(self):
        self.assertTrue(self.deny(
            'find "/mnt/c/Users" -name x; es -path "D:/data" y'))

    def test_es_scoped_to_the_root_covers(self):
        self.assertFalse(self.deny(
            'find "/mnt/c/Users" -name x; es -path "C:/Users" y'))

    def test_es_scoped_to_the_drive_covers_a_directory_under_it(self):
        self.assertFalse(self.deny(
            'find "/mnt/c/Users" -name x; es -path "C:/" y'))

    def test_unrestricted_es_covers_every_indexed_drive(self):
        self.assertFalse(self.deny('find "/mnt/c/Users" -name x; es y'))

    def test_a_later_es_can_supply_the_coverage(self):
        self.assertFalse(self.deny(
            'find "/mnt/c/Users" -name x; es -path "D:/d" y; '
            'es -path "C:/Users" z'))

    def test_plocate_help_does_not_count_as_a_search(self):
        self.assertTrue(policy.evaluate_search(
            command='find "$HOME" -name x; plocate -h',
            roots=["/home/alice"], scope="disk_wide",
            search_intent="filename_search", confidence=0.99, margin=0.9,
            root_has_graphify_graph=False, wsl=True)["would_deny"])

    def test_a_real_plocate_query_covers_its_ground(self):
        # The index holds the same ground whatever pattern is asked for,
        # so the pattern itself is not correlated.
        self.assertFalse(policy.evaluate_search(
            command='find "$HOME" -name x; plocate -i pattern',
            roots=["/home/alice"], scope="disk_wide",
            search_intent="filename_search", confidence=0.99, margin=0.9,
            root_has_graphify_graph=False, wsl=True)["would_deny"])


class SonnetReviewRoundFive(unittest.TestCase):
    """Review findings on PR #1: an unquoted Windows path eaten by the
    POSIX lexer, and a heredoc delimiter the stripper would not recognise."""

    def covers(self, command, root="/mnt/c/Users/bob"):
        return policy.command_covers_roots(
            command, roots=[root], wsl=True, db_kind="home", has_es=True)

    def test_unquoted_backslash_path_still_covers_its_root(self):
        self.assertTrue(self.covers(
            r'find /mnt/c/Users/bob -iname "*.txt"; '
            r'es -path C:\Users\bob -n 50 x'))

    def test_quoted_backslash_path_still_covers_its_root(self):
        self.assertTrue(self.covers(
            'find /mnt/c/Users/bob -iname "*.txt"; '
            'es -path "C:\\Users\\bob" -n 50 x'))

    def test_forward_slash_path_still_covers_its_root(self):
        self.assertTrue(self.covers(
            'find /mnt/c/Users/bob -iname "*.txt"; '
            'es -path C:/Users/bob -n 50 x'))

    def test_a_backslash_path_on_another_drive_does_not_cover(self):
        self.assertFalse(self.covers(
            r'find /mnt/c/Users/bob -iname "*.txt"; es -path D:\data -n 50 x'))

    def test_preserving_backslashes_does_not_change_command_structure(self):
        # Round 11's escaped separator must still be one token, so the
        # escape-free pass is used ONLY to read es -path values.
        self.assertEqual(
            scope_mod.shell_segments(r"find /mnt/c -name foo\;es"),
            [["find", "/mnt/c", "-name", "foo;es"]])

    def test_a_delimiter_that_is_not_an_identifier_is_recognised(self):
        # bash has no strip-tabs `<<~`; it reads `~EOF` as the literal
        # delimiter, so `EOF` never ends the body and it runs to the end.
        command = "cat <<~EOF\nfind / -name secret\nEOF\n"
        self.assertEqual(scope_mod.shell_segments(command),
                         [["cat", "<<", "~EOF"]])

    def test_a_body_under_such_a_delimiter_is_not_an_indexed_search(self):
        self.assertFalse(policy.command_already_uses_indexed_search(
            "cat <<~EOF\nes results\nEOF\n", windows=False, wsl=True))


if __name__ == "__main__":
    unittest.main()
