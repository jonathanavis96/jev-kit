"""Windows search shapes: scope classification, the rules, the file-search steer.

All of it injected (`windows=True`), so it runs on Linux. The filesystem
probes scope.py makes -- is this root inside a git repo, does it hold two of
them -- are patched out wherever the answer would otherwise depend on the
machine the tests happen to run on: a Windows path does not exist on Linux,
and letting `Path("D:\\x").parents` fall back to the current directory would
make the result depend on where the suite was invoked from.
"""
import os
import unittest
from unittest import mock

from airlock import policy, rules, scope
from tests import posix_only

HOME = "C:\\Users\\alice"
ENV = {"USERPROFILE": HOME, "APPDATA": HOME + "\\AppData\\Roaming",
       "LOCALAPPDATA": HOME + "\\AppData\\Local"}


def classify(command, cwd="C:\\Users\\alice\\code\\proj", repo=True, many=False):
    """Classify a Windows command with the filesystem answers pinned."""
    with mock.patch.dict(os.environ, ENV, clear=False), \
         mock.patch.object(scope, "_is_within_git_repo", return_value=repo), \
         mock.patch.object(scope, "_contains_multiple_repos", return_value=many):
        return scope.classify_command(command, cwd, windows=True)


class TestCmdShapes(unittest.TestCase):
    def test_dir_s_at_a_drive_root_is_disk_wide(self):
        result = classify("dir /s C:\\ *.xlsm")
        self.assertEqual(result["scope"], "disk_wide")
        self.assertEqual(result["program"], "dir")
        self.assertEqual(result["roots"], ["C:\\"])

    def test_dir_s_in_a_repo_is_not_disk_wide(self):
        result = classify("dir /s", cwd="C:\\Users\\alice\\code\\proj")
        self.assertEqual(result["scope"], "single_repo")

    def test_a_trailing_file_spec_is_a_pattern_not_a_root(self):
        """`dir /s C:\\ *.xlsm` has one root and one pattern, not two roots."""
        self.assertEqual(classify("dir /s C:\\ *.xlsm")["roots"], ["C:\\"])

    def test_dir_without_slash_s_is_not_a_search_at_all(self):
        self.assertEqual(classify("dir")["program"], None)
        self.assertEqual(classify("dir C:\\Users\\alice")["program"], None)

    def test_where_slash_r_takes_the_directory_after_it(self):
        result = classify("where /r C:\\Users\\alice report.docx")
        self.assertEqual(result["program"], "where")
        self.assertEqual(result["roots"], [HOME])
        self.assertEqual(result["scope"], "disk_wide")

    def test_bare_where_searches_PATH_and_is_not_a_crawl(self):
        self.assertEqual(classify("where python")["program"], None)

    def test_findstr_s_roots_at_the_file_spec_directory(self):
        result = classify("findstr /s /i \"TODO\" C:\\code\\proj\\*.py")
        self.assertEqual(result["program"], "findstr")
        self.assertEqual(result["roots"], ["C:\\code\\proj"])

    def test_findstr_without_s_is_not_recursive(self):
        self.assertEqual(classify("findstr TODO file.txt")["program"], None)


class TestPowerShellShapes(unittest.TestCase):
    def test_get_childitem_recurse_at_a_drive_root(self):
        result = classify("Get-ChildItem -Path C:\\ -Recurse -Filter *.xlsm")
        self.assertEqual(result["scope"], "disk_wide")
        self.assertEqual(result["roots"], ["C:\\"])

    def test_a_filter_value_is_never_mistaken_for_a_root(self):
        result = classify("Get-ChildItem -Recurse -Filter *.xlsm D:\\shared")
        self.assertEqual(result["roots"], ["D:\\shared"])

    def test_gci_alias_and_case_insensitivity(self):
        for spelling in ("gci -Recurse C:\\", "GCI -RECURSE C:\\",
                         "get-childitem -recurse C:\\"):
            self.assertEqual(classify(spelling)["scope"], "disk_wide", spelling)

    def test_without_recurse_it_is_one_directory_not_a_search(self):
        self.assertEqual(classify("Get-ChildItem C:\\Users\\alice")["program"], None)

    def test_the_user_profile_is_disk_wide(self):
        result = classify("Get-ChildItem -Recurse", cwd=HOME)
        self.assertEqual(result["scope"], "disk_wide")

    def test_select_string_with_a_path(self):
        result = classify("Select-String -Path C:\\code\\proj\\*.py -Pattern TODO")
        self.assertEqual(result["program"], "select-string")
        self.assertEqual(result["roots"], ["C:\\code\\proj"])

    def test_select_string_in_a_pipeline_reads_stdin(self):
        result = classify("Get-Content x.txt | Select-String TODO")
        self.assertEqual(result["scope"], "stdin")


class TestShellWrappers(unittest.TestCase):
    def test_cmd_c_is_unwrapped(self):
        result = classify('cmd.exe /c "dir /s C:\\"')
        self.assertEqual(result["scope"], "disk_wide")
        self.assertEqual(result["program"], "dir")

    def test_powershell_command_is_unwrapped(self):
        result = classify('powershell.exe -NoProfile -Command "Get-ChildItem -Recurse C:\\"')
        self.assertEqual(result["scope"], "disk_wide")
        self.assertEqual(result["program"], "get-childitem")

    def test_execution_policy_value_is_skipped(self):
        result = classify(
            'pwsh -NoProfile -ExecutionPolicy Bypass -Command "gci -Recurse C:\\"')
        self.assertEqual(result["scope"], "disk_wide")

    def test_encoded_command_is_not_decoded_and_classifies_as_nothing(self):
        result = classify('powershell -EncodedCommand ZwBjAGkA')
        self.assertEqual(result["program"], None)

    def test_a_wrapper_around_something_harmless_stays_harmless(self):
        self.assertEqual(classify('cmd /c "echo hello"')["program"], None)


class TestPathSpellings(unittest.TestCase):
    def test_git_bash_msys_paths_are_understood(self):
        result = classify('find /c/Users/alice -name "*.xlsm"')
        self.assertEqual(result["scope"], "disk_wide")
        self.assertEqual(result["roots"], [HOME])

    def test_git_bash_ls_r_keeps_its_msys_root(self):
        """`/c/...` was read as a cmd.exe /flag, so the root was dropped and
        the search was measured against the cwd."""
        for c in ("ls -R /c/Users/alice", "ls -R /c", "Get-ChildItem -Recurse /c/"):
            self.assertEqual(classify(c)["scope"], "disk_wide", c)
        self.assertEqual(classify("ls -R /c/Users/alice")["roots"], [HOME])
        self.assertEqual(classify("dir /s C:\\")["roots"], ["C:\\"])

    def test_dir_with_a_dash_recurse_flag_keeps_its_msys_root(self):
        """`dir -R /c/` is Get-ChildItem or coreutils, not cmd.exe: the
        /-token is its root, not a switch."""
        for c in ("dir -R /c/", "dir -r /", "dir -Recurse /c/Users/alice"):
            self.assertEqual(classify(c)["scope"], "disk_wide", c)
        self.assertEqual(classify("dir -Recurse /c/Users")["roots"], ["C:\\Users"])
        self.assertEqual(classify("dir -Recurse /c/Users/alice")["roots"], [HOME])

    def test_a_continued_line_keeps_its_root(self):
        """Continuations are not joined on Windows, so a newline must not
        split the command and drop the root on the continued line."""
        for c in ("Get-ChildItem -Recurse `\n  -Path C:\\ -Filter *.log",
                  "grep -r \\\n  password /c/"):
            self.assertEqual(classify(c)["scope"], "disk_wide", repr(c))

    def test_a_backslash_is_a_separator_not_an_escape(self):
        """POSIX shlex eats the backslash and `dir /s C:\\` becomes `C:`, so
        every drive root would be misread as a relative path."""
        self.assertEqual(classify("dir /s C:\\")["roots"], ["C:\\"])

    def test_comparison_is_case_insensitive(self):
        result = classify("Get-ChildItem -Recurse c:\\users\\ALICE")
        self.assertEqual(result["scope"], "disk_wide")

    def test_a_unc_share_root_is_disk_wide(self):
        result = classify("Get-ChildItem -Recurse \\\\fileserver\\projects")
        self.assertEqual(result["scope"], "disk_wide")

    def test_a_relative_root_resolves_against_the_windows_cwd(self):
        result = classify("Get-ChildItem -Recurse src", cwd="C:\\code\\proj")
        self.assertEqual(result["roots"], ["C:\\code\\proj\\src"])

    def test_percent_userprofile_expands(self):
        result = classify("Get-ChildItem -Recurse %USERPROFILE%")
        self.assertEqual(result["scope"], "disk_wide")


class TestEverythingIsTheIndexedTool(unittest.TestCase):
    def test_es_is_recognised_as_the_index(self):
        result = classify('es -path "C:\\code" report')
        self.assertEqual(result["program"], "es")
        self.assertEqual(result["scope"], "disk_wide")

    def test_es_exe_spelling_too(self):
        self.assertEqual(classify('es.exe report')["program"], "es")

    def test_a_walker_beats_es_at_the_same_scope(self):
        """Same reason a `find` beats a `plocate` in a pipeline: the walker is
        the thing costing the disk, so it must not be masked."""
        result = classify('es report | Get-ChildItem -Recurse C:\\')
        self.assertEqual(result["program"], "get-childitem")

    def test_a_command_already_using_es_is_never_told_to_use_es(self):
        self.assertTrue(policy.command_already_uses_indexed_search(
            'es -path "C:\\code" report', windows=True))
        self.assertFalse(policy.command_already_uses_indexed_search(
            'dir /s C:\\', windows=True))

    def test_es_is_not_matched_inside_an_unrelated_word(self):
        for command in ("notes.txt", "dir /s C:\\files", "grep tests ."):
            self.assertFalse(
                policy.command_already_uses_indexed_search(command, windows=True),
                command)

    def test_es_is_not_recognised_on_linux(self):
        """`es` is not a plain-Linux program; matching it there would be a
        false positive on anything that happened to contain the word.
        wsl=False pins this to non-WSL Linux explicitly -- under WSL `es` is
        a real program on PATH (voidtools Everything's client), which is
        covered separately in tests/test_wsl_filesearch.py."""
        self.assertFalse(policy.command_already_uses_indexed_search(
            "es report", windows=False, wsl=False))


class TestTheSuggestion(unittest.TestCase):
    def test_linux_gets_plocate(self):
        suggestion = policy.filename_search_suggestion(windows=False)
        self.assertIn("plocate", suggestion)
        self.assertNotIn("es.exe", suggestion)

    def test_windows_gets_es_exe(self):
        suggestion = policy.filename_search_suggestion(windows=True)
        self.assertIn("es.exe", suggestion)
        self.assertNotIn("plocate", suggestion)

    def test_the_windows_suggestion_names_the_flags_it_promises(self):
        suggestion = policy.filename_search_suggestion(windows=True)
        self.assertIn("-path", suggestion)   # path-scoped
        self.assertIn("-r", suggestion)      # regex
        self.assertIn("-i", suggestion)      # case
        self.assertIn("instant", suggestion)

    def test_the_case_flag_is_described_the_right_way_round(self):
        """es -i means MATCH CASE. Describing it as grep's -i would send a
        session the opposite way, which is the one mistake worth a test."""
        suggestion = policy.filename_search_suggestion(windows=True)
        self.assertIn("case-sensitive", suggestion)
        self.assertNotIn("case-insensitive match", suggestion)

    def test_evaluate_search_denies_with_the_right_advice_per_platform(self):
        kwargs = {"scope": "disk_wide", "search_intent": "filename_search",
                  "confidence": 0.99, "root_has_graphify_graph": False, "margin": 0.9}
        linux = policy.evaluate_search(command="find / -name x", windows=False, **kwargs)
        windows = policy.evaluate_search(command="dir /s C:\\", windows=True, **kwargs)
        self.assertTrue(linux["would_deny"])
        self.assertIn("plocate", linux["suggestion"])
        self.assertTrue(windows["would_deny"])
        self.assertIn("es.exe", windows["suggestion"])

    def test_a_command_already_on_the_index_is_allowed_on_both(self):
        kwargs = {"scope": "disk_wide", "search_intent": "filename_search",
                  "confidence": 0.99, "root_has_graphify_graph": False, "margin": 0.9}
        self.assertFalse(policy.evaluate_search(
            command="plocate -i x", windows=False, **kwargs)["would_deny"])
        self.assertFalse(policy.evaluate_search(
            command='es -path "C:\\code" x', windows=True, **kwargs)["would_deny"])


class TestPrefilter(unittest.TestCase):
    def test_windows_search_shapes_reach_the_tool_choice_guard(self):
        for command in ("dir /s C:\\", "Get-ChildItem -Recurse", "where /r C:\\ x",
                        "findstr /s TODO *.py", "es report",
                        'cmd /c "dir /s C:\\"'):
            self.assertTrue(policy.bash_is_search_like(command, windows=True), command)

    def test_they_are_invisible_on_linux(self):
        """`dir`, `where` and `findstr` mean other things (or nothing) on
        Linux, so recognising them there would be a behaviour change."""
        for command in ("dir /s C:\\", "Get-ChildItem -Recurse", "where /r C:\\ x",
                        "findstr /s TODO *.py"):
            self.assertFalse(policy.bash_is_search_like(command, windows=False), command)

    def test_ordinary_posix_searches_still_match_on_windows(self):
        """Git Bash is the documented way to get the Bash tool on Windows, so
        a Windows session still issues plain `find` and `grep`."""
        for command in ("find /c/Users/alice -name x", "grep -rn TODO ."):
            self.assertTrue(policy.bash_is_search_like(command, windows=True), command)

    def test_an_ordinary_command_matches_nothing_on_either(self):
        for command in ("echo hello", "git status", "npm test"):
            self.assertFalse(policy.bash_is_search_like(command, windows=True), command)
            self.assertFalse(policy.bash_is_search_like(command, windows=False), command)


class TestPowerShellTool(unittest.TestCase):
    """Claude Code's hooks reference: "Match `Bash|PowerShell` in hooks that
    inspect shell commands... On Windows without Git Bash, the tool is enabled
    automatically and Claude Code doesn't register the Bash tool at all. A
    hook that matches only `Bash` never fires there."""

    def test_the_command_is_read_off_a_powershell_payload(self):
        ctx = rules.build_ctx(
            {"tool_name": "PowerShell",
             "tool_input": {"command": "Remove-Item -Recurse -Force C:\\x"}},
            "PowerShell")
        self.assertEqual(ctx["command"], "Remove-Item -Recurse -Force C:\\x")
        self.assertTrue(ctx["segments"])

    def test_every_shell_rule_covers_both_tools(self):
        for rule in rules.RULES:
            if "Bash" in rule.tools:
                self.assertIn("PowerShell", rule.tools, rule.id)

    def test_a_powershell_call_reaches_the_rules(self):
        """R1, not R6: R6 is `off` by default on Windows, and an attempt to
        print the key file is the deny that actually matters there."""
        ctx = rules.build_ctx(
            {"tool_name": "PowerShell",
             "tool_input": {"command": "Get-Content $env:APPDATA\\airlock\\env"}},
            "PowerShell")
        matched = [r.id for r, _m in rules.prefilter_matches(ctx, overrides={})]
        self.assertIn("R1-secret-exposure", matched)

    def test_a_non_shell_tool_still_carries_no_command(self):
        ctx = rules.build_ctx(
            {"tool_name": "Read", "tool_input": {"file_path": "C:\\x\\y.txt"}}, "Read")
        self.assertEqual(ctx["command"], "")


@posix_only("the POSIX branch of scope._expand goes through os.path.normpath,\n"
            "            which turns / into \\ on a Windows host: the result would be\n"
            "            about the host's os.path, not about airlock")
class TestLinuxIsUnchanged(unittest.TestCase):
    """The Windows work must not be visible on Linux at all. These are the
    same assertions tests/test_scope.py makes, re-stated here as a guard
    against a Windows change leaking into the default path."""

    def test_default_platform_classification_is_posix(self):
        with mock.patch.dict(os.environ, {"HOME": "/home/alice"}, clear=False):
            result = scope.classify_command("find / -name '*.xlsm'", "/home/alice")
        self.assertEqual(result["scope"], "disk_wide")
        self.assertEqual(result["program"], "find")
        self.assertEqual(result["roots"], ["/"])

    def test_dir_on_linux_is_not_a_windows_dir(self):
        self.assertIsNone(scope.classify_command("dir /s", "/home/alice",
                                                 windows=False)["program"])

    def test_backslash_still_escapes_on_linux(self):
        result = scope.classify_command("grep -rn foo /home/alice/a\\ b",
                                        "/home/alice", windows=False)
        self.assertEqual(result["roots"], ["/home/alice/a b"])


class TestDotDotRoots(unittest.TestCase):
    def test_dot_dot_is_resolved_before_comparing_roots(self):
        from airlock import winpath
        self.assertEqual(winpath.canonical(r"C:\Users\me\.."), "C:\\Users")
        self.assertEqual(winpath.canonical(r"C:\Users\.."), "C:\\")
        self.assertEqual(winpath.canonical("c:/x/../.."), "C:\\")
        self.assertEqual(winpath.canonical(r"..\x"), "..\\x")


if __name__ == "__main__":
    unittest.main()
