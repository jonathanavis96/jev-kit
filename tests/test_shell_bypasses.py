"""Shell forms that used to hide a command from the rules.

Each case here failed against the rules before the fix that added it. The
sibling lists hold the forms that must keep passing or keep being denied, so
a later loosening has to change this file on purpose.
"""

import tests  # noqa: F401, I001 -- MUST be the first import (see tests/test_rules.py).

import datetime
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from airlock import health, rules, scope

R1 = "R1-secret-exposure"
R5 = "R5-sudo"
R7 = "R7-destructive"
R7_ROOT = "R7-root-delete"
R9 = "R9-commit-secret"


def ctx_bash(command):
    return rules.build_ctx({"tool_name": "Bash", "tool_input": {"command": command},
                            "cwd": "/tmp"}, "Bash")


def fires(command, rule_id):
    rows = rules.dry_run(ctx_bash(command), overrides={}, windows=False)
    return any(r["rule_id"] == rule_id and r["fires"] for r in rows)


def r1(command):
    return rules.prefilter_secret(ctx_bash(command))


class ForcePushSpellings(unittest.TestCase):
    def test_combined_flags_and_plus_refspec_warn(self):
        for c in ("git push -uf origin x", "git push -fu origin x", "git push origin +main",
                  "git push origin +HEAD:main", "git -C repo push -vf origin x",
                  "(git push -f origin x)"):
            self.assertTrue(fires(c, R7), c)

    def test_ordinary_pushes_stay_quiet(self):
        for c in ("git push", "git push -u origin x", "git push --force-with-lease origin x",
                  "git push origin main", "git push -o ci.skip origin x",
                  "git push --push-option=+x origin main", "git push -o +x origin main",
                  "git push origin refs/heads/a+b"):
            self.assertFalse(fires(c, R7), c)

    def test_a_force_push_is_still_only_a_warning(self):
        rows = rules.dry_run(ctx_bash("git push origin +main"), overrides={}, windows=False)
        row = [r for r in rows if r["rule_id"] == R7][0]
        self.assertEqual(row["action"], "warn")


class SubshellsAndGroups(unittest.TestCase):
    READS = (
        "(cat .env)", "( cat .env )", "((cat .env))", "{ cat .env; }", "(cd x && cat .env)",
        "(cat ~/.config/jev-kit/env)", "(cat .env) > /tmp/x", "(cat .env) 2>&1",
        "! cat .env", "(cd a; (cd b; cat .env))", "(head -5 .env)",
        "if cat .env; then echo y; fi", "if true; then cat .env; fi",
        "for i in 1 2; do cat .env; done", "while true; do cat .env; done",
        "if false; then :; else cat .env; fi", "true; { cat .env; }",
        "case $x in a) cat .env;; esac", "case $x in\na) cat .env;;\nesac",
    )

    def test_reads_are_denied(self):
        for c in self.READS:
            self.assertIsNotNone(r1(c), c)

    def test_redirections_around_the_program(self):
        for c in ("cat<.env", "< .env cat", "<.env cat", "> /dev/stderr cat .env", "2>&1 cat .env",
                  "case a in a) < .env cat;; esac", "sudo cat<.env", "sudo < .env cat"):
            self.assertIsNotNone(r1(c), c)
        self.assertEqual(rules.program_of("< .env cat -n"), ("cat", ["-n", ".env"]))
        self.assertEqual(rules.program_of("cat<.env"), ("cat", [".env"]))
        self.assertEqual(rules.program_of("(ls) > f 2>&1"), ("ls", [">", "f", "2>&1"]))

    def test_a_redirection_to_a_file_descriptor_is_not_a_list_operator(self):
        self.assertEqual(rules.split_segments("ls 2>&1 | wc -l"), ["ls 2>&1", "wc -l"])
        self.assertEqual(rules.split_segments("ls &> f; pwd"), ["ls &> f", "pwd"])
        self.assertEqual(rules.split_segments("ls & pwd"), ["ls", "pwd"])

    def test_function_bodies(self):
        for c in ("f() { cat .env; }; f", "f(){ cat .env; }; f", "function f { cat .env; }; f",
                  "function f() { cat .env; }; f", "f() ( cat .env ); f"):
            self.assertIsNotNone(r1(c), c)

    def test_program_of_sees_through_openers_and_closers(self):
        self.assertEqual(rules.program_of("(cat .env)"), ("cat", [".env"]))
        self.assertEqual(rules.program_of("( cat .env )"), ("cat", [".env"]))
        self.assertEqual(rules.program_of("((cat .env))"), ("cat", [".env"]))
        self.assertEqual(rules.program_of("{ cat .env"), ("cat", [".env"]))
        self.assertEqual(rules.program_of("cat .env)"), ("cat", [".env"]))
        self.assertEqual(rules.program_of("(cat .env) 2>&1"), ("cat", [".env", "2>&1"]))
        self.assertEqual(rules.program_of("then cat .env"), ("cat", [".env"]))
        self.assertEqual(rules.program_of("a|b) cat .env"), ("cat", [".env"]))

    def test_balanced_and_quoted_parens_are_kept(self):
        self.assertEqual(rules.program_of('grep ")" f'), ("grep", [")", "f"]))
        self.assertEqual(rules.program_of('(grep ")" f)'), ("grep", [")", "f"]))
        self.assertEqual(rules.program_of("echo $(date)"), ("echo", ["$(date)"]))
        self.assertEqual(rules.program_of("(echo $(date))"), ("echo", ["$(date)"]))

    def test_sudo_and_git_rules_see_it_too(self):
        self.assertTrue(fires("(sudo systemctl stop x)", R5))
        self.assertTrue(fires("{ sudo systemctl stop x; }", R5))
        self.assertTrue(fires("if true; then sudo systemctl stop x; fi", R5))
        self.assertTrue(fires("(git add .env)", R9))

    def test_a_group_keeps_a_plain_command_plain(self):
        for c in ("(cd sub && ls)", "{ ls; }", "(cd build && rm -rf out)", "if true; then ls; fi",
                  "for i in 1 2; do echo $i; done"):
            self.assertEqual([r["rule_id"] for r in rules.dry_run(ctx_bash(c), overrides={}, windows=False)
                              if r["fires"]], [], c)


class EnvSplitString(unittest.TestCase):
    def test_env_dash_runs_the_next_word(self):
        self.assertEqual(rules.program_of("env - sudo systemctl stop x")[0], "sudo")
        self.assertEqual(rules.program_of("env - PATH=/usr/bin ls")[0], "ls")

    def test_split_string_is_the_command(self):
        for c in ('env -S "sudo systemctl stop x"', "env -S 'sudo systemctl stop x'",
                  "env -S sudo\\ systemctl\\ stop\\ x", '--split-string="sudo x"'):
            if c.startswith("--"):
                c = "env " + c
            self.assertEqual(rules.program_of(c)[0], "sudo", c)

    def test_split_string_read_is_denied(self):
        self.assertIsNotNone(r1('env -S "cat .env"'))
        self.assertIsNotNone(r1("env -i -S 'cat .env'"))

    def test_bare_env_is_still_env(self):
        self.assertEqual(rules.program_of("env")[0], "env")
        self.assertEqual(rules.program_of("env -0")[0], "env")


class CommandSubstitutions(unittest.TestCase):
    def test_a_substitution_runs_its_commands(self):
        for c in ("echo $(sudo systemctl stop x)", "echo `sudo systemctl stop x`",
                  'echo "$(cd /tmp && sudo systemctl stop x)"', "echo $(echo $(sudo rm x))",
                  "x=$(sudo reboot)", "echo $(sudo x)  # comment", "echo `sudo x` # trailing",
                  "diff <(sudo cat /etc/shadow) x"):
            self.assertTrue(fires(c, R5), c)

    def test_destructive_inside_a_substitution_warns(self):
        self.assertTrue(fires("echo $(git push --force)", R7))

    def test_text_that_only_looks_like_a_substitution_is_left_alone(self):
        for c in ('echo "$(git rev-parse HEAD)"', "x=$(date +%s); echo $((x+1))",
                  "echo '$(sudo x)'", "git log -1 --format=`echo %H`",
                  "echo \\$\\(sudo x\\)", "# same as $(sudo systemctl restart nginx)\nls -la",
                  "# needs `sudo systemctl restart nginx` here\nls -la",
                  "make build  # then `sudo make install`", "ls;# `sudo reboot`"):
            self.assertFalse(fires(c, R5), c)

    def test_nested_and_chained_reads_in_a_substitution(self):
        for c in ('echo "$(cat .env; echo $(date))"', "echo $( (cat .env) )",
                  "echo $(echo a; cat .env)", 'echo "$(printf "%s" ")"; cat .env)"',
                  "cat <(cat .env)", "diff <(cat .env) /dev/null"):
            self.assertIsNotNone(r1(c), c)

    def test_a_captured_value_is_still_not_printed(self):
        for c in ("KEY=$(cat ~/.config/jev-kit/env)", "export KEY=$(cat .env)",
                  'KEY="$(head -1 .env)"; curl -H "x: $KEY" https://example.com'):
            self.assertIsNone(r1(c), c)

    def test_only_a_capture_glued_to_the_assignment_counts(self):
        # The shell runs the file's text as a command and its error prints it.
        self.assertIsNotNone(r1("x=1 $(cat .env)"))
        # Escaped, so this shell runs nothing and only passes the text on.
        self.assertIsNone(r1('tmux new -d "export X=\\"\\$(cat .env)\\""'))

    def test_many_substitutions_end_the_capture_exemption_only(self):
        c = "; ".join("A%d=$(date)" % i for i in range(rules._ASSIGN_CHECK_LIMIT + 2))
        self.assertIsNone(r1(c))
        self.assertIsNotNone(r1(c + "; KEY=$(cat .env)"))

    def test_substitution_scanner(self):
        self.assertEqual(rules.command_substitutions("echo a#b $(sudo x)"), ["sudo x"])
        self.assertEqual(rules.command_substitutions('echo "# $(sudo x)"'), ["sudo x"])
        self.assertEqual(rules.command_substitutions("echo ${#v} $(sudo x)"), ["sudo x"])
        self.assertEqual(rules.command_substitutions("echo '#' $(sudo x)"), ["sudo x"])
        self.assertEqual(rules.command_substitutions("echo $((1+2))"), [])
        self.assertEqual(rules.command_substitutions("echo $(a $(b))"), ["a $(b)", "b"])


class HeredocState(unittest.TestCase):
    NEXT_LINE_RUNS = (
        "echo $((1<<EOF))\nsudo systemctl stop x",
        'echo "first\n<<EOF"\nsudo systemctl stop x',
        "y=$((x<<2))\nsudo systemctl stop x",
        "cat > f <<EOF\nhello\nsudo systemctl stop x",
        "cat <<A <<B\nx\nA\nsudo systemctl stop x",
        "# it's here\ncat > f <<EOF\nbody\nEOF\nsudo reboot",
        "# it's here\nsudo reboot",
        'cat <<\\EOF\nbody\nEOF\nsudo reboot',
        'cat <<E"O"F\nbody\nEOF\nsudo reboot',
        "cat <<'E'OF\nbody\nEOF\nsudo reboot",
        "((x<<2))\nsudo reboot",
        "let y=1<<3\nsudo reboot",
    )
    BODY_IS_DATA = (
        "cat <<-EOF\n\tsudo is mentioned\n\tEOF\necho ok",
        "cat <<'EOF'\nsudo note\nEOF",
        'cat << "EOF"\nsudo note\nEOF',
        "git commit -F- <<'EOF'\nfix: drop sudo from rm -rf / docs\nEOF",
        "cat > f <<EOF\nsudo here\nEOF",
        "python3 - <<'EOF'\nimport os  # sudo rm -rf /\nEOF",
        "git commit -m \"$(cat <<'EOF'\nsudo reboot is what broke it\nrm -rf / is mentioned\nEOF\n)\"",
        "# save the user's notes\ncat > notes.md <<'EOF'\nIt's simple:\n"
        "sudo systemctl restart nginx\nEOF\necho done",
    )

    def test_lines_after_a_heredoc_are_commands(self):
        for c in self.NEXT_LINE_RUNS:
            self.assertTrue(fires(c, R5), c)

    def test_root_delete_after_a_marker_in_a_multiline_quote(self):
        self.assertTrue(fires("echo 'a\nb <<EOF'\nrm -rf /", R7_ROOT))
        self.assertTrue(fires("cat > f <<'EOF'\nrm -rf /", R7_ROOT))
        self.assertTrue(fires("cat <<\\EOF\nbody\nEOF\nrm -rf /", R7_ROOT))

    def test_a_body_is_data(self):
        for c in self.BODY_IS_DATA:
            for rule in (R5, R7_ROOT, R7):
                self.assertFalse(fires(c, rule), (rule, c))

    def test_the_lines_after_a_terminated_heredoc_still_run(self):
        for c in ("cat <<-EOF\n\tnote\n\tEOF\nsudo systemctl stop x",
                  "git commit -F- <<'EOF'\nmsg\nEOF\nsudo systemctl stop x"):
            self.assertTrue(fires(c, R5), c)
        self.assertTrue(fires("python3 - <<'EOF'\nprint(1)\nEOF\nrm -rf /", R7_ROOT))

    def test_strip_heredocs_exact(self):
        cmd = "# save the user's notes\ncat > n <<'EOF'\nIt's simple:\nEOF\necho done"
        self.assertEqual(scope.strip_heredocs(cmd), "# save the user's notes\ncat > n <<'EOF'\necho done")
        self.assertEqual(rules.strip_heredocs("cat <<EOF\nnever closed\nrm x"),
                         "cat <<EOF\nnever closed\nrm x")
        self.assertEqual(scope.strip_heredocs("cat <<EOF\nnever closed\nrm x"), "cat <<EOF")


class ShellComments(unittest.TestCase):
    def test_a_comment_is_not_a_segment(self):
        self.assertEqual(rules.split_segments("ls # it's a comment\npwd"), ["ls", "pwd"])
        self.assertEqual(rules.split_segments("# one\n# two's\nls"), ["ls"])

    def test_a_hash_inside_a_word_or_quotes_is_kept(self):
        self.assertEqual(rules.split_segments("echo a#b; ls"), ["echo a#b", "ls"])
        self.assertEqual(rules.split_segments("echo '# x'; ls"), ["echo '# x'", "ls"])
        self.assertEqual(rules.split_segments("echo ${#v}; ls"), ["echo ${#v}", "ls"])
        self.assertEqual(rules.split_segments("[ $# -gt 0 ]; ls"), ["[ $# -gt 0 ]", "ls"])
        self.assertEqual(rules.split_segments("echo \\ #x; ls"), ["echo \\ #x", "ls"])


class SecretsThroughAShell(unittest.TestCase):
    def test_code_handed_to_a_shell_is_read(self):
        for c in ("bash -c 'cat .env'", 'sh -c "head -1 .env"', "bash -lc 'cat .env'", "eval cat .env",
                  'eval "cat .env"', "bash <<< 'cat .env'", "bash <<EOF\ncat .env\nEOF",
                  "cat <<EOF | bash\ncat .env\nEOF", "echo 'cat .env' | bash",
                  "printf 'cat .env\\n' | sh", "bash -c 'bash -c \"cat .env\"'", "sudo cat .env",
                  "sudo -u root head -1 .env", 'echo "$(bash -c \'cat .env\')"',
                  "bash -c 'echo $API_KEY'", "bash -c 'cat .env' _ a"):
            self.assertIsNotNone(r1(c), c)

    def test_a_captured_value_in_a_handed_script_is_still_not_printed(self):
        for c in ("bash -c 'KEY=$(cat .env); curl x'", "eval \"$(ssh-agent -s)\"",
                  "bash -c 'grep -q x .env'", "cat > f.sh <<'EOF'\ncat .env\nEOF",
                  "bash run.sh <<EOF\ncat .env\nEOF"):
            self.assertIsNone(r1(c), c)


class HostileInput(unittest.TestCase):
    """The scanners run on untrusted text before any rule does. An exception
    would fail open, so nothing here may raise or take noticeable time."""

    def test_deep_nesting_does_not_raise(self):
        for c in ("echo " + "$(" * 5000 + "rm -rf /" + ")" * 5000,
                  "echo " + "`" * 5001, "(" * 5000 + "cat .env" + ")" * 5000,
                  "bash -c " * 3000 + "'rm -rf /'", "eval " * 3000 + "rm -rf /"):
            rules.dry_run(ctx_bash(c), overrides={}, windows=False)

    def test_many_unterminated_heredocs_are_linear(self):
        c = "\n".join("cat <<EOF%d" % i for i in range(20000))
        self.assertEqual(rules.strip_heredocs(c), c)

    def test_a_terminated_body_inside_the_depth_bound_is_found(self):
        self.assertTrue(fires("bash -c \"bash -c 'eval rm -rf /'\"", R7_ROOT))


class RootDeleteThroughAShell(unittest.TestCase):
    DENIED = (
        "eval rm -rf /", 'eval "rm -rf /"', "eval 'rm -rf ~'", "eval 'ls; rm -rf /'",
        'eval "rm" "-rf" "/"', "command eval rm -rf /", 'sudo eval "rm -rf /"',
        'bash -c "eval rm -rf /"',
        "bash <<< 'rm -rf /'", 'sh <<< "rm -rf ~"', "bash <<<'rm -rf /'",
        "bash -s <<< 'rm -rf /'", "sudo bash <<< 'rm -rf /'", "bash <<< 'ls; rm -rf /'",
        "bash <<EOF\nrm -rf /\nEOF", "sh <<'EOF'\ncd /tmp\nrm -rf ~\nEOF",
        "bash -s <<-EOF\n\trm -rf /\n\tEOF", "cat <<EOF | bash\nrm -rf /\nEOF",
        "sudo bash <<'EOF'\nrm -rf /\nEOF", "bash <<'EOF'\neval rm -rf /\nEOF",
        "bash <<'OUTER'\nsh <<'INNER'\nrm -rf /\nINNER\nOUTER",
        "source /dev/stdin <<EOF\nrm -rf /\nEOF", ". /dev/stdin <<< 'rm -rf /'",
        "echo 'rm -rf /' | bash", "printf 'rm -rf /\\n' | sh", "echo rm -rf / | bash",
        "env -S 'rm -rf /'", "f() { rm -rf /; }; f", "function f { rm -rf ~; }; f",
        "> /dev/stderr rm -rf /", "2>&1 rm -rf ~", "bash -c 'rm -rf /' _ a",
    )
    ALLOWED = (
        "cat > f.sh <<'EOF'\nrm -rf /\nEOF", "bash run.sh <<EOF\nrm -rf /\nEOF",
        "bash -c 'cat' <<EOF\nrm -rf /\nEOF", "eval ls", 'eval "$(ssh-agent -s)"',
        "bash <<EOF\nrm -rf ./build\nEOF", "echo 'rm -rf /' | grep rm", "echo 'rm -rf /'",
        "cat <<< 'rm -rf /'", "echo 'rm -rf /' | bash run.sh", "grep x <<< 'rm -rf /'",
    )

    def test_denied_and_strict(self):
        for c in self.DENIED:
            self.assertTrue(fires(c, R7_ROOT), c)
            m = rules.prefilter_root_delete(ctx_bash(c))
            self.assertTrue(m.extra.get("strict"), c)

    def test_data_is_left_alone(self):
        for c in self.ALLOWED:
            self.assertFalse(fires(c, R7_ROOT), c)


class ValuelessSecretChecks(unittest.TestCase):
    """Loosened on purpose: these forms cannot print a value."""

    SAFE = (
        'echo "GEMINI_API_KEY set: ${GEMINI_API_KEY:+yes}"',
        'echo "kit=${TYPESAFE_API_KEY:+set}"',
        'echo "${OPENAI_API_KEY+present}"',
        "echo ${#OPENAI_API_KEY}",
        "env | grep -c PAPERCLIP_",
        "env | grep -q PAPERCLIP_API_KEY && echo yes",
        "env | grep -o '^PAPERCLIP[A-Z_]*'",
        "env | grep -o '^PAPERCLIP[A-Z_]*\\|^GEMINI[A-Z_]*'",
        "env | wc -l",
        "env | sort | wc -l",
        "env | sort -u | wc -l",
        "env | head -5 | wc -l",
        "env | grep API | wc -c",
        "compgen -e",
    )
    STILL_DENIED = (
        "env", "set", "(env)", "env | grep PAPERCLIP_", "env | grep PAPERCLIP_ | head",
        "env | grep PAPERCLIP_; echo hi | wc -l",
        "env | grep -o '^PAPERCLIP.*'", "env | grep -o '^[A-Z_]*=[^ ]*'",
        "env | grep -o 'KEY[A-Z_]*'", "echo $OPENAI_API_KEY", "echo ${OPENAI_API_KEY}",
        "echo ${OPENAI_API_KEY:-none}", 'echo "${OPENAI_API_KEY:+set} $OPENAI_API_KEY"',
        "echo ${KEY_TOKEN:+$KEY_TOKEN}", 'echo "${API_KEY:+${API_KEY}}"', "echo ${API_KEY:-}",
        'echo "${API_KEY:+$(cat ~/.env)}"', 'printf %s "$API_KEY"',
        '[ -n "$API_KEY" ] && echo $API_KEY', "n=API_KEY; echo ${!n}", "declare -p",
        "set | grep -c KEY", "env | wc -l; env", "env | cut -d= -f1",
        "env | cut -d= -f1 -s --complement", "env | tee /dev/stderr | wc -l",
        'env | grep -o -e "^PAPERCLIP[A-Z]*" -e ".*"', "env | grep -o '^PAP[*-?]*'",
        "env | grep -oP '^PAPERCLIP[\\x00-\\x7f]*'", "env | grep -o '^[A-Z_]*KEY[A-Z_]*'",
        "env | grep -o '^PAPERCLIP[^ ]*'", "env | grep -c X ~/.config/example/env",
        "env | grep -o '^PAPERCLIP[A-Z_]*' ~/.config/example/env", "env | sed -n p | wc -l",
        "env |& wc -l; env", "env | grep -c X > /tmp/out; cat /tmp/out; env",
        "echo ${API_KEY:+set}$API_KEY", "echo ${API_KEY:+`cat .env`}",
        "echo ${API_KEY:+\\$API_KEY}", 'printf "%s" "${!API_KEY}"',
        "env | wc -l > /dev/stderr | env",
        # Found by running these in bash with fake secrets in the environment.
        # A multi-line value has lines of its own, so cut keeps a piece of it.
        "env | cut -d= -f1 -s", "env | grep PAPERCLIP_ | cut -d= -f1 -s",
        "env 2>&1", "env 2>/dev/null", "env 2>&1 | grep PAPERCLIP",
        "env | sort -o /dev/stderr | wc -l", "env | sort --output=/dev/stderr | wc -l",
        "env | uniq - /dev/stderr | wc -l", "env | wc --files0-from=-",
        "env | head | tee /dev/stderr | wc -l", "env | tail -f /dev/null | wc -l",
    )

    def test_safe_forms_pass(self):
        for c in self.SAFE:
            self.assertIsNone(r1(c), c)

    def test_value_printing_forms_stay_denied(self):
        for c in self.STILL_DENIED:
            self.assertIsNotNone(r1(c), c)

    def test_split_segments_ops_keeps_the_split_segments_contract(self):
        c = "echo 'a;b' && cat x | grep y"
        self.assertEqual(rules.split_segments(c), ["echo 'a;b'", "cat x", "grep y"])
        self.assertEqual(rules.split_segments_ops(c),
                         [("echo 'a;b'", "&&"), ("cat x", "|"), ("grep y", "")])


class RelativeKeyPath(unittest.TestCase):
    def test_a_relative_spelling_of_the_key_file_is_denied(self):
        for c in ("cat jev-kit/env", "cat airlock/env", "cat ./jev-kit/env",
                  "cd ~/.config && cat jev-kit/env", "head -1 .config/airlock/env"):
            self.assertIsNotNone(r1(c), c)

    def test_a_bare_name_read_from_the_key_directory_is_denied(self):
        for c in ("cd ~/.config/jev-kit && cat env", "cd $HOME/.config/airlock; head -1 ./env",
                  "cd ~/.config && cd jev-kit && cat env", "(cd ~/.config/jev-kit && cat env)",
                  "cd ~/.config/jev-kit; cat ../airlock/env"):
            self.assertIsNotNone(r1(c), c)
        ctx = rules.build_ctx({"tool_name": "Bash", "tool_input": {"command": "cat env"},
                               "cwd": os.path.expanduser("~/.config/jev-kit")}, "Bash")
        self.assertIsNotNone(rules.prefilter_secret(ctx))

    def test_a_pointer_target_is_read_relative_to_the_directory(self):
        target = os.path.join(rules.HOME, "keys-elsewhere", "kit-file")
        with mock.patch.object(rules.keyfile, "pointer_target", return_value=target):
            self.assertIsNotNone(r1("cd ~/keys-elsewhere && cat kit-file"))
            self.assertIsNone(r1("cd ~/keys-elsewhere && cat other-file"))

    def test_other_env_paths_stay_allowed(self):
        for c in ("cat env", "cat docs/env", "cat my-jev-kit/env.md", "cat node_modules/env/x.js",
                  "cat airlock/env.py", "cat jev-kit/environment.md", "cd /tmp && cat env",
                  "cd ~/code && cat env"):
            self.assertIsNone(r1(c), c)


class HashInsideShellConstructs(unittest.TestCase):
    """A `#` only starts a comment at the start of a word in plain shell code."""

    TAILS = (("rm -rf /", R7_ROOT), ("rm -rf /", R7), ("cat .env", R1), ("sudo reboot", R5))

    SHAPES = ("echo ${x:- #}", "echo ${x%% #*}", "echo ${x/ #/y}", "echo `echo #`",
              'echo "$(echo "a # b")"', "echo $(echo)#x", "cat <(echo)#x", "(( 1 #2 ))",
              "echo $(( 1 #2 ))", "echo $[ 1 #2 ]", "[[ a =~ ( #) ]]", 'echo "${x:- #}"',
              "echo ${x:-${y:- #}}", "echo ${x:-`echo #`}",
              "echo $'a # b'", "echo $'it\\'s # b'", 'echo "a\\" #b"')

    def test_the_command_after_the_hash_is_still_seen(self):
        for shape in self.SHAPES:
            for tail, rule in self.TAILS:
                c = "%s; %s" % (shape, tail)
                self.assertTrue(fires(c, rule), c)

    def test_a_substitution_after_the_hash_is_still_seen(self):
        for shape in self.SHAPES:
            for sub in ("$(rm -rf /)", "`rm -rf /`"):
                c = "%s; echo %s" % (shape, sub)
                self.assertTrue(fires(c, R7_ROOT), c)

    def test_a_real_comment_still_hides_what_is_in_it(self):
        for c in ("echo hi # rm -rf /", "echo hi # x; rm -rf /", "# rm -rf /", "echo ${x:-a} # b; rm -rf /",
                  "echo $(echo a) # b; rm -rf /", 'echo "a" # b; rm -rf /', "(echo a) # b; rm -rf /",
                  "if true; then # it's; rm -rf /\n:\nfi"):
            self.assertFalse(fires(c, R7_ROOT), c)

    def test_a_comment_inside_a_substitution_is_one(self):
        self.assertFalse(fires("echo $(echo a # rm -rf /\n)", R7_ROOT))
        self.assertFalse(fires('echo "$(echo a # rm -rf /\n)"', R7_ROOT))

    def test_an_apostrophe_in_a_comment_still_hides_nothing(self):
        for c in ("# it's\nrm -rf /", "echo a # it's\nrm -rf /", "echo ${x} # it's\nrm -rf /",
                  'echo "$(echo a # say "hi\n)"; rm -rf /'):
            self.assertTrue(fires(c, R7_ROOT), c)

    def test_a_case_inside_a_substitution_keeps_the_rest_in_view(self):
        for c in ('echo "$(case x in x) echo "a # b";; esac)"; rm -rf /',
                  'echo "$(echo case)" "a #"; rm -rf /'):
            self.assertTrue(fires(c, R7_ROOT), c)

    def test_the_ansi_string_is_one_word(self):
        for c in ("echo $'a\\'b'; rm -rf /", "echo $'a\\'b'; $(rm -rf /)", "echo $'a\\'b' `rm -rf /`",
                  "echo $'\\''; rm -rf /"):
            self.assertTrue(fires(c, R7_ROOT), c)
        for c in ("echo $'a; rm -rf /'", "echo $'$(rm -rf /)'", "echo $'a\\'; rm -rf /'"):
            self.assertFalse(fires(c, R7_ROOT), c)

    def test_quoted_text_stays_data(self):
        for c in ("echo '$(rm -rf /)'", 'echo "a\\"; rm -rf /"', "echo 'a # $(rm -rf /)'",
                  'echo "\\$(rm -rf /)"'):
            self.assertFalse(fires(c, R7_ROOT), c)


class ShellScriptWord(unittest.TestCase):
    """The script of `sh -c` is one shell word, however it is quoted."""

    def test_joined_quotes_stay_one_script(self):
        for c in ("bash -c 'echo '\\''hi'\\'' ; rm -rf /'", "bash -c 'a b'' ; rm -rf /'",
                  'bash -c "a b"" ; rm -rf /"', "bash -c 'a'\" ; rm -rf /\"",
                  "bash -c 'it'\\''s' ; rm -rf /", "sudo bash -lc 'echo '\\''a b'\\''; rm -rf /'",
                  'bash -c "echo \\"a\\"; rm -rf /"', 'bash -c "echo $(echo "a b"); rm -rf /"',
                  "bash -c 'echo \"a\\\"b\"; rm -rf /'", "bash -c rm\\ -rf\\ /"):
            self.assertTrue(fires(c, R7_ROOT), c)

    def test_the_same_forms_reach_r1(self):
        for c in ("bash -c 'echo '\\''hi'\\'' ; cat .env'", "bash -c 'a b'' ; cat .env'",
                  'bash -c "a b"" ; cat .env"'):
            self.assertIsNotNone(r1(c), c)

    def test_a_newline_in_the_script_ends_a_command(self):
        for c in ("bash -c 'true\nrm -rf /'", 'sh -c "true\nrm -rf /"', "bash -c $'true\\nrm -rf /'",
                  "bash -c $'echo \\'hi\\' ; rm -rf /'"):
            self.assertTrue(fires(c, R7_ROOT), c)

    def test_words_after_the_script_are_not_code(self):
        for c in ("bash -c 'true' _ rm -rf /", "bash -c 'echo '\\''a'\\''' _ rm -rf /",
                  'bash -c "true" _ rm -rf /', "bash -c 'a b''c' _ rm -rf /"):
            self.assertFalse(fires(c, R7_ROOT), c)
        self.assertIsNone(r1("bash -c 'echo '\\''a'\\''' _ cat .env"))

    def test_quoted_data_in_the_script_stays_data(self):
        for c in ("bash -c 'echo \"rm -rf /\"'", "bash -c 'echo '\\''rm -rf /'\\'''"):
            self.assertFalse(fires(c, R7_ROOT), c)

    def test_an_unterminated_script_stays_in_view(self):
        self.assertTrue(fires("bash -c 'rm -rf /", R7_ROOT))


class NestedCodeStaysCheap(unittest.TestCase):
    """The hook has 5 seconds and fails open, so no short command may use them."""

    LIMIT = 2.0  # exponential shapes take 30 s or never finish

    @staticmethod
    def nest(opening, closing, depth, core="echo"):
        return opening * depth + core + closing * depth

    def timed(self, command):
        start = time.monotonic()
        rows = rules.dry_run(ctx_bash(command), overrides={}, windows=False)
        self.assertLess(time.monotonic() - start, self.LIMIT, command[:60])
        return {r["rule_id"] for r in rows if r["fires"]}

    def test_mixed_nesting_is_read_in_time(self):
        for opening, closing in (("eval $(", ")"), ('eval "$(', ')"'), ('bash -c "$(', ')"'),
                                 ("bash -c '$(", ")'"), ("echo $(eval `", "`)")):
            for depth in (14, 20, 40):
                body = self.nest(opening, closing, depth)
                self.assertIn(R7_ROOT, self.timed(body + "; rm -rf /"), body)
                self.assertIn(R7_ROOT, self.timed("rm -rf /; " + body), body)

    def test_nesting_that_differs_on_each_path_is_read_in_time(self):
        s = "echo"
        for k in range(30):
            s = "eval $(cd d%d; %s)" % (k, s)
        self.assertIn(R7_ROOT, self.timed(s + "; rm -rf /"))
        s = "echo"
        for _ in range(10):
            s = "eval $(%s) $(%s)" % (s, s)
        self.assertIn(R7_ROOT, self.timed(s + "; rm -rf /"))

    def test_a_long_run_of_leading_words_is_read_in_time(self):
        # Each is skipped ahead of the command. Re-slicing the token list for
        # every one is quadratic, and past the hook's 5 s the hook fails open.
        for lead in ("! ", "( ", "(( ", "{ ", "do ", "if ", "a=1 ", "x) ", "> a ", "<a ", "time ",
                     "nice ", "env ", "env a=1 ", "sudo ", "sudo -u x ", "sudo env ", "sudo nice ", "sudo a=1 ",
                     "timeout 5 ", "command ", "case in ",
                     "function f ", "f() "):
            command = lead * (120000 // len(lead)) + "rm -rf /"
            self.assertIn(R7_ROOT, self.timed(command), lead)

    def test_a_secret_read_inside_the_nesting_is_still_found(self):
        for depth in (1, 2, 4, 8):
            for opening, closing in (("eval $(", ")"), ('bash -c "$(', ')"')):
                c = self.nest(opening, closing, depth, "cat .env")
                self.assertIn(R1, self.timed(c), c)

    def test_the_same_script_is_read_again_from_another_directory(self):
        self.assertIsNotNone(r1("eval cat env; cd ~/.config/jev-kit; eval cat env"))

    def test_past_the_allowance_the_command_itself_is_still_read(self):
        with mock.patch.object(rules, "_SCAN_LIMIT", 0):
            self.assertIsNotNone(r1("cat .env"))
            self.assertIsNone(r1("eval cat .env"))
            self.assertTrue(fires("rm -rf /", R7_ROOT))
            self.assertFalse(fires("eval rm -rf /", R7_ROOT))
            self.assertTrue(fires("eval cat .env; rm -rf /", R7_ROOT))


class LineContinuations(unittest.TestCase):
    def test_a_continuation_after_an_operator_hides_nothing(self):
        for c, rule in (("ls &&\\\nsudo rm -rf /etc", R5),
                        ("echo x |\\\nsudo tee /etc/x", R5),
                        ("\\\nsudo reboot", R5),
                        ("true;\\\nrm -rf /", R7_ROOT),
                        ("rm -rf \\\n  /", R7_ROOT)):
            self.assertTrue(fires(c, rule), repr(c))

    def test_a_continuation_inside_single_quotes_stays_text(self):
        self.assertFalse(fires("echo 'a &&\\\nsudo reboot'", R5))


class QuotedPathWithASpace(unittest.TestCase):
    def test_a_secret_file_under_a_spaced_directory_is_caught(self):
        for c in ('cat "/home/u/My Project/.env"', "head -5 '/home/u/My Project/.env'"):
            self.assertTrue(r1(c), c)

    def test_an_ordinary_spaced_path_is_not(self):
        self.assertFalse(r1('cat "/home/u/My Project/notes.txt"'))


class ReaderOperands(unittest.TestCase):
    def test_writing_a_secret_file_is_not_printing_it(self):
        for c in ("cat > .env <<EOF\nA=1\nEOF", "grep X .env.example > .env",
                  "echo x | tee .env", "cat >.env"):
            self.assertFalse(r1(c), c)

    def test_a_pattern_is_not_a_path(self):
        for c in ("jq .key data.json", "grep -rn credentials src/", "grep .env"):
            self.assertFalse(r1(c), c)

    def test_reading_the_file_is_still_caught(self):
        for c in ("cat .env", "cat .env > out", "cat < .env", "grep foo .env",
                  "grep -e foo .env", "jq . .env", "sed -n p .env",
                  "awk '{print}' .env", "grep -A 3 foo .env"):
            self.assertTrue(r1(c), c)


class ReaderOperandsFailSafe(unittest.TestCase):
    """Leaving an operand out of R1 must never hide a read: each of these
    was a bypass in the first version of the operand filter."""

    def test_tee_with_an_input_redirection_still_reads_it(self):
        for c in ("tee out < .env", "< .env tee out"):
            self.assertTrue(r1(c), c)

    def test_a_quoted_redirect_sign_is_an_argument(self):
        for c in ('grep ">" .env', "grep '>' .env > out", 'cat ">" .env'):
            self.assertTrue(r1(c), c)

    def test_a_pattern_file_in_a_flag_cluster_keeps_the_operands(self):
        for c in ("grep -rf .env x", "grep -ie foo .env"):
            self.assertTrue(r1(c), c)

    def test_a_glob_option_value_is_not_taken_for_the_pattern(self):
        for c in ("grep -r --include .env KEY .", "rg -g .env KEY"):
            self.assertTrue(r1(c), c)

    def test_awk_and_sed_programs_stay_in_view(self):
        self.assertTrue(r1("sed -n p .env"))
        self.assertTrue(r1("awk '{print}' .env"))


class CommandLookups(unittest.TestCase):
    def test_command_v_runs_nothing(self):
        self.assertFalse(fires("command -v sudo", R5))
        self.assertFalse(r1("command -v printenv"))

    def test_command_still_runs_its_argument(self):
        self.assertTrue(fires("command sudo reboot", R5))
        self.assertTrue(fires("command -p sudo reboot", R5))


class BareExportAndDeclare(unittest.TestCase):
    def test_bare_export_and_declare_dump_the_environment(self):
        for c in ("export", "declare", "export | grep KEY"):
            self.assertTrue(r1(c), c)

    def test_setting_a_variable_is_not_a_dump(self):
        self.assertFalse(r1("export FOO=1"))
        self.assertFalse(r1("declare -f myfn"))


class QuotedAssignmentValues(unittest.TestCase):
    def test_words_inside_a_quoted_value_are_not_a_command(self):
        self.assertFalse(fires('MSG="Remove sudo usage"', R5))
        self.assertFalse(fires('NOTE="never rm -rf / ok"', R7_ROOT))

    def test_the_command_after_the_value_still_counts(self):
        for c in ('X="a b"c sudo reboot', 'X="a \\" b" sudo reboot',
                  'X="unclosed sudo reboot', "X=a\\ b sudo reboot"):
            self.assertTrue(fires(c, R5), c)
        self.assertTrue(fires("X='a b' sudo reboot", R5))
        self.assertTrue(fires('X="a b" rm -rf /', R7_ROOT))
        self.assertTrue(fires('env X="a b" sudo reboot', R5))


class CommitMessageWords(unittest.TestCase):
    def test_a_message_naming_a_secret_file_stages_nothing(self):
        for c in ('git commit -m "ignore .env files"', "git commit -am 'drop .env'",
                  'git commit --message="no .env here"'):
            self.assertFalse(fires(c, R9), c)

    def test_a_pathspec_or_a_token_still_counts(self):
        token = "sk-" + "abcdefghijklmnopqrstuvwx1234"
        for c in ('git commit -m "x" .env', "git add .env",
                  'git commit -m "key %s"' % token):
            self.assertTrue(fires(c, R9), c)


class SudoThroughAShell(unittest.TestCase):
    def test_sudo_handed_to_a_shell_is_still_sudo(self):
        for c in ("bash -c 'sudo rm -rf /etc/x'", "eval sudo reboot",
                  "sh -c \"bash -c 'sudo reboot'\"", 'bash <<< "sudo reboot"'):
            self.assertTrue(fires(c, R5), c)

    def test_a_named_install_through_a_shell_is_still_allowed(self):
        self.assertFalse(fires("bash -c 'sudo apt-get install -y jq'", R5))


class QuotedTilde(unittest.TestCase):
    def test_a_quoted_tilde_is_a_file_named_tilde(self):
        for c in ('rm -rf "~"', "rm -rf '~'", 'rm -rf "~/"'):
            self.assertFalse(fires(c, R7_ROOT), c)

    def test_the_home_directory_is_still_denied(self):
        for c in ("rm -rf ~", 'rm -rf "$HOME"', 'rm -rf "/"', "rm '-rf' /",
                  'nice "-n" 5 rm -rf /', "sudo '-u' root rm -rf /"):
            self.assertTrue(fires(c, R7_ROOT), c)


class HealthSummaryTimestamps(unittest.TestCase):
    def test_a_naive_timestamp_does_not_break_the_summary(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        rows = [{"ts": now.replace(tzinfo=None).isoformat()}, {"ts": now.isoformat()}]
        self.assertEqual(health.summarize_last_hour(rows=rows, now=now)["total_rows"], 2)


if __name__ == "__main__":
    unittest.main()
