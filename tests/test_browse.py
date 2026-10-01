"""browse/server.py: the MCP framing, the schema, and every way a call fails.

Nothing here reaches the network or starts a browser. The jev-ultrafast call
(`run_runner`) and the Chromium lifecycle are mocked wherever a test would
otherwise need them; the two tests that start a real child process start a
one-line Python stand-in, never the agent.
"""
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from browse import server  # noqa: E402

KEY = "apikey_test_0123456789"


def read(path):
    with open(path) as f:
        return f.read()


def rpc(method, msg_id=1, **params):
    msg = {"jsonrpc": "2.0", "method": method}
    if msg_id is not None:
        msg["id"] = msg_id
    if params:
        msg["params"] = params
    return msg


def call(srv, **arguments):
    response = srv.handle(rpc("tools/call", name="browse", arguments=arguments))
    return response["result"]


class FakeBrowse:
    def __init__(self, result=None, error=None):
        self.result, self.error = result or {"final_url": "https://example.com/"}, error
        self.calls, self.shut = [], 0

    def call(self, args):
        self.calls.append(args)
        if self.error:
            raise self.error
        return self.result

    def shutdown(self):
        self.shut += 1


class TestHandshake(unittest.TestCase):
    def setUp(self):
        self.srv = server.Server(FakeBrowse())

    def test_initialize_echoes_a_version_it_knows(self):
        r = self.srv.handle(rpc("initialize", protocolVersion="2024-11-05",
                                capabilities={}, clientInfo={"name": "t"}))
        self.assertEqual(r["jsonrpc"], "2.0")
        self.assertEqual(r["id"], 1)
        self.assertEqual(r["result"]["protocolVersion"], "2024-11-05")
        self.assertEqual(r["result"]["capabilities"], {"tools": {}})
        self.assertEqual(r["result"]["serverInfo"]["name"], "jev-kit-browse")

    def test_initialize_answers_an_unknown_version_with_its_newest(self):
        r = self.srv.handle(rpc("initialize", protocolVersion="1999-01-01"))
        self.assertEqual(r["result"]["protocolVersion"], server.PROTOCOL_VERSIONS[0])

    def test_a_notification_gets_no_response(self):
        self.assertIsNone(self.srv.handle(rpc("notifications/initialized", msg_id=None)))
        self.assertIsNone(self.srv.handle(rpc("notifications/cancelled", msg_id=None,
                                              requestId=3)))

    def test_ping(self):
        self.assertEqual(self.srv.handle(rpc("ping", msg_id="a"))["result"], {})

    def test_an_unknown_method_is_a_jsonrpc_error(self):
        r = self.srv.handle(rpc("resources/list"))
        self.assertEqual(r["error"]["code"], -32601)

    def test_an_unknown_tool_is_a_jsonrpc_error(self):
        r = self.srv.handle(rpc("tools/call", name="navigate", arguments={}))
        self.assertEqual(r["error"]["code"], -32602)

    def test_an_invalid_request(self):
        for msg in ({"id": 1, "method": "ping"}, {"jsonrpc": "2.0", "id": 1}, 7, "x"):
            self.assertEqual(self.srv.handle(msg)["error"]["code"], -32600, msg)
        r = self.srv.handle({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": [1]})
        self.assertEqual(r["error"]["code"], -32602)

    def test_a_line_that_is_not_json_is_a_parse_error(self):
        (r,) = self.srv.handle_line("{nope")
        self.assertEqual(r["error"]["code"], -32700)
        self.assertIsNone(r["id"])

    def test_a_batch(self):
        out = self.srv.handle_line(json.dumps([rpc("ping", 1), rpc("x", None), rpc("ping", 2)]))
        self.assertEqual([r["id"] for r in out], [1, 2])
        self.assertEqual(self.srv.handle_line("[]")[0]["error"]["code"], -32600)


class TestSchema(unittest.TestCase):
    def test_tools_list_is_the_one_tool(self):
        r = server.Server(FakeBrowse()).handle(rpc("tools/list"))
        (tool,) = r["result"]["tools"]
        self.assertEqual(tool["name"], "browse")
        self.assertTrue(tool["description"])
        schema = tool["inputSchema"]
        self.assertEqual(schema["type"], "object")
        self.assertEqual(schema["required"], ["goal"])
        self.assertEqual(set(schema["properties"]), {"goal", "start_url", "extract", "screenshot", "links", "rank_goal",
                          "plan", "plan_model"})
        self.assertIs(schema["properties"]["plan"]["default"], False)
        self.assertEqual(schema["properties"]["plan_model"]["enum"], ["sonnet", "haiku"])
        # The description says when to plan and what it costs, not only that it exists.
        self.assertIn("open-ended", tool["description"])
        self.assertIn("claude login", tool["description"])
        for name in ("goal", "start_url", "extract"):
            self.assertEqual(schema["properties"][name]["type"], "string", name)
        self.assertEqual(schema["properties"]["screenshot"]["type"], "boolean")
        self.assertIs(schema["properties"]["screenshot"]["default"], False)
        json.dumps(r)  # the whole thing must serialise


class TestTheReadLoop(unittest.TestCase):
    def _serve(self, lines, browse=None):
        browse = browse or FakeBrowse()
        out = io.StringIO()
        server.Server(browse).serve(io.StringIO("".join(x + "\n" for x in lines)), out)
        return [json.loads(x) for x in out.getvalue().splitlines()], browse

    def test_one_response_per_request_one_line_each(self):
        out, browse = self._serve([
            json.dumps(rpc("initialize", 1, protocolVersion="2025-06-18")),
            json.dumps(rpc("notifications/initialized", None)),
            "",
            json.dumps(rpc("tools/list", 2)),
            json.dumps(rpc("tools/call", 3, name="browse", arguments={"goal": "g"})),
        ])
        self.assertEqual([r["id"] for r in out], [1, 2, 3])
        self.assertFalse(out[2]["result"]["isError"])
        self.assertEqual(json.loads(out[2]["result"]["content"][0]["text"]),
                         {"final_url": "https://example.com/"})
        self.assertEqual(browse.shut, 1, "the browser is closed when stdin ends")

    def test_garbage_never_stops_the_loop(self):
        out, _ = self._serve(["{nope", "[1, 2]", json.dumps(rpc("ping", 9))])
        self.assertEqual(out[-1], {"jsonrpc": "2.0", "id": 9, "result": {}})

    def test_a_crash_in_the_tool_is_an_is_error_result(self):
        out, _ = self._serve(
            [json.dumps(rpc("tools/call", 1, name="browse", arguments={"goal": "g"})),
             json.dumps(rpc("ping", 2))],
            FakeBrowse(error=RuntimeError("boom")))
        self.assertTrue(out[0]["result"]["isError"])
        self.assertIn("RuntimeError", out[0]["result"]["content"][0]["text"])
        self.assertEqual(out[1]["id"], 2)

    def test_the_real_server_answers_the_handshake_over_stdio(self):
        """What install/doctor.sh does: a real process, a real pipe."""
        lines = [json.dumps(rpc("initialize", 1, protocolVersion="2025-06-18")),
                 json.dumps(rpc("notifications/initialized", None)),
                 json.dumps(rpc("tools/list", 2))]
        done = subprocess.run([sys.executable, str(REPO_ROOT / "browse" / "server.py")],
                              input="\n".join(lines) + "\n", capture_output=True,
                              text=True, timeout=30,
                              env=dict(os.environ, JEV_BROWSE_PREWARM="0"))
        self.assertEqual(done.returncode, 0, done.stderr)
        out = [json.loads(x) for x in done.stdout.splitlines()]
        self.assertEqual([r["id"] for r in out], [1, 2])
        self.assertEqual(out[1]["result"]["tools"][0]["name"], "browse")


class TestArguments(unittest.TestCase):
    def test_the_start_url_comes_from_the_goal_when_not_given(self):
        p = server.parse_arguments({"goal": "open https://example.com/a?b=1, then report."})
        self.assertEqual(p["start_url"], "https://example.com/a?b=1")
        self.assertIsNone(p["extract"])
        self.assertIs(p["screenshot"], False)
        p = server.parse_arguments({"goal": "see (https://example.com)."})
        self.assertEqual(p["start_url"], "https://example.com")

    def test_an_explicit_start_url_wins(self):
        p = server.parse_arguments({"goal": "open https://a.example", "extract": " h1 ",
                                    "start_url": "https://b.example", "screenshot": True})
        self.assertEqual((p["start_url"], p["extract"], p["screenshot"]),
                         ("https://b.example", "h1", True))

    def test_what_is_refused(self):
        for args, fragment in (
            ({}, "`goal` is required"),
            ({"goal": "  "}, "`goal` is required"),
            ({"goal": 3}, "`goal` is required"),
            ({"goal": "report the heading"}, "start_url"),
            ({"goal": "g", "start_url": "file:///etc/passwd"}, "http://"),
            ({"goal": "g", "start_url": "javascript:alert(1)"}, "http://"),
            ({"goal": "g https://x.example", "screenshot": "yes"}, "`screenshot`"),
            ({"goal": "g https://x.example", "extract": 4}, "`extract`"),
            ({"goal": "g https://x.example", "url": "https://x"}, "unknown argument"),
            ({"goal": "g https://x.example", "links": "yes"}, "`links`"),
            ({"goal": "g https://x.example", "rank_goal": 7}, "`rank_goal`"),
            ({"goal": "g https://x.example", "plan": "yes"}, "`plan`"),
            ({"goal": "g https://x.example", "plan": True, "plan_model": "opus"}, "`plan_model`"),
            ("goal", "must be an object"),
        ):
            with self.assertRaises(server.BrowseError) as caught:
                server.parse_arguments(args)
            self.assertIn(fragment, str(caught.exception), args)

    def test_links_and_rank_goal_are_off_unless_asked_for(self):
        p = server.parse_arguments({"goal": "open https://a.example"})
        self.assertIs(p["links"], False)
        self.assertIsNone(p["rank_goal"])
        p = server.parse_arguments({"goal": "click 'Bicycle wheel'",
                                    "start_url": "https://a.example",
                                    "links": True, "rank_goal": "  the whole task  "})
        self.assertIs(p["links"], True)
        self.assertEqual(p["rank_goal"], "the whole task")

    def test_text_is_trimmed_to_8_kb_on_a_character_boundary(self):
        text, truncated = server.trim_text("é" * 5000)
        self.assertTrue(truncated)
        self.assertLessEqual(len(text.encode("utf-8")), 8192)
        self.assertEqual(text, "é" * 4096)
        self.assertEqual(server.trim_text("short"), ("short", False))
        self.assertEqual(server.trim_text(None), ("", False))


class CallCase(unittest.TestCase):
    """A Browse whose clone, key and Chromium are all stand-ins."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.clone = Path(self.tmp) / "jev-ultrafast"
        (self.clone / "jev_ultrafast").mkdir(parents=True)
        (self.clone / "jev_ultrafast" / "agent.py").write_text("")
        env = {"JEV_ULTRAFAST_DIR": str(self.clone),
               "XDG_STATE_HOME": str(Path(self.tmp) / "state")}
        for var in ("JEV_BROWSE_TIMEOUT", "AIRLOCK_BROWSER_DIR"):
            os.environ.pop(var, None)
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)
        k = mock.patch.object(server.keyfile, "get_api_key", return_value=KEY)
        k.start()
        self.addCleanup(k.stop)
        self.browse = server.Browse()
        self.browse.chromium = mock.Mock()
        self.browse.chromium.ensure.return_value = "http://127.0.0.1:45678"
        self.srv = server.Server(self.browse)

    RESULT = {"status": "done", "steps": 2, "final_url": "https://example.com/",
              "title": "Example Domain", "text": "Example Domain\n\nMore",
              "extracted": "Example Domain"}


class TestACall(CallCase):
    def test_the_result_has_the_documented_fields(self):
        with mock.patch.object(self.browse, "ask", return_value=dict(self.RESULT)) as run:
            result = call(self.srv, goal="open https://example.com and report the heading",
                          extract="h1")
        self.assertFalse(result["isError"])
        out = json.loads(result["content"][0]["text"])
        self.assertEqual(out["final_url"], "https://example.com/")
        self.assertEqual(out["title"], "Example Domain")
        self.assertEqual(out["steps"], 2)
        self.assertEqual(out["status"], "done")
        self.assertEqual(out["extracted"], "Example Domain")
        self.assertIsInstance(out["elapsed_ms"], int)
        self.assertNotIn("screenshot_path", out)
        request, env, clone, timeout = run.call_args[0]
        self.assertEqual(request["op"], "browse")
        self.assertEqual(request["start_url"], "https://example.com")
        self.assertEqual(request["extract"], "h1")
        self.assertNotIn("screenshot_path", request)
        self.assertEqual(clone, self.clone)
        self.assertLessEqual(timeout, 90)
        self.assertGreater(timeout, 80)

    def test_the_key_travels_in_the_environment_and_nowhere_else(self):
        with mock.patch.object(self.browse, "ask", return_value=dict(self.RESULT)) as run:
            call(self.srv, goal="open https://example.com")
        request, env, _clone, _timeout = run.call_args[0]
        self.assertEqual(env["TYPESAFE_API_KEY"], KEY)
        self.assertEqual(env["BU_CDP_URL"], "http://127.0.0.1:45678")
        self.assertTrue(env["BU_NAME"].startswith("jevkit-browse-"))
        self.assertNotIn(KEY, json.dumps(request))

    def test_links_reach_the_runner_and_come_back(self):
        rows = [{"index": "1", "role": "link", "label": "Bicycle wheel"}]
        with mock.patch.object(self.browse, "ask",
                               return_value=dict(self.RESULT, links=rows)) as run:
            out = json.loads(call(self.srv, goal="open https://example.com",
                                  links=True, rank_goal="the whole task")["content"][0]["text"])
        self.assertEqual(out["links"], rows)
        request = run.call_args[0][0]
        self.assertIs(request["links"], True)
        self.assertEqual(request["rank_goal"], "the whole task")

    def test_plan_mode_sends_the_plan_op_with_a_budget_inside_the_timeout(self):
        plan = {"model": "sonnet", "turns": 3, "cost_usd": 0.04}
        with mock.patch.dict(os.environ, {"JEV_BROWSE_TIMEOUT": ""}), \
                mock.patch.object(self.browse, "ask",
                                  return_value=dict(self.RESULT, plan=plan)) as run:
            out = json.loads(call(self.srv, goal="find when the author of X was born",
                                  start_url="https://example.com", plan=True,
                                  plan_model="haiku")["content"][0]["text"])
        self.assertEqual(out["plan"], plan)
        request, _env, _clone, timeout = run.call_args[0]
        self.assertEqual(request["op"], "plan")
        self.assertEqual(request["plan_model"], "haiku")
        self.assertGreater(timeout, 170)
        self.assertLess(request["budget_s"], timeout - 5)

    def test_plain_browse_is_the_default_and_never_plans(self):
        with mock.patch.object(self.browse, "ask", return_value=dict(self.RESULT)) as run:
            out = json.loads(call(self.srv, goal="open https://example.com")["content"][0]["text"])
        request = run.call_args[0][0]
        self.assertEqual(request["op"], "browse")
        self.assertIs(request["plan"], False)
        self.assertNotIn("budget_s", request)
        self.assertNotIn("plan", out)

    def test_links_are_absent_unless_asked_for(self):
        with mock.patch.object(self.browse, "ask",
                               return_value=dict(self.RESULT, links=[{"index": "1"}])) as run:
            out = json.loads(call(self.srv, goal="open https://example.com")["content"][0]["text"])
        self.assertNotIn("links", out)
        self.assertIs(run.call_args[0][0]["links"], False)

    def test_extracted_is_absent_unless_asked_for(self):
        with mock.patch.object(self.browse, "ask", return_value=dict(self.RESULT)):
            out = json.loads(call(self.srv, goal="open https://example.com")["content"][0]["text"])
        self.assertNotIn("extracted", out)

    def test_a_screenshot_lands_under_the_state_directory(self):
        def runner(request, env, clone, timeout):
            return dict(self.RESULT, screenshot_path=request["screenshot_path"])

        with mock.patch.object(self.browse, "ask", side_effect=runner):
            out = json.loads(call(self.srv, goal="open https://example.com",
                                  screenshot=True)["content"][0]["text"])
        path = Path(out["screenshot_path"])
        self.assertEqual(path.parent, Path(self.tmp) / "state" / "jev-kit" / "browse")
        self.assertEqual(path.suffix, ".png")
        self.assertTrue(path.parent.is_dir())

    def test_the_state_directory_defaults_under_local_state(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("XDG_STATE_HOME", None)
            self.assertEqual(server.state_dir(),
                             Path.home() / ".local" / "state" / "jev-kit" / "browse")

    def test_long_text_is_trimmed_and_flagged(self):
        with mock.patch.object(self.browse, "ask",
                               return_value=dict(self.RESULT, text="x" * 20000)):
            out = json.loads(call(self.srv, goal="open https://example.com")["content"][0]["text"])
        self.assertEqual(len(out["text"]), 8192)
        self.assertTrue(out["text_truncated"])

    def test_the_key_is_scrubbed_from_whatever_comes_back(self):
        with mock.patch.object(self.browse, "ask",
                               return_value=dict(self.RESULT, text="leak %s here" % KEY)):
            result = call(self.srv, goal="open https://example.com")
        self.assertNotIn(KEY, json.dumps(result))
        with mock.patch.object(self.browse, "ask",
                               side_effect=server.BrowseError("HTTP 401 for %s" % KEY)):
            result = call(self.srv, goal="open https://example.com")
        self.assertTrue(result["isError"])
        self.assertNotIn(KEY, json.dumps(result))
        self.assertIn("[REDACTED]", result["content"][0]["text"])

    def test_the_text_model_key_is_scrubbed_too(self):
        text_key = "sk-or-v1-textmodelsecret0123456789"
        with mock.patch.dict(os.environ, {"TEXT_MODEL_API_KEY": text_key}):
            with mock.patch.object(self.browse, "ask",
                                   return_value=dict(self.RESULT, text="leak %s" % text_key)):
                result = call(self.srv, goal="open https://example.com")
            self.assertNotIn(text_key, json.dumps(result))
            with mock.patch.object(self.browse, "ask",
                                   side_effect=server.BrowseError("401 for %s" % text_key)):
                result = call(self.srv, goal="open https://example.com")
        self.assertTrue(result["isError"])
        self.assertNotIn(text_key, json.dumps(result))


class TestShutdown(CallCase):
    def shut_down_after(self, calls, owned):
        self.browse.chromium.owned.return_value = owned
        with mock.patch.object(self.browse, "ask", return_value=dict(self.RESULT)) as run:
            for _ in range(calls):
                call(self.srv, goal="open https://example.com")
            run.reset_mock()
            self.browse.shutdown()
        return run

    def assert_one_stop(self, run):
        self.assertEqual(run.call_count, 1)
        request, env, clone, _timeout = run.call_args[0]
        self.assertEqual(request, {"op": "stop_daemon"})
        self.assertEqual(env["BU_NAME"], self.browse.daemon_name())
        self.assertEqual(clone, self.clone)
        self.browse.chromium.close.assert_called_once_with()

    def test_an_attached_browser_still_has_its_daemon_stopped(self):
        self.assert_one_stop(self.shut_down_after(1, owned=False))

    def test_an_owned_browser_has_its_daemon_stopped(self):
        self.assert_one_stop(self.shut_down_after(1, owned=True))

    def test_a_call_that_failed_in_the_runner_still_counts(self):
        self.browse.chromium.owned.return_value = False
        with mock.patch.object(self.browse, "ask",
                               side_effect=server.BrowseError("the agent fell over")):
            self.assertTrue(call(self.srv, goal="open https://example.com")["isError"])
        with mock.patch.object(self.browse, "ask") as run:
            self.browse.shutdown()
        self.assert_one_stop(run)

    def test_no_call_means_no_daemon_to_stop(self):
        for owned in (False, True):
            run = self.shut_down_after(0, owned=owned)
            run.assert_not_called()

    def test_a_stop_that_fails_still_closes_the_browser(self):
        self.browse.daemon_used = True
        with mock.patch.object(self.browse, "ask", side_effect=OSError("gone")):
            self.browse.shutdown()
        self.browse.chromium.close.assert_called_once_with()


class TestErrorPaths(CallCase):
    def test_a_missing_source_tree_names_the_vendored_copy(self):
        with mock.patch.dict(os.environ, {"JEV_ULTRAFAST_DIR": str(Path(self.tmp) / "absent")}), \
             mock.patch.object(self.browse, "ask") as run:
            result = call(self.srv, goal="open https://example.com")
        self.assertTrue(result["isError"])
        text = result["content"][0]["text"]
        self.assertIn("vendor/jev-ultrafast", text)
        self.assertIn("JEV_ULTRAFAST_DIR", text)
        run.assert_not_called()
        self.browse.chromium.ensure.assert_not_called()

    def test_the_source_tree_falls_back_to_the_vendored_copy(self):
        with mock.patch.dict(os.environ, {"AIRLOCK_BROWSER_DIR": "/somewhere/else"}):
            self.assertEqual(server.clone_dir(), self.clone)
            os.environ.pop("JEV_ULTRAFAST_DIR")
            self.assertEqual(server.clone_dir(), Path("/somewhere/else"))
            os.environ.pop("AIRLOCK_BROWSER_DIR")
            # Relative to server.py, so it is the checkout in development and
            # $AIRLOCK_HOME/releases/<sha>/vendor/jev-ultrafast once deployed.
            self.assertEqual(server.clone_dir(),
                             server.REPO_ROOT / "vendor" / "jev-ultrafast")
            self.assertTrue((server.REPO_ROOT / "vendor" / "jev-ultrafast"
                             / "jev_ultrafast" / "agent.py").is_file())

    def test_the_environment_lives_outside_the_release(self):
        with mock.patch.dict(os.environ, {"JEV_ULTRAFAST_VENV": "~/elsewhere/venv"}):
            self.assertEqual(server.venv_dir(),
                             Path(os.path.expanduser("~/elsewhere/venv")))
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("JEV_ULTRAFAST_VENV", None)
            venv = server.venv_dir()
        # Under $AIRLOCK_HOME, never inside the release: a release is pruned
        # and re-exported, and the environment has to outlive that.
        self.assertEqual(venv.name, "jev-ultrafast-venv")
        self.assertFalse(str(venv).startswith(str(server.REPO_ROOT) + os.sep))

    def test_the_runner_prefers_the_shared_environment(self):
        venv = Path(self.tmp) / "venv"
        (venv / "bin").mkdir(parents=True)
        python = venv / "bin" / "python"
        python.write_text("")
        with mock.patch.dict(os.environ, {"JEV_ULTRAFAST_VENV": str(venv)}):
            self.assertEqual(server.runner_command(self.clone)[0], str(python))

    def test_the_child_is_told_where_the_source_is(self):
        captured = {}

        def fake_popen(argv, **kwargs):
            captured.update(kwargs)
            raise OSError("stop here")

        with mock.patch.object(server, "runner_command", return_value=["x"]), \
             mock.patch.object(server.subprocess, "Popen", fake_popen):
            with self.assertRaises(server.BrowseError):
                server.Worker(self.clone, {"PYTHONPATH": "/keep"}, None).start()
        self.assertEqual(captured["env"]["PYTHONPATH"],
                         str(self.clone) + os.pathsep + "/keep")

    def test_a_missing_key_names_the_key_file(self):
        for missing in (None, ""):
            with mock.patch.object(server.keyfile, "get_api_key", return_value=missing), \
                 mock.patch.object(self.browse, "ask") as run:
                result = call(self.srv, goal="open https://example.com")
            self.assertTrue(result["isError"])
            self.assertIn("~/.config/jev-kit/env", result["content"][0]["text"])
            self.assertIn("TYPESAFE_API_KEY", result["content"][0]["text"])
            run.assert_not_called()
            self.browse.chromium.ensure.assert_not_called()

    def test_the_key_comes_from_the_kits_own_resolver(self):
        self.assertIs(server.keyfile, __import__("airlock.keyfile", fromlist=["x"]))

    def test_a_timeout_is_an_error_and_restarts_the_browser(self):
        with mock.patch.object(self.browse, "ask",
                               side_effect=server.BrowseTimeout("timed out after 90 s")):
            result = call(self.srv, goal="open https://example.com")
        self.assertTrue(result["isError"])
        self.assertIn("timed out", result["content"][0]["text"])
        self.browse.chromium.close.assert_called_once()

    def test_the_timeout_is_read_from_the_environment(self):
        for raw, want in (("12.5", 12.5), ("", 90.0), ("soon", 90.0), ("-4", 90.0), ("0", 90.0)):
            with mock.patch.dict(os.environ, {"JEV_BROWSE_TIMEOUT": raw}):
                self.assertEqual(server.call_timeout_s(), want, raw)

    def test_a_chromium_failure_is_an_error_result(self):
        self.browse.chromium.ensure.side_effect = server.BrowseError(
            "no Chromium binary found")
        with mock.patch.object(self.browse, "ask") as run:
            result = call(self.srv, goal="open https://example.com")
        self.assertTrue(result["isError"])
        run.assert_not_called()

    def test_a_bad_argument_is_an_error_result_not_a_crash(self):
        result = call(self.srv, goal="no url in here")
        self.assertTrue(result["isError"])
        self.assertIn("start_url", result["content"][0]["text"])


ECHO_WORKER = (
    "import json, sys\n"
    "for line in sys.stdin:\n"
    "    print(json.dumps({'ok': json.loads(line)['op']}), flush=True)\n"
)


@unittest.skipIf(os.name == "nt", "process groups are POSIX here")
class TestTheWorkerProcess(unittest.TestCase):
    """Worker against a few-line stand-in for browse/runner.py."""

    def worker(self, code):
        with mock.patch.object(server, "runner_command",
                               return_value=[sys.executable, "-c", code]):
            w = server.Worker(Path("."), dict(os.environ), None).start()
        self.addCleanup(w.stop)
        return w

    def _run(self, code, timeout=10):
        return self.worker(code).ask({"op": "browse"}, timeout)

    def test_one_json_line_per_request_and_noise_is_ignored(self):
        w = self.worker("import sys, json\n"
                        "for line in sys.stdin:\n"
                        "    json.loads(line); print('noise', flush=True)\n"
                        "    print(json.dumps({'status': 'done'}), flush=True)\n")
        self.assertEqual(w.ask({"op": "browse"}, 10), {"status": "done"})
        self.assertEqual(w.ask({"op": "browse"}, 10), {"status": "done"})
        self.assertEqual(w.calls, 2)

    def test_one_worker_serves_every_call(self):
        w = self.worker(ECHO_WORKER)
        pid = w.proc.pid
        for _ in range(3):
            w.ask({"op": "browse"}, 10)
        self.assertEqual(w.proc.pid, pid)

    def test_an_error_result_is_raised_with_its_message_and_keeps_the_worker(self):
        w = self.worker("import sys, json\n"
                        "for line in sys.stdin:\n"
                        "    json.loads(line)\n"
                        "    print(json.dumps({'error': 'KeyError: x'}), flush=True)\n")
        with self.assertRaises(server.BrowseError) as caught:
            w.ask({"op": "browse"}, 10)
        self.assertIn("KeyError: x", str(caught.exception))
        self.assertTrue(w.alive(), "a failed call is not a dead worker")

    def test_a_crash_with_no_result_reports_the_stderr_tail(self):
        with self.assertRaises(server.BrowseError) as caught:
            self._run("import sys; sys.stderr.write('ModuleNotFoundError: jev_ultrafast\\n'); "
                      "sys.exit(3)")
        self.assertIn("status 3", str(caught.exception))
        self.assertIn("ModuleNotFoundError", str(caught.exception))

    def test_a_hung_agent_is_killed_at_the_timeout(self):
        marker = os.path.join(tempfile.mkdtemp(), "pid")
        self.addCleanup(__import__("shutil").rmtree, os.path.dirname(marker), True)
        code = ("import os, sys, time\n"
                "for line in sys.stdin:\n"
                "    open(%r, 'w').write(str(os.getpid())); time.sleep(60)\n" % marker)
        w = self.worker(code)
        started = time.monotonic()
        with self.assertRaises(server.BrowseTimeout) as caught:
            w.ask({"op": "browse"}, 1.0)
        self.assertLess(time.monotonic() - started, 10)
        self.assertIn("JEV_BROWSE_TIMEOUT", str(caught.exception))
        self.assertFalse(w.alive())
        pid = int(read(marker))
        with self.assertRaises(OSError):
            os.kill(pid, 0)

    def test_no_interpreter_and_no_uv_is_a_message(self):
        with mock.patch.object(server.shutil, "which", return_value=None):
            with self.assertRaises(server.BrowseError) as caught:
                server.runner_command(Path(tempfile.gettempdir()) / "no-such-clone")
        self.assertIn("browser/install.sh", str(caught.exception))


@unittest.skipIf(os.name == "nt", "process groups are POSIX here")
class TestTheWorkerLifecycle(CallCase):
    """Browse.ask: one worker for the server, replaced when it has to be."""

    def setUp(self):
        super().setUp()
        self.started = []

        class FakeWorker:
            def __init__(worker, clone, env, cdp_url):
                worker.clone, worker.env, worker.cdp_url = clone, env, cdp_url
                worker.dead = False
                worker.asked = []
                worker.stopped = 0
                self.started.append(worker)

            def start(worker):
                return worker

            def alive(worker):
                return not worker.dead

            def ask(worker, request, timeout_s):
                worker.asked.append(request)
                return dict(TestACall.RESULT)

            def stop(worker):
                worker.stopped += 1
                worker.dead = True

        p = mock.patch.object(server, "Worker", FakeWorker)
        p.start()
        self.addCleanup(p.stop)

    def test_one_worker_serves_every_call(self):
        for _ in range(3):
            call(self.srv, goal="open https://example.com")
        self.assertEqual(len(self.started), 1)
        self.assertEqual(len(self.started[0].asked), 3)

    def test_a_dead_worker_is_replaced(self):
        call(self.srv, goal="open https://example.com")
        self.started[0].dead = True
        call(self.srv, goal="open https://example.com")
        self.assertEqual(len(self.started), 2)
        self.assertEqual(self.started[0].stopped, 1)

    def test_a_new_chromium_gets_a_new_worker(self):
        call(self.srv, goal="open https://example.com")
        self.browse.chromium.ensure.return_value = "http://127.0.0.1:45679"
        call(self.srv, goal="open https://example.com")
        self.assertEqual([w.cdp_url for w in self.started],
                         ["http://127.0.0.1:45678", "http://127.0.0.1:45679"])

    def test_shutdown_stops_the_worker_and_the_daemon(self):
        call(self.srv, goal="open https://example.com")
        self.browse.shutdown()
        self.assertEqual(self.started[0].asked[-1], {"op": "stop_daemon"})
        self.assertEqual(self.started[0].stopped, 1)
        self.assertEqual(len(self.started), 1, "stopping is not worth a new worker")
        self.browse.chromium.close.assert_called_once_with()

    def test_the_text_model_defaults_to_the_warm_claude_child(self):
        with mock.patch.dict(os.environ), \
             mock.patch.object(server.keyfile, "get_env_value", return_value=None):
            for var in ("TEXT_MODEL_PROVIDER", "TEXT_MODEL_API_KEY",
                        "MAX_THINKING_TOKENS", "TEXT_MODEL_CONTEXT"):
                os.environ.pop(var, None)
            env = self.browse.child_env(KEY, "http://127.0.0.1:1")
        self.assertEqual(env["TEXT_MODEL_PROVIDER"], "claude-standing")
        self.assertEqual(env["MAX_THINKING_TOKENS"], "0")
        self.assertEqual(env["TEXT_MODEL_CONTEXT"], "trimmed")
        self.assertNotIn("TEXT_MODEL_API_KEY", env)

    def test_a_text_model_key_selects_the_openai_compatible_helper(self):
        with mock.patch.object(server.keyfile, "get_env_value", return_value="sk-test"):
            env = server.text_model_env({})
        self.assertNotIn("TEXT_MODEL_PROVIDER", env)
        self.assertEqual(env["TEXT_MODEL_API_KEY"], "sk-test")
        self.assertEqual(env["TEXT_MODEL_BASE_URL"], "https://openrouter.ai/api/v1")
        self.assertEqual(env["TEXT_MODEL"], "inception/mercury-2.5")
        self.assertEqual(env["TEXT_MODEL_REASONING"], "none")

    def test_a_named_provider_is_left_alone(self):
        env = server.text_model_env({"TEXT_MODEL_PROVIDER": "claude-cli"})
        self.assertEqual(env, {"TEXT_MODEL_PROVIDER": "claude-cli"})


class TestChromium(unittest.TestCase):
    def test_an_answering_cdp_url_is_used_and_never_owned(self):
        c = server.Chromium()
        with mock.patch.dict(os.environ, {"BU_CDP_URL": "http://127.0.0.1:9444"}), \
             mock.patch.object(server, "cdp_answers", return_value=True) as answers, \
             mock.patch.object(server.subprocess, "Popen") as popen:
            self.assertEqual(c.ensure(), "http://127.0.0.1:9444")
        answers.assert_called_once_with("http://127.0.0.1:9444")
        popen.assert_not_called()
        self.assertFalse(c.owned())

    def test_an_unset_cdp_url_is_never_probed(self):
        """The old default was http://127.0.0.1:9333. Whatever answers there
        is somebody else's browser unless a person named it."""
        c = server.Chromium()
        with mock.patch.dict(os.environ), \
             mock.patch.object(server, "cdp_answers", return_value=True) as answers, \
             mock.patch.object(server, "running_chromiums", return_value=[]), \
             mock.patch.object(server, "find_chromium", return_value=None):
            os.environ.pop("BU_CDP_URL", None)
            with self.assertRaises(server.BrowseError) as caught:
                c.ensure()
        # It went looking for a binary of its own instead of attaching.
        self.assertIn("playwright install chromium", str(caught.exception))
        answers.assert_not_called()

    def test_a_chromium_somebody_else_started_does_not_stop_us(self):
        """A Playwright MCP browser, or another session's own browse server,
        used to make every call here fail. Now it is noted and ignored."""
        c = server.Chromium()
        with mock.patch.dict(os.environ), \
             mock.patch.object(server, "cdp_answers", return_value=False), \
             mock.patch.object(server, "running_chromiums",
                               return_value=[(4242, "chrome --headless")]), \
             mock.patch.object(server, "find_chromium", return_value=None):
            os.environ.pop("BU_CDP_URL", None)
            with self.assertRaises(server.BrowseError) as caught:
                c.ensure()
        said = str(caught.exception)
        self.assertNotIn("One Chromium at a time", said)
        self.assertNotIn("4242", said)
        # It got all the way to looking for its own binary.
        self.assertIn("playwright install chromium", said)

    def test_a_dead_own_chromium_is_replaced_and_its_profile_removed(self):
        c = server.Chromium()
        stale = tempfile.mkdtemp(prefix="jev-browse-profile-")
        c.proc = mock.Mock(**{"poll.return_value": 9, "pid": 4242})
        c.profile = stale
        c.url = "http://127.0.0.1:1"
        with mock.patch.dict(os.environ), \
             mock.patch.object(server, "cdp_answers", return_value=False), \
             mock.patch.object(server, "running_chromiums", return_value=[]), \
             mock.patch.object(server, "find_chromium", return_value=None):
            os.environ.pop("BU_CDP_URL", None)
            with self.assertRaises(server.BrowseError):
                c.ensure()
        self.assertIsNone(c.proc)
        self.assertIsNone(c.profile)
        self.assertFalse(os.path.exists(stale))

    def test_no_binary_is_a_message(self):
        c = server.Chromium()
        with mock.patch.object(server, "cdp_answers", return_value=False), \
             mock.patch.object(server, "running_chromiums", return_value=[]), \
             mock.patch.object(server, "find_chromium", return_value=None):
            with self.assertRaises(server.BrowseError) as caught:
                c.ensure()
        self.assertIn("playwright install chromium", str(caught.exception))

    def test_the_newest_playwright_revision_is_chosen(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        for rev in ("999", "1246", "1234"):
            d = Path(tmp) / ("chromium-" + rev) / "chrome-linux64"
            d.mkdir(parents=True)
            (d / "chrome").write_text("")
        with mock.patch.dict(os.environ, {"PLAYWRIGHT_BROWSERS_PATH": tmp}):
            os.environ.pop("JEV_BROWSE_CHROMIUM", None)
            self.assertIn("chromium-1246", server.find_chromium())

    @unittest.skipIf(os.name == "nt", "a shell stand-in for the binary")
    def test_a_sandbox_refusal_says_so_and_never_falls_back(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        fake = os.path.join(tmp, "chrome")
        with open(fake, "w") as f:
            f.write('#!/bin/sh\necho "$@" > "%s/args"\n'
                    'echo "FATAL: No usable sandbox!" >&2\nexit 134\n' % tmp)
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
        c = server.Chromium()
        with mock.patch.dict(os.environ, {"JEV_BROWSE_CHROMIUM": fake}), \
             mock.patch.object(server, "cdp_answers", return_value=False), \
             mock.patch.object(server, "running_chromiums", return_value=[]):
            os.environ.pop("JEV_BROWSE_NO_SANDBOX", None)
            with self.assertRaises(server.BrowseError) as caught:
                c.ensure()
            self.assertIn("JEV_BROWSE_NO_SANDBOX=1", str(caught.exception))
            self.assertNotIn("--no-sandbox", read(os.path.join(tmp, "args")))
            self.assertFalse(c.owned())
            self.assertIsNone(c.profile)
            os.environ["JEV_BROWSE_NO_SANDBOX"] = "1"
            with self.assertRaises(server.BrowseError):
                c.ensure()
            self.assertIn("--no-sandbox", read(os.path.join(tmp, "args")))

    def test_close_is_safe_when_nothing_was_started(self):
        c = server.Chromium()
        c.close()
        c.close()
        self.assertFalse(c.owned())


if __name__ == "__main__":
    unittest.main()


class TestRunnerPlan(unittest.TestCase):
    """browse/runner.py's plan op, with the agent, the page reads and the planner faked."""

    def setUp(self):
        vendor = str(Path(__file__).resolve().parent.parent / "vendor" / "jev-ultrafast")
        # The package's __init__ imports the browser stack; the planner module needs none of
        # it, so the package is stood in by a bare one pointing at the same directory.
        package = type(sys)("jev_ultrafast")
        package.__path__ = [os.path.join(vendor, "jev_ultrafast")]
        patcher = mock.patch.dict(sys.modules, {"jev_ultrafast": package})
        patcher.start()
        self.addCleanup(patcher.stop)
        from browse import runner
        self.runner = runner

    def test_plan_runs_each_step_through_the_agent_and_reports_the_planner(self):
        runner = self.runner
        answers = ["CLICK Bicycle wheel", "DONE ok"]
        asked = []

        class Planner:
            model = "haiku"
            sessions = 0

            def ask(self, prompt, timeout=None):
                asked.append(json.loads(prompt))
                return {"result": answers.pop(0), "total_cost_usd": 0.002}

            def new_session(self):
                Planner.sessions += 1

        start = {"final_url": "https://w/start", "title": "S", "text": "", "links": [
            {"index": "1", "role": "link", "label": "Bicycle wheel"}]}
        end = {"final_url": "https://w/Bicycle_wheel", "title": "Bicycle wheel", "text": "t",
               "extracted": "Bicycle wheel", "links": []}
        state = {"decisions": [{"operation": "CLICK", "latency_ms": 500, "confidence": 0.9}],
                 "text_calls": []}
        planner = Planner()
        tabs = []

        class Tab:
            def __init__(self, url, goal=""):
                self.closed = 0
                tabs.append(self)

            def close(self):
                self.closed += 1

        fake_browser = type(sys)("jev_ultrafast.browser")
        fake_browser.Browser = Tab
        final_reads = []

        def look_in(_browser, _request, _rank_goal, screenshot=None):
            # The planner's own looks pass no screenshot flag; the read of the tab just before
            # it closes does, and it sees the page the last step left.
            if screenshot is None:
                return start
            final_reads.append(screenshot)
            return end

        with mock.patch.object(runner, "planner_for", return_value=planner) as chosen, \
                mock.patch.dict(sys.modules, {"jev_ultrafast.browser": fake_browser}), \
                mock.patch.object(runner, "_look_in", side_effect=look_in), \
                mock.patch.object(runner, "_check_done", return_value={"probability": 0.97, "latency_ms": 4}), \
                mock.patch.object(runner, "_agent_step", return_value=(dict(end, status="done", steps=1),
                                                                        state)) as step:
            out = runner.handle({"op": "plan", "goal": "Open Bicycle wheel", "start_url": "https://w/start",
                                 "extract": "h1", "plan_model": "haiku", "budget_s": 60})
        chosen.assert_called_once_with("haiku")
        self.assertEqual(step.call_args[0][1], 'Click the element labelled "Bicycle wheel".')
        self.assertEqual(asked[0]["elements"], ["link Bicycle wheel"])
        self.assertEqual(final_reads, [False])
        self.assertEqual(out["final_url"], "https://w/Bicycle_wheel")
        self.assertEqual(out["extracted"], "Bicycle wheel")
        self.assertEqual(out["status"], "done")
        self.assertEqual(out["steps"], 1)
        self.assertNotIn("links", out)
        self.assertEqual(out["plan"]["turns"], 2)
        self.assertEqual(out["timing"]["confidence"], [0.9])
        # A fresh planner conversation for the next task, whatever happened in this one.
        self.assertEqual(Planner.sessions, 1)
        # One tab for the whole call, handed to every step, closed once.
        self.assertEqual(len(tabs), 1)
        self.assertIs(step.call_args[1]["browser"], tabs[0])
        self.assertEqual(tabs[0].closed, 1)
        self.assertEqual(out["plan"]["done_checks"][0]["probability"], 0.97)
        self.assertEqual(out["timing"]["done_checks"], [{"probability": 0.97, "latency_ms": 4}])

    def test_the_default_planner_is_sonnet_and_can_be_overridden(self):
        runner = self.runner
        made = []

        class Model:
            def __init__(self, model=None, system_prompt=None):
                made.append(model)

        fake = type(sys)("jev_ultrafast.text_model_claude_standing")
        fake.StandingTextModel = Model
        with mock.patch.dict(sys.modules, {"jev_ultrafast.text_model_claude_standing": fake}), \
                mock.patch.dict(runner._PLANNERS, clear=True), \
                mock.patch.dict(os.environ, {"JEV_PLANNER_MODEL": ""}):
            runner.planner_for(None)
            with mock.patch.dict(os.environ, {"JEV_PLANNER_MODEL": "haiku"}):
                runner.planner_for(None)
            runner.planner_for(None)  # kept warm: not built twice
        self.assertEqual(made, ["sonnet", "haiku"])
