#!/usr/bin/env python3
"""A stdio MCP server with one tool, `browse`.

`browse` hands a goal to the Jev-decided browser agent (jev-ultrafast, vendored
at vendor/jev-ultrafast) and returns what the page says afterwards.
Jev chooses each step, so the calling session pays for one tool call rather
than a navigate / snapshot / click loop of its own. That is the whole point of
it: faster and cheaper browsing. It is not a security control.

The transport is MCP over stdio: JSON-RPC 2.0, one message per line, and the
methods a client needs for one tool (`initialize`, `notifications/initialized`,
`ping`, `tools/list`, `tools/call`). Standard library only, because this file
is launched by whatever `python3` the MCP client finds.

The agent itself runs in one long-lived worker process on the vendored
project's own environment (browse/runner.py), talked to in JSON lines. It used
to be a fresh process per call, and that process paid for the agent's imports,
a cold browser_harness daemon and a cold text model every single time. One
worker keeps all three warm and every call after the first reuses them. The
per-call timeout is still a hard one: the worker's whole process group is
killed when the time is up, and the next call gets a new worker.

Typing into a field needs a text model, and this server picks one rather than
leaving it to chance. A `TEXT_MODEL_API_KEY`, in the environment or in the
kit's key file, selects upstream's OpenAI-compatible helper (OpenRouter and
`inception/mercury-2.5` with reasoning off). With no key it is a warm Haiku
through the user's own `claude` login: one standing child for the life of this
server, thinking off, the trimmed field context. No key is required and none
is added.

This process owns the Chromium lifecycle, and only its own:

  * If `BU_CDP_URL` is set in the environment and answers, that browser is
    used as it is and never closed from here. Somebody chose it deliberately.
  * Otherwise a headless Chromium of this server's own is started on a free
    port with its own temporary profile, reused by every call this process
    serves, and closed when the process exits. If it has died since, a fresh
    one is started and the dead one's profile directory is removed, so
    neither browsers nor profiles pile up.
  * Other Chromiums on the box are ignored. A Playwright MCP browser, another
    Claude session's own `browse` server, an ordinary desktop Chrome: this
    process never attaches to one, never kills one, and never refuses to work
    because one exists. The default `http://127.0.0.1:9333` is not probed for
    the same reason: whatever answers there is somebody else's browser unless
    a person said otherwise by setting `BU_CDP_URL`.

Everything fails closed with a message and never hangs. A bad request, a
missing source tree, a missing key, a timeout and a crash in the agent all come
back as an `isError` result. Nothing here raises out of the read loop.

The TypeSafe key is resolved exactly as the rest of the kit resolves it
(airlock/keyfile.py, whose module docstring is where the order is written
down). It reaches the child in its environment, never on a command line, and
it is scrubbed from any text this server returns.

Environment:
  JEV_ULTRAFAST_DIR    the agent's source tree (then AIRLOCK_BROWSER_DIR;
                       default vendor/jev-ultrafast beside this file)
  JEV_ULTRAFAST_VENV   the Python environment for it (default
                       $AIRLOCK_HOME/jev-ultrafast-venv)
  BU_CDP_URL           a Chromium to attach to instead of starting one. Only
                       an explicitly set value is honoured; unset means start
                       our own, never probe the old default
  JEV_BROWSE_TIMEOUT   seconds allowed per call (default 90)
  JEV_BROWSE_CHROMIUM  the Chromium binary to start, if the Playwright cache
                       and PATH are not where it lives
  JEV_BROWSE_NO_SANDBOX  set to 1 to start Chromium with --no-sandbox. Never
                       the default and never a silent fallback: on a distro
                       whose AppArmor denies user namespaces to an unprofiled
                       binary (Ubuntu 23.10+), Chromium refuses to start, the
                       error says so, and a person decides
  JEV_BROWSE_PREWARM   set to 1 to start Chromium, the worker and the text
                       model at start-up instead of on the first call
  JEV_OFFSCREEN_MAX    how many off-viewport links a page snapshot may offer
                       (default 100; 0 is upstream's viewport-only behaviour)
  JEV_SYSTEMONE_SOCKET the airlock daemon's socket, for Jev's own decisions.
                       Resolved for you; an empty value sends every decision
                       straight over HTTPS instead
  JEV_PLANNER_MODEL    the planner for plan=true when the call names none:
                       sonnet (default) or haiku
  JEV_PAGE_TEXT_CHARS, JEV_DONE_CONFIDENCE,
  JEV_BLOCKED_CONFIDENCE
                       how Jev's own questions are asked; see
                       vendor/jev-ultrafast/jev_ultrafast/model.py and agent.py

Plan mode (plan=true) puts a warm `claude -p` child in front of Jev for an
open-ended task: it names one step per turn and the agent executes it
(vendor/jev-ultrafast/jev_ultrafast/planner.py). The child is started on the
first planned call, never before, and kept warm for the life of the worker. It
runs on the user's own `claude` login and is billed there.
"""
import collections
import glob
import json
import os
import queue
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from airlock import keyfile, paths  # noqa: E402

SERVER_NAME = "jev-kit-browse"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

RUNNER = Path(__file__).resolve().with_name("runner.py")
DEFAULT_TIMEOUT_S = 90.0
# A planned task is several agent runs and planner turns; the Wikipedia benchmark gives each
# run 180 s and the slowest planned passes took about 60.
PLAN_TIMEOUT_S = 180.0
# What the planner loop keeps back from the per-call timeout, so it stops on its own and
# returns the page it reached instead of being killed with nothing.
PLAN_MARGIN_S = 8.0
CHROMIUM_START_S = 15.0
TEXT_LIMIT_BYTES = 8 * 1024

TOOL = {
    "name": "browse",
    "description": (
        "Browse the web with the Jev-decided browser agent. Give it a goal in "
        "plain words; Jev chooses each click and keystroke, then the page is "
        "read back. Returns JSON: final_url, title, status, steps, elapsed_ms, "
        "text (visible page text, trimmed to 8 KB), plus extracted and "
        "screenshot_path when asked for. Use this instead of driving "
        "Playwright MCP tools step by step. Example: goal=\"open "
        "https://example.com and report the main heading\", extract=\"h1\". "
        "Plain `browse` is the default and the fastest: use it when the goal "
        "spells out the steps (open X, click Y, then click Z). For an "
        "open-ended task whose route you cannot spell out, set plan=true: a "
        "warm Claude planner (Sonnet at low effort by default, "
        "plan_model=\"haiku\" for the cheaper one) names each step and Jev "
        "executes it. Plan mode is slower (about 12-26 s a task) and bills "
        "the planner to the user's own claude login (a few cents a task)."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "goal": {
                "type": "string",
                "description": "What to do on the site, in plain words.",
            },
            "start_url": {
                "type": "string",
                "description": "Where to start. Optional when the goal contains a URL.",
            },
            "extract": {
                "type": "string",
                "description": "A CSS selector whose text is returned as `extracted`, "
                               "in addition to the page text.",
            },
            "screenshot": {
                "type": "boolean",
                "default": False,
                "description": "Write a PNG of the final page and return its path.",
            },
            "links": {
                "type": "boolean",
                "default": False,
                "description": "Return `links`: the final page's element table, the same "
                               "on-screen and goal-ranked off-screen candidates Jev chose "
                               "between. Use it to decide the next step.",
            },
            "rank_goal": {
                "type": "string",
                "description": "Rank off-screen links against this text instead of `goal`. "
                               "Give the whole task here when `goal` is only the next step.",
            },
            "plan": {
                "type": "boolean",
                "default": False,
                "description": "Put a warm Claude planner in front of Jev for an open-ended "
                               "task. Slower and billed to the user's claude login; leave it "
                               "off when the goal already names the steps.",
            },
            "plan_model": {
                "type": "string",
                "enum": ["sonnet", "haiku"],
                "description": "The planner's model when plan=true. Default sonnet (low "
                               "effort, thinking off), or JEV_PLANNER_MODEL.",
            },
        },
        "required": ["goal"],
        "additionalProperties": False,
    },
}


class BrowseError(Exception):
    """A failure with a message fit to hand back to the caller."""


class BrowseTimeout(BrowseError):
    """The per-call time ran out and the agent was killed."""


def log(message):
    # stdout belongs to the protocol. Everything else goes to stderr.
    try:
        sys.stderr.write("browse: %s\n" % message)
        sys.stderr.flush()
    except Exception:
        pass


# --- configuration -----------------------------------------------------------

def clone_dir():
    """The jev-ultrafast source tree.

    The default is the copy vendored in this same tree, found relative to this
    file rather than to a working directory. That resolves to the checkout when
    the server is run from one, and to $AIRLOCK_HOME/releases/<sha>/vendor/
    jev-ultrafast when install/deploy.sh exported it, because a release is a
    plain `git archive` of the commit and carries vendor/ with it."""
    for var in ("JEV_ULTRAFAST_DIR", "AIRLOCK_BROWSER_DIR"):
        value = os.environ.get(var)
        if value:
            return Path(os.path.expanduser(value))
    return REPO_ROOT / "vendor" / "jev-ultrafast"


def venv_dir():
    """Where the vendored project's dependencies live.

    Outside the release on purpose. A release is an immutable export and
    deploy.sh prunes old ones, so a .venv inside vendor/jev-ultrafast would be
    re-synced on every deploy and thrown away again. One venv under
    $AIRLOCK_HOME is synced when uv.lock changes and shared by every release
    and by the checkout. It holds the third-party dependencies only; the
    project itself is imported from whichever tree clone_dir() resolved."""
    value = os.environ.get("JEV_ULTRAFAST_VENV")
    if value:
        return Path(os.path.expanduser(value))
    return paths.install_home() / "jev-ultrafast-venv"


def resolve_clone():
    clone = clone_dir()
    if not (clone / "jev_ultrafast" / "agent.py").is_file():
        raise BrowseError(
            "the jev-ultrafast source was not found at %s. It is vendored at "
            "vendor/jev-ultrafast in the jev-kit checkout (%s); point "
            "JEV_ULTRAFAST_DIR at a copy if yours lives elsewhere."
            % (clone, REPO_ROOT)
        )
    return clone


def resolve_key():
    try:
        key = keyfile.get_api_key()
    except Exception:
        key = None
    if not key:
        raise BrowseError(
            "no TypeSafe key. Put a TYPESAFE_API_KEY=... line in ~/.config/jev-kit/env "
            "(mode 600), or set TYPESAFE_API_KEY in this server's environment. "
            "Jev decides every step, so nothing can run without it."
        )
    return key


def call_timeout_s(plan=False):
    default = PLAN_TIMEOUT_S if plan else DEFAULT_TIMEOUT_S
    try:
        value = float(os.environ.get("JEV_BROWSE_TIMEOUT", ""))
    except ValueError:
        return default
    return value if value > 0 else default


def state_dir():
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(os.path.expanduser(base)) / "jev-kit" / "browse"


def runner_command(clone):
    """The interpreter that runs browse/runner.py.

    The shared venv first, because it survives a deploy and starts faster than
    anything that touches the network. A .venv inside the tree next, so a
    JEV_ULTRAFAST_DIR pointed at somebody's own synced clone still works. `uv
    run` last, which makes a tree that was never synced work at all."""
    candidates = []
    for base in (venv_dir(), clone / ".venv"):
        candidates += [base / "bin" / "python", base / "Scripts" / "python.exe"]
    for python in candidates:
        if python.is_file():
            return [str(python), str(RUNNER)]
    uv = shutil.which("uv")
    if uv:
        return [uv, "run", "--project", str(clone), "python", str(RUNNER)]
    raise BrowseError(
        "no Python environment for the browser agent: neither %s nor %s/.venv "
        "exists and `uv` is not on PATH. Run browser/install.sh, or install uv "
        "(https://docs.astral.sh/uv/)." % (venv_dir(), clone)
    )


# --- the worker process ------------------------------------------------------

def _kill_group(proc):
    try:
        if hasattr(os, "killpg"):
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except Exception:
        pass
    try:
        # communicate, not wait: it reaps the child and closes our pipe ends.
        proc.communicate(timeout=5)
    except Exception:
        pass


class Worker:
    """One long-lived browse/runner.py child, talked to in JSON lines.

    It used to be a fresh process per call. That paid for the agent's imports,
    a cold browser_harness daemon and, worst of all, a cold text model on every
    single call. One worker for the life of the server keeps all three warm.

    What a per-call process gave for free has to be kept by hand here:

      * the per-call timeout still kills the whole process group, and the
        worker is then gone, so the next call starts a clean one;
      * stdout and stderr are drained by reader threads, because nobody is
        waiting on communicate() to empty the pipes for us;
      * a worker that died between calls is simply replaced.
    """

    STDERR_TAIL = 40

    def __init__(self, clone, env, cdp_url):
        self.clone = clone
        self.cdp_url = cdp_url
        self.proc = None
        self.calls = 0
        self._lines = queue.Queue()
        self._stderr = collections.deque(maxlen=self.STDERR_TAIL)
        # The shared venv carries the dependencies, not jev_ultrafast itself,
        # so the child is told where the source is. cwd is not enough:
        # sys.path[0] is runner.py's own directory, which is this repo's
        # browse/.
        self.env = dict(env)
        existing = self.env.get("PYTHONPATH")
        self.env["PYTHONPATH"] = str(clone) + (os.pathsep + existing if existing else "")

    def start(self):
        try:
            self.proc = subprocess.Popen(
                runner_command(self.clone), cwd=str(self.clone), env=self.env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, start_new_session=True,
            )
        except OSError as exc:
            raise BrowseError("could not start the browser agent: %s" % exc)
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()
        return self

    def _read_stdout(self):
        try:
            for line in self.proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except ValueError:
                    # Not ours. Anything the agent prints is supposed to go to
                    # stderr; a stray line must not be mistaken for a result.
                    self._stderr.append(line)
                    continue
                if isinstance(message, dict):
                    self._lines.put(message)
        except Exception:
            pass
        finally:
            self._lines.put(None)  # EOF: the worker is gone

    def _read_stderr(self):
        try:
            for line in self.proc.stderr:
                self._stderr.append(line.rstrip("\n"))
        except Exception:
            pass

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def tail(self, lines=3):
        return " | ".join(list(self._stderr)[-lines:])

    def ask(self, request, timeout_s):
        """One request in, one result dict out. Raises BrowseError or
        BrowseTimeout, and the worker is dead by the time either is raised."""
        if not self.alive():
            raise BrowseError("the browser agent is not running. %s" % self.tail())
        try:
            self.proc.stdin.write(json.dumps(request) + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            self.stop()
            raise BrowseError("the browser agent stopped listening (%s). %s"
                              % (exc, self.tail()))
        try:
            message = self._lines.get(timeout=max(timeout_s, 0.01))
        except queue.Empty:
            self.stop()
            raise BrowseTimeout(
                "timed out after %.0f s (JEV_BROWSE_TIMEOUT). The agent was stopped; "
                "try a narrower goal or a start_url closer to it." % timeout_s
            )
        if message is None:
            returncode = self.proc.poll()
            self.stop()
            raise BrowseError("the browser agent exited with status %s and no result. %s"
                              % (returncode, self.tail()))
        self.calls += 1
        if message.get("error"):
            raise BrowseError(str(message["error"]))
        return message

    def stop(self):
        proc, self.proc = self.proc, None
        if proc is None:
            return
        try:
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
        except Exception:
            pass
        if proc.poll() is None:
            try:
                if hasattr(os, "killpg"):
                    os.killpg(proc.pid, signal.SIGTERM)
                else:
                    proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                _kill_group(proc)
        for pipe in (proc.stdout, proc.stderr):
            try:
                if pipe is not None and not pipe.closed:
                    pipe.close()
            except Exception:
                pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass


# --- Chromium ----------------------------------------------------------------

def cdp_answers(url, timeout_s=2.0):
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/json/version", timeout=timeout_s) as r:
            return r.status == 200
    except Exception:
        return False


def _revision(path):
    m = re.search(r"chromium-(\d+)", path)
    return int(m.group(1)) if m else 0


def find_chromium():
    explicit = os.environ.get("JEV_BROWSE_CHROMIUM")
    if explicit:
        return os.path.expanduser(explicit)
    roots = [os.environ.get("PLAYWRIGHT_BROWSERS_PATH"),
             str(Path.home() / ".cache" / "ms-playwright"),
             str(Path.home() / "Library" / "Caches" / "ms-playwright")]
    for root in filter(None, roots):
        found = []
        for pattern in ("chromium-*/chrome-linux*/chrome",
                        "chromium-*/chrome-mac*/Chromium.app/Contents/MacOS/Chromium"):
            found.extend(glob.glob(os.path.join(os.path.expanduser(root), pattern)))
        if found:
            return max(found, key=_revision)
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        path = shutil.which(name)
        if path:
            return path
    return None


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def running_chromiums():
    """[(pid, command line)] from `pgrep -a chrom`. Empty when pgrep is absent."""
    try:
        out = subprocess.run(["pgrep", "-a", "chrom"], capture_output=True, text=True,
                             timeout=5).stdout
    except Exception:
        return []
    rows = []
    for line in out.splitlines():
        pid, _, cmd = line.strip().partition(" ")
        if pid.isdigit():
            rows.append((int(pid), cmd))
    return rows


class Chromium:
    """The one headless Chromium this server process may own."""

    def __init__(self):
        self.proc = None
        self.url = None
        self.profile = None

    def owned(self):
        return self.proc is not None and self.proc.poll() is None

    def _foreign(self):
        rows = []
        own = self.proc.pid if self.owned() else None
        for pid, cmd in running_chromiums():
            if own is not None:
                try:
                    if os.getpgid(pid) == own:
                        continue
                except OSError:
                    continue
            rows.append((pid, cmd))
        return rows

    def ensure(self):
        """The CDP URL to use, starting this server's own Chromium if needed.

        Never attaches to, and never kills, a browser this process did not
        start. The one exception is an explicitly set `BU_CDP_URL`, which is a
        person naming a browser to share."""
        if self.owned() and cdp_answers(self.url):
            return self.url
        if self.proc is not None:
            # Ours, but gone or unreachable. close() reaps it and removes its
            # profile directory, so a restart cannot leave either behind.
            log("this server's Chromium is no longer answering; starting a fresh one")
        self.close()
        configured = os.environ.get("BU_CDP_URL")
        if configured and cdp_answers(configured):
            return configured
        # Anything else running is somebody else's: a Playwright MCP browser,
        # another session's browse server, a desktop Chrome. Noted, then
        # ignored. The old refusal made every call fail whenever one existed.
        foreign = self._foreign()
        if foreign:
            log("%d other Chromium process(es) on this box; starting our own anyway"
                % len(foreign))
        binary = find_chromium()
        if not binary or not os.path.isfile(binary):
            raise BrowseError(
                "no Chromium binary found. Install one with `npx playwright install "
                "chromium`, or set JEV_BROWSE_CHROMIUM to a Chromium or Chrome binary."
            )
        port = free_port()
        self.profile = tempfile.mkdtemp(prefix="jev-browse-profile-")
        command = [binary, "--headless=new", "--remote-debugging-port=%d" % port,
                   "--user-data-dir=%s" % self.profile, "--no-first-run",
                   "--no-default-browser-check"]
        if os.environ.get("JEV_BROWSE_NO_SANDBOX") == "1":
            command.append("--no-sandbox")
        command.append("about:blank")
        stderr_path = os.path.join(self.profile, "chromium-stderr.log")
        try:
            with open(stderr_path, "wb") as stderr:
                proc = self.proc = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=stderr, start_new_session=True,
                )
        except OSError as exc:
            self.close()
            raise BrowseError("could not start Chromium (%s): %s" % (binary, exc))
        self.url = "http://127.0.0.1:%d" % port
        deadline = time.monotonic() + CHROMIUM_START_S
        while time.monotonic() < deadline and proc.poll() is None:
            if cdp_answers(self.url, timeout_s=1.0):
                log("started headless Chromium pid %d on %s" % (proc.pid, self.url))
                return self.url
            time.sleep(0.1)
        try:
            with open(stderr_path, "r", errors="replace") as f:
                said = f.read(64 * 1024)
        except OSError:
            said = ""
        self.close()
        if "No usable sandbox" in said:
            raise BrowseError(
                "Chromium (%s) refused to start: no usable sandbox. On Ubuntu 23.10+ "
                "AppArmor denies user namespaces to a binary with no profile. Give the "
                "binary an AppArmor profile, or accept an unsandboxed browser by setting "
                "JEV_BROWSE_NO_SANDBOX=1 in this server's `env`. See browse/README.md."
                % binary)
        raise BrowseError("Chromium (%s) did not open its CDP port within %.0f s."
                          % (binary, CHROMIUM_START_S))

    def close(self):
        proc, self.proc = self.proc, None
        if proc is not None and proc.poll() is None:
            try:
                if hasattr(os, "killpg"):
                    os.killpg(proc.pid, signal.SIGTERM)
                else:
                    proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                _kill_group(proc)
        profile, self.profile = self.profile, None
        if profile:
            shutil.rmtree(profile, ignore_errors=True)
        self.url = None


# --- the tool ----------------------------------------------------------------

_URL_IN_GOAL = re.compile(r"https?://[^\s<>\"'`]+")


def parse_arguments(args):
    if not isinstance(args, dict):
        raise BrowseError("arguments must be an object with a `goal`.")
    unknown = sorted(set(args) - set(TOOL["inputSchema"]["properties"]))
    if unknown:
        raise BrowseError("unknown argument(s): %s. `browse` takes goal, start_url, "
                          "extract, screenshot, links, rank_goal, plan and plan_model."
                          % ", ".join(unknown))
    goal = args.get("goal")
    if not isinstance(goal, str) or not goal.strip():
        raise BrowseError("`goal` is required and must be a non-empty string.")
    for name in ("start_url", "extract", "rank_goal"):
        if args.get(name) is not None and not isinstance(args[name], str):
            raise BrowseError("`%s` must be a string." % name)
    screenshot = args.get("screenshot", False)
    if not isinstance(screenshot, bool):
        raise BrowseError("`screenshot` must be true or false.")
    links = args.get("links", False)
    if not isinstance(links, bool):
        raise BrowseError("`links` must be true or false.")
    plan = args.get("plan", False)
    if not isinstance(plan, bool):
        raise BrowseError("`plan` must be true or false.")
    plan_model = args.get("plan_model")
    if plan_model is not None and plan_model not in ("sonnet", "haiku"):
        raise BrowseError("`plan_model` must be \"sonnet\" or \"haiku\".")
    start_url = (args.get("start_url") or "").strip()
    if not start_url:
        m = _URL_IN_GOAL.search(goal)
        if not m:
            raise BrowseError("give `start_url`, or put an http(s) URL in the goal: "
                              "the agent needs a page to start on.")
        start_url = m.group(0).rstrip(".,;:!?)]}")
    if not re.match(r"https?://", start_url, re.IGNORECASE):
        raise BrowseError("`start_url` must be an http:// or https:// URL.")
    return {"goal": goal.strip(), "start_url": start_url,
            "extract": (args.get("extract") or "").strip() or None,
            "screenshot": screenshot, "links": links,
            "rank_goal": (args.get("rank_goal") or "").strip() or None,
            "plan": plan, "plan_model": plan_model}


def trim_text(text, limit=TEXT_LIMIT_BYTES):
    raw = (text or "").encode("utf-8")
    if len(raw) <= limit:
        return text or "", False
    return raw[:limit].decode("utf-8", errors="ignore"), True


def text_model_env(env):
    """Decide how TYPE_TEXT gets its value, and say so in the environment.

    Two supported ways, and the choice is made here rather than in the agent
    so that one place explains it:

      * `TEXT_MODEL_API_KEY`, from the environment or from the kit's own key
        file, means the OpenAI-compatible helper upstream ships with. The
        defaults are upstream's documented ones: OpenRouter and
        `inception/mercury-2.5` with reasoning off.
      * Otherwise a warm Haiku through the user's normal `claude` login: one
        standing child for the life of this server, thinking off, the trimmed
        field context. No key, nothing to configure, and it is the default.

    An explicit `TEXT_MODEL_PROVIDER` in the environment is left alone: a
    person who named a provider gets that provider."""
    if env.get("TEXT_MODEL_PROVIDER"):
        return env
    key = env.get("TEXT_MODEL_API_KEY") or keyfile.get_env_value("TEXT_MODEL_API_KEY")
    if key:
        env["TEXT_MODEL_API_KEY"] = key
        env.setdefault("TEXT_MODEL_BASE_URL", "https://openrouter.ai/api/v1")
        env.setdefault("TEXT_MODEL", "inception/mercury-2.5")
        env.setdefault("TEXT_MODEL_REASONING", "none")
        return env
    env["TEXT_MODEL_PROVIDER"] = "claude-standing"
    # Both measured in the spike, both the default there too. Set explicitly
    # so the worker's configuration is legible in its own environment.
    env.setdefault("MAX_THINKING_TOKENS", "0")
    env.setdefault("TEXT_MODEL_CONTEXT", "trimmed")
    return env


def prewarm_wanted():
    """Whether to warm the whole chain at start-up instead of on first use.

    Off by default, and that is a measurement rather than caution. Warming
    buys about a second on the first call and nothing after it, and it costs
    a headless Chromium and a standing Haiku child in every session that
    merely has this server configured. A session that is definitely going to
    browse sets `JEV_BROWSE_PREWARM=1` and gets that second back."""
    return (os.environ.get("JEV_BROWSE_PREWARM") or "").strip().lower() in \
        ("1", "yes", "on", "true")


class Browse:
    def __init__(self):
        self.chromium = Chromium()
        self.calls = 0
        self.daemon_used = False
        self.worker = None
        self.lock = threading.RLock()

    def daemon_name(self):
        # browser_harness keeps one daemon per BU_NAME. A name of our own
        # keeps this server off a daemon some other session attached to a
        # different browser.
        return "jevkit-browse-%d" % os.getpid()

    def child_env(self, key, cdp_url):
        env = dict(os.environ)
        env["TYPESAFE_API_KEY"] = key
        env["BU_CDP_URL"] = cdp_url
        env.pop("BU_CDP_WS", None)
        env["BU_NAME"] = self.daemon_name()
        # Jev's own decisions can go through airlock's warm daemon, which
        # already holds pooled keep-alive connections to the same endpoint.
        # Resolving the path here keeps the vendored agent free of any import
        # from this kit. An empty value in the environment turns it off and
        # sends every decision straight over HTTPS.
        if "JEV_SYSTEMONE_SOCKET" not in env:
            try:
                env["JEV_SYSTEMONE_SOCKET"] = paths.runtime_socket()
            except Exception:
                pass
        return text_model_env(env)

    def ensure_chromium(self):
        """`Chromium.ensure()` under this server's lock.

        The background prewarm made this necessary: two threads in `ensure()`
        at once each started a browser, and only the second one was ever
        tracked or closed. One lock, one browser."""
        with self.lock:
            return self.chromium.ensure()

    # --- the worker ----------------------------------------------------------

    def ask(self, request, env, clone, timeout_s):
        """Send one request to the worker, starting or replacing it first.

        The seam every call goes through. A worker that died, or one started
        against a Chromium that has since been restarted, is replaced rather
        than reused."""
        with self.lock:
            worker, wanted_cdp = self.worker, env.get("BU_CDP_URL")
            # A request with no browser in it (stop_daemon) takes whatever
            # worker is up; a browse call needs one on the right Chromium.
            if worker is not None and (
                not worker.alive() or worker.clone != clone
                or (wanted_cdp is not None and worker.cdp_url != wanted_cdp)
            ):
                worker.stop()
                self.worker = worker = None
            if worker is None:
                log("starting the browser agent worker")
                self.worker = worker = Worker(clone, env, env.get("BU_CDP_URL")).start()
            try:
                return worker.ask(request, timeout_s)
            finally:
                if not worker.alive():
                    self.worker = None

    def prewarm(self):
        """Pay the cold starts before the first call asks for them.

        Chromium, the worker process, the agent's imports, the harness daemon
        and the text model's own child. Never raises: a prewarm that fails
        just leaves the first real call to do the work, exactly as before."""
        try:
            clone = resolve_clone()
            key = resolve_key()
            cdp_url = self.ensure_chromium()
            self.daemon_used = True
            result = self.ask({"op": "warm"}, self.child_env(key, cdp_url), clone, 60)
            log("prewarmed: %s" % ", ".join(result.get("warmed") or ["nothing"]))
        except Exception as exc:
            log("prewarm skipped: %s" % exc)

    def call(self, args):
        started = time.monotonic()
        params = parse_arguments(args)
        deadline = started + call_timeout_s(params["plan"])
        clone = resolve_clone()
        key = resolve_key()
        try:
            cdp_url = self.ensure_chromium()
            request = dict(params, op="plan" if params["plan"] else "browse")
            if params["screenshot"]:
                directory = state_dir()
                directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                self.calls += 1
                request["screenshot_path"] = str(directory / (
                    "browse-%s-%d-%d.png" % (time.strftime("%Y%m%d-%H%M%S"),
                                             os.getpid(), self.calls)))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BrowseTimeout("timed out after %.0f s (JEV_BROWSE_TIMEOUT) before "
                                    "the agent could start." % call_timeout_s(params["plan"]))
            if params["plan"]:
                request["budget_s"] = max(remaining - PLAN_MARGIN_S, 1.0)
            # The daemon starts on the worker's first use, so a call that
            # raises from here on still leaves one to stop.
            self.daemon_used = True
            result = self.ask(request, self.child_env(key, cdp_url), clone, remaining)
        except BrowseTimeout:
            # The killed agent leaves its tab behind. A browser we own is
            # cheaper to restart than to clean; one we do not own is left be.
            self.chromium.close()
            raise
        except BrowseError as exc:
            raise BrowseError(str(exc).replace(key, "[REDACTED]"))
        text, truncated = trim_text(result.get("text"))
        out = {
            "final_url": result.get("final_url"),
            "title": result.get("title"),
            "status": result.get("status"),
            "steps": result.get("steps"),
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "text": text,
        }
        if truncated:
            out["text_truncated"] = True
        if params["extract"]:
            out["extracted"] = trim_text(result.get("extracted"))[0]
        if params["screenshot"]:
            out["screenshot_path"] = result.get("screenshot_path")
        if params["links"]:
            out["links"] = result.get("links") or []
        if result.get("reason"):
            out["reason"] = result["reason"]
        if result.get("plan"):
            out["plan"] = result["plan"]
        if result.get("timing"):
            out["timing"] = result["timing"]
        return json.loads(json.dumps(out).replace(key, "[REDACTED]"))

    def shutdown(self):
        if self.daemon_used:
            # Stop the harness daemon whenever one may exist, whoever owns the
            # browser. It outlives an external browser we never close, so
            # ownership is the wrong test: a call was made, so stop it.
            try:
                clone = resolve_clone()
                env = dict(os.environ, BU_NAME=self.daemon_name())
                self.ask({"op": "stop_daemon"}, env, clone, 10)
            except Exception:
                pass
        with self.lock:
            worker, self.worker = self.worker, None
        if worker is not None:
            worker.stop()
        self.chromium.close()


# --- JSON-RPC ----------------------------------------------------------------

def _result(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def tool_result(text, is_error=False):
    return {"content": [{"type": "text", "text": text}], "isError": bool(is_error)}


class Server:
    def __init__(self, browse=None):
        self.browse = browse or Browse()
        self.prewarming = None

    def start_prewarm(self):
        """Warm the whole chain in the background while the client finishes
        its handshake. The first `browse` call is otherwise the one that pays
        for Chromium, the worker's imports, the harness daemon and the text
        model's cold start, all at once."""
        if self.prewarming is not None or not prewarm_wanted():
            return
        if not hasattr(self.browse, "prewarm"):
            return
        self.prewarming = threading.Thread(target=self.browse.prewarm, daemon=True)
        self.prewarming.start()

    def handle(self, msg):
        """One JSON-RPC message in, one response out, or None for a
        notification. Never raises."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" \
                or not isinstance(msg.get("method"), str):
            msg_id = msg.get("id") if isinstance(msg, dict) else None
            return _error(msg_id, -32600, "Invalid Request")
        method, msg_id = msg["method"], msg.get("id")
        if "id" not in msg:
            return None  # a notification: notifications/initialized, cancelled, ...
        params = msg.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return _error(msg_id, -32602, "params must be an object")
        try:
            if method == "initialize":
                wanted = params.get("protocolVersion")
                version = wanted if wanted in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
                self.start_prewarm()
                return _result(msg_id, {
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                })
            if method == "ping":
                return _result(msg_id, {})
            if method == "tools/list":
                return _result(msg_id, {"tools": [TOOL]})
            if method == "tools/call":
                if params.get("name") != TOOL["name"]:
                    return _error(msg_id, -32602, "Unknown tool: %r" % (params.get("name"),))
                return _result(msg_id, self.call_tool(params.get("arguments") or {}))
            return _error(msg_id, -32601, "Method not found: %s" % method)
        except Exception as exc:
            return _error(msg_id, -32603, "Internal error: %s" % type(exc).__name__)

    def call_tool(self, args):
        try:
            return tool_result(json.dumps(self.browse.call(args), ensure_ascii=False))
        except BrowseError as exc:
            return tool_result("browse failed: %s" % exc, is_error=True)
        except Exception as exc:
            return tool_result("browse failed: unexpected %s" % type(exc).__name__,
                               is_error=True)

    def handle_line(self, line):
        """A line of input in, a list of responses out."""
        try:
            msg = json.loads(line)
        except Exception:
            return [_error(None, -32700, "Parse error")]
        if isinstance(msg, list):
            if not msg:
                return [_error(None, -32600, "Invalid Request")]
            return [r for r in (self.handle(m) for m in msg) if r is not None]
        response = self.handle(msg)
        return [] if response is None else [response]

    def serve(self, stdin, stdout):
        try:
            for line in stdin:
                if not line.strip():
                    continue
                for response in self.handle_line(line):
                    # ASCII escapes on the wire: a lone surrogate from a page,
                    # or any non-ASCII text on a stdout that is not UTF-8
                    # (cp1252 on Windows), raised here and ended the server.
                    stdout.write(json.dumps(response) + "\n")
                    stdout.flush()
        except (KeyboardInterrupt, BrokenPipeError):
            pass
        finally:
            try:
                self.browse.shutdown()
            except Exception:
                pass


def main():
    server = Server()

    def stop(_signum, _frame):
        raise KeyboardInterrupt()

    for sig in (signal.SIGTERM, getattr(signal, "SIGHUP", None)):
        if sig is not None:
            try:
                signal.signal(sig, stop)
            except Exception:
                pass
    server.serve(sys.stdin, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
