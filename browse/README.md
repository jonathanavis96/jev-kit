# browse: one MCP tool over the Jev-decided browser agent

`browse` is a stdio MCP server with a single tool. A session hands it a goal
in plain words. Jev chooses each click and keystroke, and the page comes back
as JSON. The session pays for one tool call, not for a navigate, snapshot and
click loop of its own.

Jev is here to make browsing faster and cheaper. It is not a security control,
and nothing in this directory claims to be one.

It sits beside the Playwright MCP servers and removes none of them. Airlock's
`R11-browse-via-jev` rule denies a Playwright MCP browsing call and names this
tool. [docs/rules.md](../docs/rules.md#r11-browse-via-jev-a-playwright-mcp-call-is-pointed-at-browse)
has that half.

## Install

The agent it drives is vendored at `vendor/jev-ultrafast`, so a checkout
already has it. What it still needs is that project's Python environment,
which [browser/](../browser/README.md) syncs.

```bash
browser/install.sh        # the agent's dependencies, once
browse/install.sh         # checks both, runs a real handshake, prints the block
```

`install/install.sh --browse-mcp` runs the second one, and `--all` includes it.
It is not part of the default set.

Nothing here edits `~/.claude.json`. The installer prints a block like this
one for you to add under `mcpServers`, with the absolute path on your machine:

```json
{
  "mcpServers": {
    "browse": {
      "type": "stdio",
      "command": "/home/you/code/jev-kit/browse/server.py",
      "args": [],
      "env": {}
    }
  }
}
```

`install/doctor.sh` runs the server through `initialize` and `tools/list` over
a real pipe and reports PASS. With no agent environment it reports a skip.

## The tool

| Input | Type | |
|---|---|---|
| `goal` | string, required | What to do, in plain words. |
| `start_url` | string | Where to start. Optional when the goal contains an `http(s)` URL. |
| `extract` | string | A CSS selector. The text of every match comes back as `extracted`. |
| `screenshot` | boolean, default false | Write a PNG of the final page and return its path. |
| `links` | boolean, default false | Return `links`, the final page's element table: the same candidates Jev chose between. |
| `rank_goal` | string | Rank off-screen links against this text instead of `goal`. |
| `plan` | boolean, default false | Put a warm Claude planner in front of Jev. For open-ended tasks only; see [Plan mode](#plan-mode). |
| `plan_model` | `sonnet` or `haiku` | The planner's model. Default `sonnet`, or `JEV_PLANNER_MODEL`. |

The result is JSON text:

| Field | |
|---|---|
| `final_url`, `title` | Where the agent ended up. |
| `status` | `done` when Jev judged the goal met, `blocked` when it could not go on. |
| `steps` | How many decisions Jev made. |
| `elapsed_ms` | Wall time for the whole call, Chromium start included. |
| `text` | Visible text of the final page, trimmed to 8 KB. `text_truncated` is set when it was cut. |
| `extracted` | Text at `extract`, only when you gave one. |
| `screenshot_path` | Only when asked for. A PNG under `$XDG_STATE_HOME/jev-kit/browse/`, else `~/.local/state/jev-kit/browse/`. |
| `timing` | Where the time went: `decisions`, `ops`, `jev_ms`, `confidence`, `rechecks`, `text_ms`, `agent_ms`, `total_ms`, `jev_transport`. |
| `plan` | Only with `plan: true`: the planner's `model`, `turns`, `finds`, `transcript`, `planner_ms`, `browse_ms`, `tokens` and `cost_usd`. |

`timing.ops` is one entry per decision Jev made, not per action executed, so a
decision the executor threw away because the page moved under it shows up there
and nowhere else. That is the first thing to look at when a call takes longer
than its step count explains.

Only `http://` and `https://` start pages are accepted.

A real run on the development box, 2026-09-23, driven over stdio:

```text
goal:    "open https://example.com and report the main heading"
extract: "h1"
```

```json
{
  "final_url": "https://example.com/",
  "title": "Example Domain",
  "status": "done",
  "steps": 1,
  "elapsed_ms": 1392,
  "text": "Example Domain\n\nThis domain is for use in documentation examples without needing permission. Avoid use in operations.\n\nLearn more",
  "extracted": "Example Domain",
  "timing": {"decisions": 1, "ops": ["DONE"], "jev_ms": [431], "text_ms": [],
             "agent_ms": 435, "total_ms": 977, "jev_transport": ["daemon"]}
}
```

That is one run, so treat the 1.4 seconds as an example and not a benchmark.
It is the first call of a server, so it includes starting Chromium and the
worker.

## How it runs

`server.py` is standard library only. It speaks JSON-RPC 2.0 over stdio:
`initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`.

The agent runs in one long-lived worker process, `runner.py`, on the vendored
project's own environment. That environment sits at
`$AIRLOCK_HOME/jev-ultrafast-venv`, outside any release, and holds the
dependencies only; `jev_ultrafast` is imported from whichever source tree the
server resolved, which the worker is told through `PYTHONPATH`. A `.venv`
inside the source tree is used if one is there, and `uv run` is the last
resort.

One worker for the life of the server, not one per call. A fresh process per
call paid for the agent's imports, a cold `browser_harness` daemon and a cold
text model every single time, and that was most of the fourteen seconds the
README's own Wikipedia example used to take. The timeout is still a hard one:
the worker's whole process group is killed when the time is up, and the next
call gets a new worker. So does a worker that died on its own, or one that was
started against a Chromium which has since been replaced.

`JEV_BROWSE_PREWARM=1` starts Chromium, the worker and the text model when the
server starts rather than when the first call arrives. It is worth about a
second on that first call and nothing after it, so it is off by default: a
session that merely has this server configured should not be paying for a
headless Chromium it never uses. Turn it on for a session you know will browse.

## Typing into a field

`TYPE_TEXT` needs a model to write the value, and this server picks one rather
than leaving it to chance.

| | when | what runs |
|---|---|---|
| Warm Haiku | the default, no key anywhere | One standing `claude` child on your ordinary login, thinking off, trimmed field context. It lives as long as the server does. |
| OpenAI-compatible | `TEXT_MODEL_API_KEY` is set | Upstream's helper, defaulting to OpenRouter and `inception/mercury-2.5` with reasoning off. |

The key can be an ordinary environment variable, or a `TEXT_MODEL_API_KEY=...`
line in the same key file the TypeSafe key lives in (`~/.config/jev-kit/env`,
and `airlock/keyfile.py` is where the resolution order is written down). It is
optional: nothing here requires one, and the kit does not add one.

Measured on this box, same goal, five calls in one session: warm Haiku writes a
field value in 0.70 to 0.86 s. Upstream reports Mercury doing the same job in
roughly 0.35 s, so a key is worth having if you already have one and is not
worth getting if you do not. `TEXT_MODEL_PROVIDER` set by hand overrides both,
and `vendor/jev-ultrafast/SPIKE-NOTES.md` has the full measurements.

Jev's own decisions go through airlock's warm daemon when it is running, which
saves about 70 ms on the first decision of a worker and about 25 ms after it,
and fall back to a direct HTTPS call when it is not.

The server owns the Chromium lifecycle, and only its own.

- If you set `BU_CDP_URL` and something answers there, it attaches to that and
  never closes it. This is how you hand it a browser that is already logged
  in. Unset means unset: the old `http://127.0.0.1:9333` default is not probed
  any more, because whatever answers there is somebody else's browser unless
  you said otherwise.
- Otherwise it starts a headless Chromium of its own on a free port, with its
  own temporary profile. Every call this server process serves reuses it, and
  it closes when the server exits. If it has died since, the next call starts
  a fresh one and removes the dead one's profile directory.
- Other Chromiums on the box are ignored. A Playwright MCP browser, a second
  Claude session running its own copy of this server, an ordinary desktop
  Chrome: none of them is attached to, none is killed, and none stops a call.
  Until 2026-09-23 any one of them made every call fail, which taught agents
  to go back to Playwright.

## When it fails

It fails closed with a message and it never hangs. Every failure below comes
back as an `isError` result, and the read loop keeps going.

| What went wrong | What the message names |
|---|---|
| No agent source | `vendor/jev-ultrafast` and `JEV_ULTRAFAST_DIR` |
| No TypeSafe key | `~/.config/jev-kit/env` |
| The call ran past `JEV_BROWSE_TIMEOUT` (default 90 s) | the timeout. The agent is killed, and a Chromium this server owns is restarted. |
| No Chromium binary anywhere | `npx playwright install chromium` and `JEV_BROWSE_CHROMIUM` |
| Chromium has no usable sandbox | `JEV_BROWSE_NO_SANDBOX`, see below |
| Our Chromium exited during the call, twice | the binary and its own last `FATAL` line. The first exit is retried on a fresh browser, from the next-newest installed binary when there is one. |
| A bad argument | the argument |

### `blocked` hands the browser back

`status: blocked` means Jev gave up on the goal. It chooses one action at a
time, out of what it can see in the viewport, so a task that needs several
hops is beyond it. A goal written as explicit steps gets further than a goal
written as an outcome. "Open the article, click the link to X, then click the
link to Y, scroll if the link is not in view" is the shape that works.

When it is beyond `browse` anyway, airlock notices. A PostToolUse hook,
`hooks/airlock_browse_unlock.py`, records a `blocked` result and an errored
call alike, and `R11-browse-via-jev` then warns instead of denying Playwright
MCP for the next thirty minutes of that session. There is nothing to do by
hand: try `browse` first, and a failure hands the browser back.
[docs/rules.md](../docs/rules.md#when-browse-gives-up-r11-stands-aside) has
the detail, including what a subagent shares with its parent.

Key resolution is the same as everywhere else in the kit, and the order is
written down once, in the module docstring of `airlock/keyfile.py`. The child
gets the key in its environment and never on a command line. It is scrubbed
from anything the tool returns.

## The sandbox

Chromium is started with its sandbox on. On Ubuntu 23.10 and later, AppArmor
denies user namespaces to a binary that has no profile. A Chromium from the
Playwright cache is such a binary, so there it refuses to start.

The server does not work round that for you. The error says what happened, and
`JEV_BROWSE_NO_SANDBOX=1` in the server's `env` block starts Chromium with
`--no-sandbox`. That means a page which exploits the renderer is no longer
contained. Playwright makes the same trade by default when it launches
Chromium itself, so this is no worse than the Playwright MCP server beside it.
It is still your decision and it is never the default. The better fix is an
AppArmor profile for the binary.

## Plan mode

Plain `browse` is the default, and it is the right call whenever the goal can
spell out the steps: "open X, click Y, then click Z". Jev picks one action at a
time out of what it can see, and it is fast at that.

It is not built to work out a route. For an open-ended task, "find the year the
author of X was born", set `plan: true`. A planner, one warm `claude -p` child
with thinking off and `--effort low`, reads the page's element labels and names
one step per turn:

```text
CLICK <label>          the Jev agent executes it on the current page
TYPE <field> = <text>
FIND <words>           every element on the page matching the words, however far down
DONE <answer or ok>
```

The planner is Sonnet by default. `plan_model: "haiku"` (or
`JEV_PLANNER_MODEL=haiku`) is cheaper and does as well on spelled-out hops, and
much worse on open-ended ones; the numbers are in the main
[README](../README.md).

What it costs:

- **Money.** The planner runs on the user's own `claude` login and is billed
  there, a few cents a task. Plain `browse` spends nothing on Claude.
- **Time.** Every turn is a planner answer plus an agent run. Expect tens of
  seconds a task, not the few seconds a spelled-out goal takes.
- **A process.** The child starts on the first planned call, never before, and
  stays warm for the life of the worker. A session that never plans never
  starts one.

`JEV_BROWSE_TIMEOUT` defaults to 180 seconds for a planned call instead of 90,
and the loop stops itself a few seconds early so the page it reached still
comes back.

## Settings

| Variable | Default | |
|---|---|---|
| `JEV_ULTRAFAST_DIR` | `vendor/jev-ultrafast` beside the server | The agent's source. Resolved from `server.py`, so a deployed release finds its own copy. `AIRLOCK_BROWSER_DIR` is honoured after it. |
| `JEV_ULTRAFAST_VENV` | `$AIRLOCK_HOME/jev-ultrafast-venv` | The agent's Python environment. Outside the release on purpose, so a deploy does not rebuild it. |
| `BU_CDP_URL` | unset | A Chromium to attach to instead of starting one. Only an explicit value counts. |
| `JEV_BROWSE_TIMEOUT` | `90` | Seconds allowed for a call. |
| `JEV_BROWSE_CHROMIUM` | newest in the Playwright cache, then `PATH` | The binary to start. A pre-2021 `chromium-8xxxxx` directory ranks below any current one. |
| `JEV_BROWSE_NO_SANDBOX` | unset | `1` adds `--no-sandbox`. Read the section above first. |
| `JEV_BROWSE_PREWARM` | unset | `1` warms Chromium, the worker and the text model at start-up. |
| `TEXT_MODEL_API_KEY` | unset | Selects the OpenAI-compatible helper. Also read from the key file. |
| `TEXT_MODEL_PROVIDER` | chosen for you | Set by hand to override the choice above. |
| `JEV_OFFSCREEN_MAX` | `100` | How many off-viewport links a snapshot may offer. `0` is upstream's viewport-only behaviour, `-1` fills the budget. |
| `JEV_SYSTEMONE_SOCKET` | the airlock daemon's socket | An empty value sends every decision straight over HTTPS. |
| `JEV_PLANNER_MODEL` | `sonnet` | The planner for `plan: true` when the call names none. |
| `JEV_PAGE_TEXT_CHARS` | see model.py | Characters of page text in Jev's state per decision. |
| `JEV_DONE_CONFIDENCE`, `JEV_BLOCKED_CONFIDENCE` | see agent.py | Below this, a DONE or BLOCKED is looked at again once before it ends the run. |

### Links below the fold

A long article keeps almost every link out of the viewport, and upstream sends
only what is in it. The snapshot also offers the nearest off-viewport links,
labelled `(below)` or `(above)`, and the executor scrolls one into view before
it resolves geometry and hit-tests as usual. Fields are never offered that way:
typing into something nobody has seen is a different kind of risk.

`JEV_OFFSCREEN_MAX` bounds how many, and 100 is a measured default rather than
a round number. The curve is not monotonic. A cap too small to reach the link a
goal actually wants is worse than offering none at all, because it fills the
table with that link's neighbours and the agent clicks one of them instead of
scrolling. The sweep is in
[SPIKE-NOTES.md](../vendor/jev-ultrafast/SPIKE-NOTES.md#how-many-off-screen-links).

## What leaves the machine

The same as the browser agent. The goal and the observed page state go to
TypeSafe for each decision. Field text goes to whichever text model the agent
is configured with. The page text and the screenshot stay on the machine.

Native Windows is not supported, because the browser agent is not ported
there.

## Tests

`tests/test_browse.py` covers the framing, the handshake, the schema and every
failure in the table above. The call into the vendored agent is mocked. No test touches
the network or starts a browser.
