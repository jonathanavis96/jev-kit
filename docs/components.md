# What is in the kit

One row per component, with what it does, whether it is installed by default,
what it sends off the machine, and how much use it has actually had.

Every component is optional except the guard. Two columns are worth reading
before you install anything: **Exercised**, which says how much use and testing
each piece has actually had, and **What leaves the machine**.

`Exercised` means unit tests, a labelled eval, a measured bench and real daily
use on at least one machine. `Experimental` means the logic has unit tests and
the component has been run by hand. No labelled corpus, no measured number, no
sustained use. Keep it, read its README's banner, and build nothing
load-bearing on it yet.

## Guards

| Component | What it does | Default | Exercised | What leaves the machine |
|---|---|---|---|---|
| **Airlock, the tool-call guard** (`airlock/` + `hooks/`) | The rules table, policy, redaction, client and health. The `PreToolUse` entry point. | **yes** (`--guard`) | exercised | Redacted summaries of the ambiguous fraction of tool calls, to TypeSafe. Never a raw tool result; every string passes through `airlock/redact.py` first. |
| **Tier guard** (`airlock/tiers.py`, rule `R8-tier-guard`) | Compares the agent rung a dispatch chose against the kind of task Jev judges it to be, and warns, blocks or (opt-in) rewrites. | part of the guard | exercised | The `Agent` dispatch's description and prompt, redacted. |
| **Session check** (`hooks/airlock_session_check.py`) | A `SessionStart` hook. The guard fails open, so a dead guard is silent; on a workstation nothing outside the machine can notice. This tells the person at the one moment they are certainly there. Silent when healthy, hard 300 ms budget, reads local state only, fails open, de-duplicated to once per 6 hours (24 for the informational "it is switched off"). | **yes** (`--session-check`) | exercised | Nothing. It never makes a network call of any kind. |
| **Browse unlock** (`hooks/airlock_browse_unlock.py`) | A `PostToolUse` and `PostToolUseFailure` hook on the one tool name `mcp__browse__browse` (an errored call only reaches the second). When a `browse` call comes back `blocked`, or errors, it records a per-session row and `R11-browse-via-jev` warns instead of denying Playwright MCP for the rest of the session. Writes local state only, prints nothing, blocks nothing, and records nothing it cannot parse. | **yes** (rides with the guard) | exercised | Nothing. It never makes a network call. |
| **Belay** (`belay/`) | Wrapper for the community `jev-belay` Stop hook: when an agent claims it is finished with no passing check behind it, sends it back to verify. | **yes** (`--belay`) -- clones a pinned third-party repo | exercised | Task text, final assistant message and check command lines, through a 13-rule secret redactor, capped at a few thousand characters. No diffs, no file contents. |

## Speed and cost

| Component | What it does | Default | Exercised | What leaves the machine |
|---|---|---|---|---|
| **Warm daemon** (`deploy/`) | Keeps a warm connection so a judgement costs about 0.3 s instead of about 0.9 s. | **yes** (`--daemon`) | exercised | Nothing of its own. It is the transport the guard already uses. |
| **Compaction** (`compaction/`) | Installer for the community `fast-jev-compaction` plugin. **Read `compaction/README.md` first.** | no (`--compaction`) | never enabled here | **Up to roughly 25,000 tokens of raw, unredacted tool inputs and tool-result text per request.** By far the largest exposure here, which is why it is never installed for you. |
| **File search** (`filesearch/`) | Per-user `plocate` index of `$HOME` and its hourly timer, so R8 can suggest an indexed search. | **yes** (`--filesearch`) | exercised | Nothing. Entirely local. |
| **File search on Windows** (`airlock/everything.py`) | Detects [Everything](https://www.voidtools.com/) (`es.exe`) and whether its index is running, so the same R8 steer names `es.exe` instead of `plocate`. It **detects only and never installs either**: Everything is third-party software with its own installer and service, and airlock says what the human must do rather than doing it. | **yes** on native Windows, n/a elsewhere | run on one Windows 11 machine | Nothing. Entirely local. |

## Uses

| Component | What it does | Default | Exercised | What leaves the machine |
|---|---|---|---|---|
| **Browser agent** (`browser/`) | Syncs the environment for the Jev-decided browser agent vendored at `vendor/jev-ultrafast`. | no (`--browser`) | own numbers, see `browser/README.md` | Page state and goals to the decision model you configure. |
| **Browse MCP tool** (`browse/`) | A stdio MCP server with one tool, `browse`, that runs a goal through the browser agent and owns the headless Chromium. `R11` points plain Playwright MCP read/navigate/click calls at it; uploads, scripted code and other calls it cannot express stay on Playwright. The installer prints the `mcpServers` block and applies nothing. | no (`--browse-mcp`) | one real run, see `browse/README.md` | The same as the browser agent: page state and the goal, to TypeSafe. |
| **Review** (`review/`) | Clones a Jev code reviewer at a pin, with a fail-open wrapper. | no (`--review`) | no numbers here | Diffs, to whatever review gate you configure. |
| **Document classifier** (`docclass/`) | Two-stage document classifier with an escape hatch and a confidence gate. | no | **experimental** | Page text, to TypeSafe, when you call it. |
| **Log triage** (`logtriage/`) | Redact-first, local-rules-first log triage on stdin. | no | **experimental** | Nothing until local rules are exhausted; redacted lines after that. |
| **Shim** (`shim/`) | An OpenAI-shaped HTTP shim over the `claude` CLI. | no (`--shim`) | **experimental** | Whatever you send through it. |

## Operations

| Component | What it does | Default | Exercised | What leaves the machine |
|---|---|---|---|---|
| **Installer** (`install/`) | One installer, a doctor, deploy/rollback/wire, the migration script. | n/a | exercised | Nothing. |
| **Monitoring** (`monitoring/`) | Five-minute health check and its timer. | **yes** (`--monitoring`) | exercised | Nothing. |
| **Push monitor** (`monitoring/kuma_push.py`) | Optional push to an Uptime-Kuma-style monitor you host. `heartbeat` (the default: a server, watched by its monitor's own silence timeout) or `explicit` (a workstation: the failure is stated, so silence never alerts). Any service accepting a GET with `status` and `msg` works. | no -- set `AIRLOCK_KUMA_PUSH_URL` | exercised | A status word, and in `explicit` mode which check failed: redacted, home directories replaced, capped at 200 characters. |
| **Tuning loop** (`tuning/`) | Unattended tuning loop, its timer, promotion and threshold calibration. | no (`--tuning`) | exercised | Real Claude sessions on the account you nominate, for the judge. |
| **Auto-updater** (`claude-update/`) | Idle-only Claude Code auto-updater and its timer. Updates only when no run is alive. | **yes** (`--claude-update`) | exercised | Nothing. An idle check and `npm install -g`. |

## Not components, but in the tree

| Directory | What it holds | Exercised | What leaves the machine |
|---|---|---|---|
| `eval/` | Labelled cases for every rule, and the ablations. | exercised | Nothing. |
| `bench/` | A/B benchmark: enforce mode against no guard at all. | exercised | Nothing until you run it. |
| `docs/` | Credits for the community projects the ported patterns came from, and the install guides. | n/a | Nothing. |

## Why the guard is called Airlock

`airlock` is the name of the guard component, its Python package, its systemd
units and its config directory. It was `plumbline` before that, and
`jev-guard` before that. The first rename was forced: a public project,
[leepokai/jev-guard](https://github.com/leepokai/jev-guard), already uses that
name. Both older names still work through the cutover; see
[MIGRATING-TO-AIRLOCK.md](MIGRATING-TO-AIRLOCK.md).

**Airlock is not a sandbox.** Several projects called "airlock" isolate agents
or untrusted code in a VM or container. This does none of that. It is a policy
hook inside your own session that judges individual tool calls and, at most,
returns a deny to Claude Code.
