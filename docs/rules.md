# The rules

The hook is registered for **every** tool. What filters a call is not the
matcher but the table in `airlock/rules.py`: one entry per kind of
genuinely-wrong tool use, each with a code pre-filter that runs in
microseconds. **A call no rule covers costs nothing and logs nothing**: no Jev
request, no log row, no subprocess.

| id | tools | default | decided by | what it is for |
|---|---|---|---|---|
| `R1-secret-exposure` | Bash, Read | deny | code, Jev for an ambiguous path | reading or echoing a secret into the transcript |
| `R2-claude-api-skill` | Skill | deny (warn with no stated purpose) | Jev | loading a 324,006-token reference for a price lookup |
| `R3-whole-suite-or-uncapped-build` | Bash | warn | code only | the whole test suite, or a build with uncapped parallelism |
| `R4-long-work-bare-shell` | Bash | warn | code, Jev for the ambiguous cases | long work on a shell a dropped connection would kill |
| `R5-sudo` | Bash | deny | code only | `sudo` outside a named package install, or anywhere under `$HOME` |
| `R6-gui-or-browser` | Bash | **`off` by default on every platform** | code only | opening a GUI or browser on a headless box |
| `R7-destructive` | Bash | warn | code only | force pushes, hard resets, wholesale deletion (`rm -rf` of `/`, `~` or `.`, recursive `rm` behind `find -exec` or `xargs`), SQL `DROP`, `redis-cli FLUSHALL`, `terraform destroy`, `dd` onto a device, recursive `chmod`/`chown` of `/` or `~`, a download piped into a shell |
| `R7-root-delete` | Bash | deny | code only | `rm -r` of `/`, `/*`, `~`, `~/*` or `$HOME`, behind any wrapper, past `sudo` and its options, and inside `sh -c` |
| `R8-tier-guard` | Agent | deny two rungs over, **warn one rung over**, rewrite only if asked | Jev | a task dispatched to an agent more expensive than it needs |
| `R8-tool-choice-guard` | Bash | deny | Jev | a disk-wide filename crawl, or a raw grep where a code graph exists |
| `R9-commit-secret` | Bash | deny | code + a local credential belt | staging or committing a secret |
| `R10-general-risk` | Bash | **warn only, never deny** | code pre-filter, then a Jev Score + `user_requested` | the catch-all: a call no other rule covers that plainly reaches outside the working tree |
| `R11-browse-via-jev` | every tool (only `mcp__` names can match) | deny | code only | a Playwright MCP browsing call, when the kit ships a Jev-decided `browse` tool |

`R8-tool-choice-guard`'s graphify-suggestion branch only exists when the search
root carries a graph (`graphify-out/graph.json`). With no graph the branch is
inert: it never suggests `graphify query` and never denies. That is most
users. Most do not use graphify at all.

Every deny keeps its safety net. The `[airlock-ok: <reason>]` override stamp in
a call's description, loop protection so the same call is never denied twice in
ten minutes, a hard budget, and fail-open on any error. Where Jev is involved,
a deny also needs a confidence of at least 0.8 and a margin of at least 0.4
over the runner-up.

`R11-browse-via-jev` is the exception, and the only one. It ignores the stamp
and the loop allowance both, for the reason its own section below gives. The
budget and the fail-open still apply to it. It has one door, and only the
`browse` tool itself opens it: a `browse` call that comes back `blocked`, or
errors, turns this rule into a warn for the next thirty minutes of that
session.

A deny is also softened to a warn when the user's own recent words asked for the
thing. That check reads only what the person typed, never a tool result or a
fetched page, and it can only ever soften: no answer to it can make the guard
stricter. See `airlock/context.py`.

Before anything leaves the machine, `airlock/redact.py` replaces token-shaped
strings with `[REDACTED]`, and truncation happens after redaction so a secret
straddling the boundary is not half-leaked.

## Turning rules off, or down

Individual rules can be switched off or downgraded in
`~/.config/airlock/rules.json` without touching code:

```json
{"R3-whole-suite-or-uncapped-build": "off", "R7-destructive": "log"}
```

Valid values are `deny`, `ask`, `warn`, `log`, `off`. An `off` rule is skipped
in the pre-filter, so it costs nothing at all.

`ask` hands the decision to the human instead of blocking. It is
configuration-only: no rule ships with it. In a session nobody is attending it
degrades to a plain `deny`, because a headless session has no way to answer an
ask. That was verified against Claude Code 2.1.272, not assumed.

## `R8-tier-guard`: what happens when the agent is too expensive

The guard asks Jev one question about an `Agent` dispatch: what kind of task
this really is. It compares the answer to the rung that was chosen, and the gap
decides what happens.

| gap | what happens |
|---|---|
| two or more rungs too expensive | **blocked**, with the cheaper `subagent_type` named in the reason |
| `fable` with no prior failed attempt stated | **blocked** |
| one rung too expensive, confidence >= 0.8 and margin >= 0.4 | **allowed, with a two-line note** saying what was chosen, what Jev judged adequate, and the exact `subagent_type` to use instead |
| below those confidence bars | nothing at all |
| cheaper than the task needs | logged as under-tiered, never blocked, never "corrected" upward |

The one-rung note is new, and it exists because the old behaviour was useless.
On the live log, 20 of 27 judged `Agent` calls were flagged over-tiered and
**not one of them was surfaced**. The row said `action: deny, enforced: false`
and the session never heard a word. A later session went on to conclude that
nothing intercepted the `Agent` tool at all. A guard nobody can see teaches
nobody anything. It reads:

```
airlock tier advice: dispatched 'workerO', but Jev judged this task
'scoped_implementation', which 'workerS' covers. Next time use
subagent_type=workerS.
Advice only -- nothing was blocked and this call ran as you wrote it.
```

Nothing is blocked, nothing is changed, and the dispatch runs exactly as it
was written.

### Rewrite mode (off by default, and here is the catch)

Rewrite mode goes one step further: instead of advising, the hook **edits the
dispatch**, changing `subagent_type` to the adequate rung and leaving every
other field byte-identical. Claude Code supports this: a `PreToolUse` hook may
return `hookSpecificOutput.updatedInput` alongside
`permissionDecision: "allow"`. The CLI's own shipped hooks reference documents
it as "`updatedInput` - Modified tool input (PreToolUse only)", and a live run
on CLI 2.1.278 confirmed it by executing the rewritten call rather than the
original.

Turn it on with either:

```bash
touch ~/.config/airlock/tier-rewrite     # or: export AIRLOCK_TIER_REWRITE=1
rm ~/.config/airlock/tier-rewrite        # off again
```

The bars are stricter than the warn's: confidence >= 0.9 and margin >= 0.5,
rather than 0.8 and 0.4. Four things it never does:

- rewrite upward;
- rewrite to an agent type that is not in the ladder;
- rewrite past an `[airlock-ok: <reason>]` stamp in the Agent description or
  prompt;
- rewrite a `fable` dispatch that did state a prior failed attempt.

The model is told what happened and how to override it.

**The downside: a wrong downgrade is silent apart from the context note.** A
block is loud, because the work stops and somebody looks. A rewrite is quiet.

If Jev misreads a genuinely hard task as routine, the job runs on a cheaper
agent. The only trace is one line of context. You get back a worse answer, and
nothing flagged it as worse.
That is the whole reason this is opt-in and the warn is the default. Turn it
on where the cost of one bad downgrade is smaller than the cost of the
over-tiering it prevents, and read the `surfaced: "rewrite"` rows in the log
for a while before trusting it.

### The ladder lives in one file

Agent type names differ per machine. `airlock/tiers.py` holds the built-in
ladder, and `~/.config/airlock/tiers.json` overrides it: an ordered list of
lists of equivalent names, cheapest rung first.

```json
[["scout-find"],
 ["scout"],
 ["workerS", "worker"],
 ["workerO"],
 ["claude", "general-purpose", "Plan", "Explore"],
 ["fable"]]
```

The first name in each list is both the rung's name and the type the guard
suggests or rewrites to, so put the one you actually want dispatched first.
A type that appears nowhere in the ladder is treated as Opus-level. A
malformed ladder is ignored whole and the built-in one is used, so a broken
config can never make the guard misjudge a rung. Malformed means any of these:
not a list of non-empty lists of strings, fewer than two rungs, or one name in
two rungs.

## `R11-browse-via-jev`: a Playwright MCP call is pointed at `browse`

The kit ships a Jev-decided `browse` MCP tool ([browse/](../browse/README.md)),
which drives the jev-ultrafast agent vendored at `vendor/jev-ultrafast`. On the same nine
goals the Jev-decided agent reaches everything Sonnet reaches for roughly
1/233rd of the Claude spend per run. This rule tells an agent that reaches for
Playwright MCP to use `browse` instead. It is on by default.

The whole rule is a tool-name match. The hook is wired with matcher `*`, so an
MCP call reaches the table with its name, and the name is all this needs.

- **The server** is any MCP server whose name contains `playwright`. That
  covers `mcp__playwright__`, `mcp__plugin_playwright_playwright__`,
  `mcp__playwright-ads__` and `mcp__playwright-jono__`.
- **The tool** is one of fifteen that drive or read a page:
  `browser_navigate`, `browser_navigate_back`, `browser_click`,
  `browser_type`, `browser_fill_form`, `browser_press_key`, `browser_hover`,
  `browser_drag`, `browser_select_option`, `browser_snapshot`,
  `browser_take_screenshot`, `browser_evaluate`, `browser_run_code_unsafe`,
  `browser_wait_for` and `browser_find`.
- **Housekeeping never matches**: `browser_close`, `browser_install`,
  `browser_resize`, `browser_tabs`, `browser_console_messages` and
  `browser_network_requests`.

Matched means deny. Jev is not asked anything, so there is no confidence bar
and no key is needed. The `user_requested` question that can soften other
denies is skipped here too. An MCP browser call made from a Claude session is
browsing by definition, which leaves nothing to judge.

Shell commands are never looked at. A Playwright script is fixed code with no
model choosing its steps, so Jev has nothing to decide in one. `node
scrape.js`, `npx playwright open` and `playwright test` all pass untouched.

The deny names the tool and gives its usage in one line:

```text
browse(goal="open https://example.com and report the main heading", extract="h1")
```

The deny also spells out how to write a goal Jev can follow. Jev picks one
action at a time, out of what it can see on the page, so a goal written as
steps works and a goal written as an outcome does not. "Open the article,
click the link to X, then click the link to Y, scroll if the link is not in
view" is the shape that gets there.

There is no per-call way past it. This is the one rule that ignores both
safety nets every other deny keeps. An `[airlock-ok: <reason>]` stamp is
logged as `override_refused` and the call is denied anyway, and the identical
call repeated inside the loop window is denied again rather than allowed. The
match carries `strict` in its `extra`, which is where `airlock/enforce.py`
reads that from; no other rule sets it.

Both nets were closed because both were measured being used to stay on
Playwright. A subagent given a plain click-through-Wikipedia task wrote
`[airlock-ok: ...]` into the `element` field of a click, and when that stopped
working it sent the same call twice. An MCP call has no `description` field,
so the stamp is harvested from any top-level text field, which puts it well
within reach of a model composing the call. Neither escape carried a person's
say-so, which is the only thing they exist for.

### When `browse` gives up, R11 stands aside

Strictness is only fair while the alternative works. Jev's chooser sees one
step at a time and only inside the viewport, so a task that needs several hops
is out of its reach. Measured on 2026-09-23: `browse` came back `blocked` on
a two-hop Wikipedia link-navigation task. A strict rule on top of that
leaves the session with no browser at all, which is a worse outcome than the
spend it was avoiding.

So `browse` failing is what opens the door, and nothing else does.

- A **PostToolUse and PostToolUseFailure hook**,
  `hooks/airlock_browse_unlock.py`, is registered against the one tool name
  `mcp__browse__browse` under both events. A call that errors never reaches
  PostToolUse, so it arrives on PostToolUseFailure with an `error` string in
  place of a response. It reads the response and
  writes a small per-session row when the status is `blocked`, or when the
  call itself errored. A `done` result writes nothing. A response it cannot
  parse writes nothing either, and it never prints a word or blocks anything.
- The row lives in `~/.local/state/airlock/browse_unlock.json`, handled by
  `airlock/browse_state.py`. Same lock, same 700/600 permissions and the same
  `platform_compat` calls as the loop-protection file beside it. It expires
  after **thirty minutes**, and every write prunes what has expired.
- While a row is unexpired, R11 warns instead of denying. The log row carries
  `unlocked_by: "browse_blocked"` and `browse_status`, so a warn earned this
  way is never confused with the rule simply not firing.
- Anything that goes wrong reading the file means no unlock. The rule stays
  strict, which is the failure direction that cannot be abused.

The unlock belongs to the session, not to the call. Stamps and repeats still
do nothing on their own.

**A subagent's hook payload carries the parent session's `session_id`.**
Measured on this box: a subagent's tool calls log the same id as the session
that dispatched them. So an unlock a subagent earns is shared with the parent
and its siblings. That is accepted rather than worked around. The id in the
payload is the only handle a hook gets, and `browse` giving up says something
about the task, not about which agent asked.

An agent that genuinely needs Playwright for something `browse` cannot express
at all, for per-frame timing, raw CDP or a scripted measurement, stops and
asks. Turning the rule off is the user's call, and they make it by putting
`{"R11-browse-via-jev": "off"}` in `~/.config/airlock/rules.json`.

This is a cost steer, not a security control. It removes nothing: the
Playwright MCP servers stay registered.

## `R10-general-risk`: the fallback

`R10-general-risk` is the only fallback rule, and it behaves differently on
purpose. It is consulted **only when no other rule matched the call at all**,
and only when a pure code pre-filter recognises one of six shapes:

- a write landing outside the cwd and outside temp;
- an upload to a non-localhost host (`curl`, `scp`, `rsync`);
- a package or release publish;
- a database CLI carrying a write verb;
- service or container control;
- a mass file operation globbed high in the tree.

Anything else costs nothing at all. When it does ask, it asks one Score
question about risk, over four ordered levels running from read-only and fully
reversible up to reaching off the machine. It also asks the same
`user_requested` noul used elsewhere, which can only ever soften.

It is `warn` and never `deny`. A catch-all heuristic blocking things it cannot
name is how a guard becomes something people turn off. It is ported in spirit
from [leepokai/jev-guard](https://github.com/leepokai/jev-guard)'s
`ACTION_QUESTIONS`, which asks the same risk score on *every* non-read-only
tool call. That is the cost this project exists to avoid, hence the pre-filter
and the fallback-only placement.
