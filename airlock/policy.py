"""Policy tables: turn Jev's answers into a shadow would_deny verdict.

Pure functions, no network, no I/O beyond a cheap upward filesystem walk to
detect a git repo / graphify graph. This is what tests/test_policy.py exercises
directly, independent of the HTTP call.
"""
import os
import re
import shlex
from pathlib import Path

from . import tiers, winpath
from .platform_compat import is_windows

CONFIDENCE_THRESHOLD = 0.8
MARGIN_THRESHOLD = 0.4


def compute_margin(probabilities):
    """Margin between the top probability and the runner-up, from a Choice
    answer's `probabilities` dict. Returns None if there aren't at least two
    options to compare (a deny can never require a margin that doesn't
    exist)."""
    if not probabilities:
        return None
    values = sorted(probabilities.values(), reverse=True)
    if len(values) < 2:
        return None
    return values[0] - values[1]


def meets_deny_bar(confidence, margin):
    """Shared deny gate for every guard: high confidence is not enough on its
    own -- the top option must also clearly beat the runner-up."""
    return _at_least(confidence, CONFIDENCE_THRESHOLD) and _at_least(margin, MARGIN_THRESHOLD)


def _at_least(value, threshold):
    """value >= threshold for a real number only. None, NaN and anything
    non-numeric are False: NaN compares False with everything, so a plain
    `value < threshold` check let a NaN answer clear a deny bar."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return value >= threshold

# --- Agent tier guard --------------------------------------------------------
#
# The ladder itself lives in airlock/tiers.py, which is the ONE place that
# knows which agent type names this machine uses and can be overridden per
# machine by ~/.config/airlock/tiers.json. The names below are the built-in
# default, re-exported so existing callers and tests keep working.

RUNG_ORDER = [rung[0] for rung in tiers.DEFAULT_LADDER]
RUNG_INDEX = {name: i for i, name in enumerate(RUNG_ORDER)}

AGENT_TYPE_RUNG = {
    name: rung[0] for rung in tiers.DEFAULT_LADDER for name in rung
}

# subagent_type prefixes treated as Opus-level "director" rung.
DIRECTOR_PREFIXES = tiers.DIRECTOR_PREFIXES

# Minimum adequate rung per task_kind. "unclear" is deliberately absent: it is
# never a basis for would_deny.
TASK_KIND_ADEQUATE_RUNG = {
    "lookup": "scout-find",
    "mechanical_edit": "scout",
    "scoped_implementation": "workerS",
    "judgement": "workerO",
    "hard_problem": "fable",
}


def rung_for_agent_type(subagent_type):
    return tiers.rung_for_agent_type(subagent_type)


def evaluate_tier(task_kind, task_kind_confidence, states_prior_failed_attempts, chosen_type, task_kind_margin=None):
    """Return the tier-guard verdict for one Agent tool call.

    would_deny: chosen rung is strictly higher than the adequate rung for the
    judged task_kind, AND task_kind clears the shared deny bar (confidence
    >= 0.8 AND margin >= 0.4 over the runner-up), AND task_kind != unclear.
    Also true when chosen_type == "fable" and states_prior_failed_attempts < 0.5
    (fable dispatched without stating a failed prior attempt) -- that rule
    uses a Noul answer, which carries no margin, so it is unaffected by the
    margin gate.

    under_tiered: chosen rung is strictly lower than adequate -- logged, never
    a deny.
    """
    chosen_rung = rung_for_agent_type(chosen_type)
    adequate_rung = TASK_KIND_ADEQUATE_RUNG.get(task_kind)
    index = tiers.rung_index()
    if adequate_rung is not None and (chosen_rung not in index or adequate_rung not in index):
        # A machine ladder that does not name this rung at all: no comparison
        # is possible, so nothing is over- or under-tiered. Fail open.
        adequate_rung = None

    would_deny = False
    under_tiered = False
    rung_diff = None

    if adequate_rung is not None:
        chosen_idx = index[chosen_rung]
        adequate_idx = index[adequate_rung]
        rung_diff = chosen_idx - adequate_idx
        if (
            chosen_idx > adequate_idx
            and task_kind != "unclear"
            and meets_deny_bar(task_kind_confidence, task_kind_margin)
        ):
            would_deny = True
        elif chosen_idx < adequate_idx:
            under_tiered = True

    if chosen_type == "fable" and (states_prior_failed_attempts or 0.0) < 0.5:
        would_deny = True

    return {
        "chosen_rung": chosen_rung,
        "adequate_rung": adequate_rung,
        "would_deny": would_deny,
        "under_tiered": under_tiered,
        "suggested_agent": adequate_rung,
        "rung_diff": rung_diff,
    }


def tier_entry_fields(verdict, task_kind, task_kind_confidence, margin,
                      prior_failed, chosen_type):
    """The decision-relevant half of a tier log row, in ONE place.

    `enforce_deny_tier`, `tier_rewrite_target` and `tier_surface` all read an
    entry dict rather than a verdict, so anything that wants to know what a
    judgement WOULD do -- the guard, and airlock/eval.py -- has to assemble the
    same dict. Assembling it twice is how the eval came to score a different
    thing from the hook, so it is assembled here and nowhere else.

    The caller adds whatever presentation and bookkeeping it needs on top
    (timestamps, `detail`, shadow sampling).
    """
    return {
        "would_deny": verdict["would_deny"],
        "suggestion": verdict.get("suggested_agent"),
        "under_tiered": verdict["under_tiered"],
        "margin": margin,
        "rung_diff": verdict.get("rung_diff"),
        "chosen_type": chosen_type,
        "task_kind": task_kind,
        "task_kind_confidence": task_kind_confidence,
        "prior_failed": prior_failed,
    }


# --- Enforce-mode deny gates (Part A, item 5) --------------------------------
#
# Shadow's would_deny stays the wider, always-logged signal above. Enforce
# mode only ever blocks a strict SUBSET of that: Bash blocks exactly when
# would_deny already fires (same confidence+margin bar, nothing new to add).
# Agent blocks only for fable-without-stated-prior-failure, or a rung gap of
# TWO OR MORE -- a one-rung gap is logged (would_deny) but never enforced,
# and under-tiering is never a basis for a deny.


def enforce_deny_search(search_entry):
    """Bash enforce-mode deny gate: identical to would_deny -- the shared
    confidence(>=0.8)/margin(>=0.4) bar already gates would_deny, so there is
    no additional condition to apply here."""
    return bool((search_entry or {}).get("would_deny"))


def enforce_deny_tier(tier_entry):
    """Agent enforce-mode deny gate: fable dispatched without a stated prior
    failed attempt, OR the chosen rung is at least two rungs above the
    adequate rung for the judged task_kind (same deny bar as would_deny)."""
    entry = tier_entry or {}
    if entry.get("chosen_type") == "fable" and (entry.get("prior_failed") or 0.0) < 0.5:
        return True
    rung_diff = entry.get("rung_diff")
    task_kind = entry.get("task_kind")
    if (
        rung_diff is not None
        and rung_diff >= 2
        and task_kind != "unclear"
        and meets_deny_bar(entry.get("task_kind_confidence"), entry.get("margin"))
    ):
        return True
    return False


# --- Agent tier guard: what to SURFACE when it does not block ----------------
#
# Before this, a one-rung overshoot was recorded (`would_deny: true`,
# `enforced: false`) and the model never heard a word about it: 20 of 27
# judged Agent calls on the live log were flagged over-tiered and not one of
# them was surfaced, which is how another session concluded that nothing
# intercepts the Agent tool at all. A guard nobody can see teaches nobody
# anything.
#
# Two non-blocking outcomes now exist:
#
#   warn     the default. The one-rung case that already clears the shared
#            deny bar (confidence >= 0.8, margin >= 0.4) comes back as
#            PreToolUse additionalContext saying what was chosen, what Jev
#            judged adequate, and which subagent_type to use instead. The
#            call is ALLOWED and runs unchanged. Below the bar: silence.
#
#   rewrite  opt-in, off by default (see rewrite_enabled). A stricter bar
#            (confidence >= 0.9, margin >= 0.5) and the hook edits
#            subagent_type to the adequate rung instead of only advising.
#
# Neither ever fires upward, and neither touches the fable-without-stated-
# prior-failure case, which stays a block.

REWRITE_CONFIDENCE_THRESHOLD = 0.9
REWRITE_MARGIN_THRESHOLD = 0.5
REWRITE_FLAG_FILE = "tier-rewrite"
REWRITE_ENV = "AIRLOCK_TIER_REWRITE"


def rewrite_enabled():
    """True only when the machine has explicitly opted in: env
    AIRLOCK_TIER_REWRITE=1, or ~/.config/airlock/tier-rewrite existing.
    Never raises -- any error means OFF."""
    try:
        if os.environ.get(REWRITE_ENV) == "1":
            return True
    except Exception:
        return False
    try:
        from . import paths
        return paths.config_file(REWRITE_FLAG_FILE).exists()
    except Exception:
        return False


def meets_rewrite_bar(confidence, margin):
    return (_at_least(confidence, REWRITE_CONFIDENCE_THRESHOLD)
            and _at_least(margin, REWRITE_MARGIN_THRESHOLD))


def tier_rewrite_target(tier_entry):
    """The subagent_type a rewrite would use, or None when this entry must not
    be rewritten. Refuses, in order:

      - fable dispatched WITH a stated prior failed attempt (the human has
        given the reason the ladder asks for; a downgrade would ignore it),
      - an entry that was not actually over-tiered (rung_diff < 1), an
        `unclear` task_kind, or one below the stricter rewrite bar,
      - a target rung with no dispatchable name on this machine's ladder, a
        target that is not in the ladder verbatim, or a target that is not
        strictly CHEAPER than what was chosen (never rewrite upward).
    """
    entry = tier_entry or {}
    chosen_type = entry.get("chosen_type") or ""
    if chosen_type == "fable" and (entry.get("prior_failed") or 0.0) >= 0.5:
        return None
    rung_diff = entry.get("rung_diff")
    if rung_diff is None or rung_diff < 1:
        return None
    if entry.get("task_kind") in (None, "unclear"):
        return None
    if not meets_rewrite_bar(entry.get("task_kind_confidence"), entry.get("margin")):
        return None

    target_rung = entry.get("suggestion")
    if not target_rung:
        return None
    target = tiers.dispatch_name_for_rung(target_rung)
    if not target or not tiers.is_known_agent_type(target):
        return None

    index = tiers.rung_index()
    chosen_rung = tiers.rung_for_agent_type(chosen_type)
    if chosen_rung not in index or target_rung not in index:
        return None
    if index[target_rung] >= index[chosen_rung]:
        return None
    return target


def tier_surface(tier_entry, rewrite_on=None):
    """What this Agent judgement should DO, beyond the log row.

    Returns "block", "rewrite", "warn" or None (stay silent). "block" keeps
    the existing enforce behaviour exactly; rewrite takes precedence over it
    only when rewrite mode is on and the entry qualifies, because editing the
    dispatch down a rung lets the work proceed where a block would not.
    """
    entry = tier_entry or {}
    if entry.get("error"):
        return None
    on = rewrite_enabled() if rewrite_on is None else bool(rewrite_on)
    if on and tier_rewrite_target(entry):
        return "rewrite"
    if enforce_deny_tier(entry):
        return "block"
    if entry.get("would_deny"):
        # One rung over, already past the shared deny bar: too small to block,
        # too common to keep hiding.
        return "warn"
    return None


# --- Bash tool-choice guard --------------------------------------------------

SEARCH_PROGRAMS = {"find", "fd", "fdfind", "grep", "egrep", "rg", "ag", "ack", "locate", "plocate", "tree", "du"}
# The Windows-only half, matching airlock/scope.py's WINDOWS_SEARCH_PROGRAMS,
# plus the two shells a search can be wrapped in. Consulted ONLY on Windows,
# because `dir`, `where` and `find` all mean something else on Linux.
WINDOWS_SEARCH_PROGRAMS = {
    "dir", "where", "findstr", "get-childitem", "gci", "childitem",
    "select-string", "sls", "es",
    "cmd", "powershell", "pwsh",
}
_SEGMENT_SPLIT = re.compile(r"[;&|]+")
_SKIP_PREFIX_TOKENS = {"sudo", "nice", "time", "env"}


def bash_is_search_like(command, windows=None):
    """Cheap code pre-filter: does this shell command contain a search-like
    program as a command word in any of its segments? Only when this is true
    do we spend an API call on the tool-choice guard.

    Applies to the PowerShell tool as well as the Bash tool: Claude Code's
    hooks reference says a hook that inspects shell commands must "Match
    `Bash|PowerShell`", since on Windows without Git Bash the Bash tool is
    never registered at all.
    """
    if not command:
        return False
    if windows is None:
        windows = is_windows()
    for segment in _SEGMENT_SPLIT.split(command):
        segment = segment.strip()
        if not segment:
            continue
        try:
            if windows:
                lex = shlex.shlex(segment, posix=True)
                lex.whitespace_split = True
                lex.escape = ""
                lex.commenters = ""
                tokens = list(lex)
            else:
                tokens = shlex.split(segment)
        except ValueError:
            tokens = segment.split()
        if not tokens:
            continue
        idx = 0
        while idx < len(tokens) and (
            "=" in tokens[idx] and not tokens[idx].startswith("-")
            or tokens[idx] in _SKIP_PREFIX_TOKENS
        ):
            idx += 1
        if idx >= len(tokens):
            continue
        prog = Path(tokens[idx]).name
        if prog in SEARCH_PROGRAMS:
            return True
        if windows:
            win_prog = _windows_program_name(tokens[idx])
            if win_prog in SEARCH_PROGRAMS or win_prog in WINDOWS_SEARCH_PROGRAMS:
                return True
        if prog == "ls" and any(t.startswith("-") and "R" in t for t in tokens[idx + 1:]):
            return True
    return False


def _windows_program_name(token):
    """Bare, lower-cased program name with either separator and any Windows
    executable suffix removed. Mirrors airlock/scope.py:_program_name."""
    name = str(token).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    lowered = name.lower()
    for suffix in (".exe", ".cmd", ".bat", ".com", ".ps1"):
        if lowered.endswith(suffix):
            return lowered[:-len(suffix)]
    return lowered


def _find_upward(cwd, relative):
    if not cwd:
        return None
    try:
        p = Path(cwd).expanduser().resolve()
    except Exception:
        return None
    for parent in [p] + list(p.parents):
        try:
            if (parent / relative).exists():
                return parent
        except Exception:
            continue
    return None


def cwd_is_git_repo(cwd):
    return _find_upward(cwd, ".git") is not None


def cwd_has_graphify_graph(cwd):
    return _find_upward(cwd, "graphify-out/graph.json") is not None


PLOCATE_SUGGESTION = "plocate -d ~/.cache/plocate/home.db -i '<pattern>'"

# The Windows counterpart. voidtools Everything keeps a live NTFS index, so a
# filename question it answers is instant rather than a crawl -- the same
# argument plocate makes on Linux. The flags are es.exe's own:
#   -path <dir>   confine the search to one folder (and its subfolders)
#   -n <count>    stop after N results
#   -r            treat the search term as a regular expression
#   -i            MATCH CASE. es is case-INsensitive by default, so -i makes
#                 a search stricter, not looser -- the opposite of grep -i,
#                 and the one flag that is easy to get backwards.
ES_SUGGESTION = (
    'es.exe -path "<folder>" -n 50 "<pattern>"\n'
    '    (Everything\'s index answers instantly; add -r for a regex pattern, '
    '-i to make the match case-sensitive)'
)

# Under WSL, plocate only indexes $HOME on the Linux side -- it structurally
# cannot answer for a root that lives on the Windows host. voidtools
# Everything can, and its client is on PATH there too, just reached under its
# bare name (`es`, not `es.exe` -- WSL isn't running the Windows executable
# search rules Windows itself uses to resolve a bare `es.exe`).
ES_WSL_SUGGESTION = (
    'es -path "<folder>" -n 50 "<pattern>"\n'
    "    (that root is on the Windows host; the plocate index covers $HOME on the\n"
    "     Linux side only. Everything's index answers instantly. Add -r for a regex\n"
    "     pattern, -i to make the match case-sensitive)"
)

# Mixed roots: the command spans both filesystems, and neither index covers
# the other's ground. Replacing it with either one alone silently drops every
# result from the other half, which is worse than the crawl it is replacing --
# so name both, in the order the original roots were given.
ES_WSL_MIXED_SUGGESTION = (
    "plocate -d ~/.cache/plocate/home.db -i '<pattern>'    # the Linux $HOME roots\n"
    'es -path "<folder>" -n 50 "<pattern>"                 # the /mnt/<drive> roots\n'
    "    (this search spans both filesystems and no single index covers both:\n"
    "     plocate never indexes /mnt/<drive>, and Everything never indexes the\n"
    "     Linux side. Run both and combine, or split the search by root)"
)
# A search rooted at "/" under WSL is wider still. Between them the two
# indexes cover $HOME and the Windows drives, and nothing else: /etc, /opt,
# /usr and the rest of the Linux side are in neither. Replacing the crawl
# with that pair alone would report a file in /etc as absent, so the advice
# keeps a bounded crawl for the ground neither index holds (Codex P1, PR #1).
ES_WSL_WHOLE_FS_SUGGESTION = (
    "plocate -d ~/.cache/plocate/home.db -i '<pattern>'    # $HOME, Linux side\n"
    'es -path "<folder>" -n 50 "<pattern>"                 # the /mnt/<drive> roots\n'
    "find <dir> -xdev -name '<pattern>'                    # any Linux path outside $HOME\n"
    "    (a search from / crosses both filesystems AND Linux directories\n"
    "     outside $HOME -- /etc, /opt, /usr, /srv, /root, /tmp and every\n"
    "     other mount. Neither index holds any of that, so name the\n"
    "     directories you actually need and crawl only those)"
)
#: A WSL search that stays on the Linux side but reaches BOTH $HOME and a
#: directory outside it. Everything is not named: it indexes the Windows
#: host alone, so offering it for /opt sends the reader to a tool that
#: reports every file there as absent (review finding, PR #1).
LINUX_MIXED_SUGGESTION = (
    "plocate -d ~/.cache/plocate/home.db -i '<pattern>'    # $HOME, Linux side\n"
    "find <dir> -xdev -name '<pattern>'                    # any Linux path outside $HOME\n"
    "    (the index holds $HOME and nothing else -- /etc, /opt, /usr, /srv\n"
    "     and every other mount need a crawl, so name the directories you\n"
    "     actually need rather than searching from /)"
)
GRAPHIFY_SUGGESTION = "graphify query"


#: What an unparameterised call assumes about this machine. The policy the
#: kit generates, its pinned fingerprint and every platform-neutral test
#: must not change with whether the host running them happens to have
#: Everything or a plocate database installed -- a probe that detects made
#: the generated policy host-dependent and broke the pinned-fingerprint test
#: on any machine without an index (Codex P1, PR #1). Only the live guard
#: detects, by passing what detect_availability() found.
ASSUMED_DB_KIND = "home"
ASSUMED_HAS_ES = True

#: Sentinel for "this caller said nothing", so an explicit db_kind=None
#: ("this machine has no database") stays distinct from the default.
UNSET = object()


def _es_ok(windows=None, has_es=UNSET):
    return ASSUMED_HAS_ES if has_es is UNSET else bool(has_es)


def detect_availability(windows=None):
    """What this machine can actually run: `(db_kind, has_es)`, for the live
    guard to pass into filename_search_suggestion() and evaluate_search().

    Only the deny path calls this. Everything else keeps the assumed values
    above, so policy generation stays identical on every host."""
    return (plocate_db_kind(), es_available(windows))


_HOME_DB_LINE = "plocate -d ~/.cache/plocate/home.db -i '<pattern>'"


def _with_plocate_line(template, plocate_line):
    """`template` with the plocate invocation this machine can actually
    run. The constant itself is returned untouched when the machine has
    the home database the constants were written for, so a caller can
    still compare against it by identity."""
    if plocate_line == _HOME_DB_LINE:
        return template
    return template.replace(_HOME_DB_LINE, plocate_line, 1)


def _mixed_suggestion(plocate_line):
    return _with_plocate_line(ES_WSL_MIXED_SUGGESTION, plocate_line)


def _whole_fs_suggestion(plocate_line):
    return _with_plocate_line(ES_WSL_WHOLE_FS_SUGGESTION, plocate_line)


def _linux_mixed_suggestion(plocate_line):
    return _with_plocate_line(LINUX_MIXED_SUGGESTION, plocate_line)

# A WSL mount point for a Windows drive: "/mnt/c", "/mnt/c/Users/...".
_WSL_MOUNT_RE = re.compile(r"^/mnt/([A-Za-z])(?=/|$)")


def root_is_windows_host(root, windows=None):
    """True when `root` names a path that lives on the Windows host.

    Under WSL that is the drive-mount shape alone: `/mnt/c`, `/mnt/c/Users`.
    The MSYS and Cygwin spellings winpath also recognises must NOT count
    there, because `/c/projects` under WSL is an ordinary Linux directory
    that Everything cannot search -- reading it as a drive made the guard
    deny a working crawl and hand back a query for a path that does not
    exist on the Windows side (Codex P2, PR #1). On native Windows every
    spelling winpath knows is genuine Windows ground.

    Pure string work: never touches the filesystem, never raises on a None
    or empty root."""
    if not root:
        return False
    try:
        s = str(root)
    except Exception:
        return False
    if _WSL_MOUNT_RE.match(s):
        return True
    if not is_windows(windows):
        return False
    try:
        return bool(winpath.looks_windows_path(s))
    except Exception:
        return False


def any_root_is_windows_host(roots, windows=None):
    """root_is_windows_host over a possibly-None/empty list of roots."""
    for root in roots or []:
        if root_is_windows_host(root, windows):
            return True
    return False


def any_root_is_linux_side(roots, windows=None):
    """True when any root is NOT on the Windows host, i.e. ground plocate can
    actually index. The complement of root_is_windows_host over the same list,
    so a mixed search (`find "$HOME" /mnt/c/Users -name x`) answers True to
    this AND to any_root_is_windows_host, and neither index alone will do."""
    for root in roots or []:
        if not root_is_windows_host(root, windows):
            return True
    return False


# Which replacement commands this machine can actually run, and which
# plocate database it has. Steering a session to a tool it does not have
# is worse than the crawl: the deny blocks the only command that would
# have worked. Both are cached -- the deny path is rare, but the answer
# cannot change inside one hook call, and `shutil` is imported lazily so
# this costs nothing on the calls that never reach a deny.
_AVAILABILITY_CACHE = {}

#: plocate's own default database, indexing whatever updatedb was told to
#: index (the whole filesystem, minus its prune list, on a stock install).
SYSTEM_PLOCATE_DB = "/var/lib/plocate/plocate.db"
#: The $HOME-only database this kit's own filesearch timer builds.
HOME_PLOCATE_DB = "~/.cache/plocate/home.db"


def reset_availability_cache():
    """Forget what was detected about this machine.

    The cache keys on $HOME, so a caller that changes $HOME -- a test, or a
    hook run for a different user -- would otherwise keep reading the
    previous user's answer and name a database that is not theirs."""
    _AVAILABILITY_CACHE.clear()


def _tool_on_path(name):
    """shutil.which(name), cached, never raising."""
    key = ("which", name)
    if key not in _AVAILABILITY_CACHE:
        try:
            import shutil
            _AVAILABILITY_CACHE[key] = bool(shutil.which(name))
        except Exception:
            _AVAILABILITY_CACHE[key] = False
    return _AVAILABILITY_CACHE[key]


def es_available(windows=None):
    """Is Everything usable, client AND index?

    `es` on PATH is not enough: with the Everything service stopped the
    client runs and returns nothing, so a deny would block a working crawl
    in favour of a command that reports every file as absent (Codex P1,
    PR #1). airlock.everything.status() already defines usability as the
    client being present and the service not known to be stopped, so that
    is the answer used here. A service state it cannot determine counts as
    usable, matching status()'s own `ok`.

    Cached: the subprocess probes behind it are too slow to repeat, and the
    answer cannot change inside one hook call. Falls back to PATH presence
    alone if the probe itself fails."""
    key = ("es_usable", bool(is_windows(windows)))
    if key not in _AVAILABILITY_CACHE:
        present = (_tool_on_path("es.exe") or _tool_on_path("es")) \
            if is_windows(windows) else _tool_on_path("es")
        usable = present
        if present:
            # Only the SERVICE check comes from airlock.everything. Its
            # find_es() searches for `es.exe` alone, so on the documented
            # WSL setup -- a bare `es` client on PATH and no `es.exe` --
            # status()["ok"] is False and Everything would be written off
            # as missing although it works (Codex P1, PR #1). Presence is
            # decided above, from the name this platform actually uses.
            #
            # Only a probe that came back RUNNING counts. An indeterminate
            # answer -- which is what a probe that cannot run returns --
            # must not read as usable: with Everything stopped and the
            # client still on PATH, `es` runs and returns nothing, so a
            # deny would block a working crawl for a query that finds no
            # files (Codex P1, PR #1). No answer means no deny, and the
            # crawl is merely slow.
            try:
                from . import everything
                usable = everything.service_running() is True
            except Exception:
                usable = False
        _AVAILABILITY_CACHE[key] = bool(usable)
    return _AVAILABILITY_CACHE[key]


def plocate_db_kind():
    """Which plocate database this machine has, and so what it covers:

    - "home": this kit's `~/.cache/plocate/home.db`, which indexes $HOME
      and nothing else, so /etc and /opt are NOT in it.
    - "system": plocate's own /var/lib/plocate/plocate.db, which indexes
      the whole Linux side.
    - None: plocate is not installed, or has no database. There is then no
      replacement to offer for a Linux-side root, and offering one anyway
      produces a deny whose suggestion fails with "no such file".

    The home database wins when both exist, because it is the one this kit
    installs and keeps current.
    """
    try:
        key = ("plocate_db", os.path.expanduser("~"))
    except Exception:
        key = ("plocate_db", "")
    if key not in _AVAILABILITY_CACHE:
        kind = None
        try:
            exe = "plocate" if _tool_on_path("plocate") else (
                "locate" if _tool_on_path("locate") else None)
            if exe:
                if os.path.exists(os.path.expanduser(HOME_PLOCATE_DB)):
                    kind = "home" if exe == "plocate" else "home-locate"
                elif os.path.exists(SYSTEM_PLOCATE_DB):
                    kind = "system" if exe == "plocate" else "system-locate"
        except Exception:
            kind = None
        _AVAILABILITY_CACHE[key] = kind
    return _AVAILABILITY_CACHE[key]


def plocate_command(db_kind=None):
    """The invocation to suggest: the database present, named with the
    executable actually installed.

    A machine with `locate` but no `plocate` was handed `plocate -i ...`,
    a command it cannot run (Codex P2, PR #1). `locate` takes the same -d
    and -i flags, so only the program name differs."""
    kind = db_kind if db_kind is not None else plocate_db_kind()
    exe = "locate" if str(kind or "").endswith("-locate") else "plocate"
    if str(kind or "").startswith("home"):
        return "%s -d %s -i '<pattern>'" % (exe, HOME_PLOCATE_DB)
    return "%s -i '<pattern>'" % exe


def resolve_root(root):
    """`root` with symlinks resolved.

    A Linux-side path can BE Windows-host ground: ~/notes/vault is a
    symlink into /mnt/c on this machine, so a search there is a crawl over
    the 9p bridge that plocate's index has never seen (updatedb does not
    follow symlinks out of $HOME). Classifying the unresolved path sends
    the session to the one index that cannot answer it -- the same failure
    this branch exists to fix, one indirection along. Falls back to the
    original string if the path cannot be resolved."""
    if not root:
        return root
    try:
        return os.path.realpath(os.path.expanduser(str(root)))
    except Exception:
        return root


def resolve_roots(roots, follow_symlinks=True):
    """resolve_root over a possibly-None list, order and length preserved.

    With `follow_symlinks` false the roots come back untouched. GNU find
    without -L or -H examines a symlink root itself and never enters its
    target, so resolving one there would classify a command as a
    Windows-host crawl when the command visits nothing on the Windows host,
    and the replacement would enumerate a whole tree the original never
    touched (Codex P2, PR #1)."""
    if not follow_symlinks:
        return list(roots or [])
    return [resolve_root(r) for r in roots or []]


# find follows a symlink root only when told to: -L everywhere, -H for the
# command-line arguments alone. Both make a symlinked root's target the real
# search ground.


def command_follows_symlinks(command):
    """True when every search stage in `command` makes a symlinked root's
    target the ground actually searched.

    False for a plain `find link -name x`, and True when the program is not
    find at all, since the ordinary case elsewhere (ls, grep -r, rg) is to
    follow what the path resolves to.

    Decided per stage, because `find -L a -name x; find b -name y` follows
    symlinks in one stage and not the other, and a command-wide answer
    would apply the wrong rule to one of them (Codex P2, PR #1). The roots
    reaching policy are a merged list with no stage attached, so a command
    with any non-following find stage is treated as not following: the
    roots then stay unresolved, a symlink is classified as the Linux path
    it is spelled as, and the guard allows the crawl. Erring that way costs
    a slow search; erring the other way blocks a command and recommends one
    that searches a tree the original never enters."""
    if not command:
        return True
    try:
        text = str(command)
    except Exception:
        return True
    try:
        from . import scope as _scope
        segments = _scope.shell_segments(text)
    except Exception:
        segments = None
    if segments is None:
        # Unlexable, so the stages are unknown. Treat the command as not
        # following: the roots then stay unresolved and the crawl is
        # allowed, which is the harmless direction.
        return False
    for tokens in segments:
        if _scope.segment_program(tokens) != "find":
            continue
        if not _find_dereferences(_scope._strip_prefixes(list(tokens))[1:]):
            return False
    return True


def _find_dereferences(args):
    """Does this find stage follow a symlinked root?

    Only find's LEADING global options answer that. `-L` later in the
    command line is an argument: in `find link -name -L` it is the pattern
    -name matches, and scanning the whole stage read it as dereferencing
    and classified a symlink into /mnt/c as Windows-host ground (Codex P2,
    PR #1)."""
    follows = False
    skip_value = False
    for tok in args:
        if skip_value:
            skip_value = False
            continue
        # "If more than one of -H, -L, -P is specified, each overrides the
        # others; the last one takes effect" -- find(1).
        if tok in ("-L", "-H"):
            follows = True
            continue
        if tok == "-P":
            follows = False
            continue
        if tok in _scope_find_value_flags():
            skip_value = True
            continue
        if len(tok) > 2 and tok[:2] in _scope_find_value_flags():
            continue
        # The first token that is not a global option ends them: from here
        # on come the roots and then the expression.
        break
    return follows


def _scope_find_value_flags():
    try:
        from . import scope as _scope
        return _scope._FIND_GLOBAL_FLAGS_WITH_VALUE
    except Exception:
        return {"-D", "-O"}


def root_is_plocate_covered(root, home=None, db_kind=None):
    """True when the plocate database this machine has actually covers
    `root`.

    With the kit's own home.db that means $HOME and below, and a Linux
    root such as /opt or /etc is NOT in it -- reading every non-Windows
    root as "plocate's ground" made the mixed suggestion promise results
    it cannot return (Codex P1, PR #1). With plocate's system database the
    whole Linux side is indexed. With no database at all, nothing is."""
    if not root:
        return False
    kind = db_kind if db_kind is not None else plocate_db_kind()
    if kind is None:
        return False
    # "home-locate"/"system-locate" differ only in the executable name.
    kind = str(kind).split("-")[0]
    try:
        r = os.path.normpath(str(root))
    except Exception:
        return False
    if root_is_windows_host(r):
        return False
    if root_is_wsl_fs_root(r):
        # "/" also reaches every mounted Windows drive, which no plocate
        # database holds.
        return False
    if kind == "system":
        return True
    try:
        base = os.path.normpath(home or os.path.expanduser("~"))
    except Exception:
        return False
    return r == base or r.startswith(base.rstrip("/") + "/")


def any_root_is_plocate_covered(roots, home=None, db_kind=None):
    """root_is_plocate_covered over a possibly-None/empty list of roots."""
    for root in roots or []:
        if root_is_plocate_covered(root, home, db_kind):
            return True
    return False


def any_root_is_uncovered_linux(roots, home=None, db_kind=None):
    """True when a root is Linux-side ground NO index holds: a Linux path
    the plocate database does not cover, or '/' itself (which also reaches
    every /mnt/<drive>). These are the roots a replacement command must
    keep crawling, or it reports files there as absent."""
    for root in roots or []:
        if root_is_wsl_fs_root(root):
            return True
        if not root_is_windows_host(root) \
                and not root_is_plocate_covered(root, home, db_kind):
            return True
    return False


def root_is_wsl_fs_root(root):
    """True when `root` is the WSL filesystem root itself ('/'). Unlike a
    plain Linux root -- which root_is_windows_host correctly reads as pure
    Linux-side ground -- a WSL '/' also traverses every mounted Windows
    drive under /mnt, so it is both sides at once and neither
    root_is_windows_host nor its complement alone describes it."""
    if not root:
        return False
    try:
        return os.path.normpath(str(root)) == "/"
    except Exception:
        return False


def any_root_is_wsl_fs_root(roots):
    """root_is_wsl_fs_root over a possibly-None/empty list of roots."""
    for root in roots or []:
        if root_is_wsl_fs_root(root):
            return True
    return False


# The indexed tool this platform already has. One function so the rule text,
# the deny reason and the doctor all say the same thing on each OS, and no
# caller has to test sys.platform for itself.
def filename_search_suggestion(windows=None, roots=None, wsl=None,
                               db_kind=UNSET, has_es=UNSET,
                               follow_symlinks=True):
    """The command to run INSTEAD of a disk-wide filename crawl.

    Native Windows gets ES_SUGGESTION, unless Everything is unusable on
    this machine -- the client missing, or the service stopped so that it
    answers every query with nothing. There is then no replacement to name
    and the answer is None, which its callers read as "no deny", leaving
    the slow crawl to do the job (review finding, PR #1: the docstring
    still said "always" after that gate was added). Otherwise, under WSL, a root
    that lives on the Windows host (/mnt/<drive>/...) gets ES_WSL_SUGGESTION
    instead of the plocate suggestion, since plocate's index never covers
    that ground; roots on BOTH sides get ES_WSL_MIXED_SUGGESTION, which names
    both commands, since replacing a mixed search with either index alone
    silently drops every result from the other half. A root of '/' itself
    is both sides at once -- traversing it also traverses every mounted
    Windows drive -- so it gets the mixed suggestion too, even alone
    (Codex P1, PR #1: it previously fell through to PLOCATE_SUGGESTION and
    silently dropped every Windows-host result). Everything else gets
    PLOCATE_SUGGESTION. `wsl` defaults
    lazily from airlock.headless.is_wsl() so existing zero-arg and
    windows=-only call sites keep working unchanged; a failure to detect WSL
    is treated as False, never raised."""
    if is_windows(windows):
        return ES_SUGGESTION if _es_ok(windows, has_es) else None
    wsl = _wsl_default(wsl)
    roots = resolve_roots(roots, follow_symlinks=follow_symlinks)
    kind = ASSUMED_DB_KIND if db_kind is UNSET else db_kind
    plocate_line = plocate_command(kind)
    if wsl:
        has_es = _es_ok(windows, has_es)
        needs_es = (any_root_is_windows_host(roots, windows)
                    or any_root_is_wsl_fs_root(roots))
        covered = any_root_is_plocate_covered(roots, db_kind=kind)
        uncovered = any_root_is_uncovered_linux(roots, db_kind=kind)
        if needs_es and not has_es:
            # Everything is the only thing that can answer a Windows-host
            # root. Without it there is no replacement to offer, and a deny
            # would block the one command that does work.
            return None
        if uncovered:
            # Ground no index holds. When the search never leaves the Linux
            # side, the crawl the user typed IS the answer: plocate cannot
            # see the root, Everything cannot see the Linux side, and the
            # whole-filesystem advice would name `es` for /mnt/<drive> roots
            # this command never searched (review finding, PR #1). Denying a
            # working crawl to recommend the same crawl back helps nobody.
            #
            # The whole-filesystem advice applies to the MIXED case alone,
            # where a Windows-host root or `/` is in play. It names plocate
            # for the Linux half, so with no database that line is a command
            # the machine cannot run and the remaining `find <dir>` line
            # covers only paths outside $HOME, dropping the home-side
            # results (Codex P1, PR #1). No database, no deny.
            if kind is None:
                return None
            if not needs_es:
                # Linux side only. Everything indexes the Windows host, so
                # the whole-filesystem advice would name `es` for
                # /mnt/<drive> roots this command never searched (review
                # finding, PR #1). With an indexed root in the search there
                # is still better advice; with none there is nothing to
                # offer, and denying a working crawl to recommend the same
                # crawl back helps nobody.
                if not covered:
                    return None
                return _linux_mixed_suggestion(plocate_line)
            return _whole_fs_suggestion(plocate_line)
        if needs_es:
            if covered:
                if kind is None:
                    return None
                return _mixed_suggestion(plocate_line)
            return ES_WSL_SUGGESTION
    if kind is None:
        return None
    if plocate_line == _HOME_DB_LINE:
        return PLOCATE_SUGGESTION
    return plocate_line


_LOCATE_RE = re.compile(r"(?<![A-Za-z0-9_])(plocate|locate)(?![A-Za-z0-9_])")
# `es` and `es.exe`, in COMMAND POSITION only: at the start, or straight after
# a shell separator. Two letters would otherwise match inside any word, and a
# plain-whitespace prefix was too loose -- it also matched `es` as an argument,
# so `find / -name es` read as "already using the indexed tool" and suppressed
# the very deny it should have triggered. This raw regex still does not know
# about quoting, so it is now only a fallback (see _command_position_is_es)
# for a segment shlex itself cannot parse.
_ES_RE = re.compile(r"(?:^|[\n;&|(])\s*es(?:\.exe)?(?=\s|$)", re.IGNORECASE)

def _strip_shell_comment(command):
    """scope.strip_shell_comment(), so policy and the scope parser read a
    shell comment the same way. Two copies drifted apart once already: the
    comment fix landed here and not in scope, and a commented-out stage was
    still accumulated as a real search root (Codex P2, PR #1)."""
    try:
        from . import scope as _scope
        return _scope.strip_shell_comment(command)
    except Exception:
        return command


def _invokes_program(command, names):
    """Does any stage of `command` actually INVOKE one of `names`?

    Answered from scope's shell lexer, so a quoted separator, an escaped
    separator or a comment cannot turn an argument into a command. Falls
    back to the raw regexes only when the command cannot be lexed at all,
    which is an unterminated quote.
    """
    wanted = {n.lower() for n in names}
    try:
        from . import scope as _scope
        segments = _scope.shell_segments(command)
        if segments is not None:
            for tokens in segments:
                program = _scope.segment_program(tokens)
                if program and program.lower() in wanted:
                    return True
            return False
    except Exception:
        pass
    text = command or ""
    if wanted & {"es", "es.exe"} and _ES_RE.search(text):
        return True
    if wanted & {"locate", "plocate"} and _LOCATE_RE.search(text):
        return True
    return False


_HELP_FLAGS = frozenset({"-h", "--help", "-help", "/?", "-version",
                         "--version", "-v"})
_DRIVE_SPELLING_RE = re.compile(r"^([A-Za-z]):[\\/]?(.*)$")


def _indexed_segments(command, names):
    """Every stage of `command` whose program is one of `names`, as token
    lists. Empty when the command cannot be lexed."""
    wanted = {n.lower() for n in names}
    try:
        from . import scope as _scope
        segments = _scope.shell_segments(command)
        if segments is None:
            return []
        out = []
        for tokens in segments:
            program = _scope.segment_program(tokens)
            if program and program.lower() in wanted:
                out.append(tokens)
        return out
    except Exception:
        return []


def _is_a_real_search(tokens):
    """Does this invocation search anything?

    `es -h` prints help. It was counted as Everything answering the crawl
    beside it, which suppressed the deny for a genuine Windows-host search
    (review finding, PR #1)."""
    args = tokens[1:]
    if any(a.lower() in _HELP_FLAGS for a in args):
        return False
    return any(not a.startswith("-") for a in args) or bool(args)


# `C:\Users\bob`, `d:\data` -- a drive letter followed by backslash-
# separated segments. Nothing else in a command looks like this, so
# rewriting only these separators leaves every other escape intact.
_DRIVE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z]:)((?:\\[^\s\\\"';|&<>]+)+)")


def _forward_slash_drive_paths(command):
    """`command` with the backslashes INSIDE a drive-letter path turned
    into forward slashes, so the lexer cannot eat them as escapes."""
    if not command or "\\" not in command:
        return command
    return _DRIVE_PATH_RE.sub(
        lambda m: m.group(1) + m.group(2).replace("\\", "/"), command)


def _es_path_as_wsl(value):
    """An Everything `-path` value as the WSL path it names, or None when
    the spelling is not one we can place."""
    if not value:
        return None
    text = value.replace("\\", "/")
    match = _DRIVE_SPELLING_RE.match(text)
    if match:
        return "/mnt/%s/%s" % (match.group(1).lower(), match.group(2))
    if _WSL_MOUNT_RE.match(text):
        return text
    return None


def _es_scopes(tokens):
    """The `-path` values of one es invocation, as WSL paths. None means
    the invocation is not restricted and so reaches every indexed drive."""
    scopes = []
    restricted = False
    args = tokens[1:]
    for index, arg in enumerate(args):
        if arg.lower() != "-path":
            continue
        restricted = True
        if index + 1 < len(args):
            placed = _es_path_as_wsl(args[index + 1])
            if placed:
                scopes.append(placed)
    if not restricted:
        return None
    return scopes


def _es_covers_windows_roots(command, roots, windows=None):
    """Does an Everything invocation in `command` actually cover every
    Windows-host root the command searches?

    Naming `es` anywhere used to be enough, so `find /mnt/c/Users -name x;
    es -h` read as covered and the deny disappeared (review finding, PR #1).
    """
    targets = [r for r in (roots or []) if root_is_windows_host(r, windows)]
    if not targets:
        return True
    # An unquoted `-path C:\Users\bob` loses its backslashes to POSIX
    # lexing and reads as `C:Usersbob`, so an invocation already scoped to
    # the crawled directory looked like it covered something else (review
    # finding, PR #1). Only the separators inside a drive-letter path are
    # rewritten, so `\;` and `\#` elsewhere keep their meaning.
    for tokens in _indexed_segments(_forward_slash_drive_paths(command),
                                    ("es", "es.exe")):
        if not _is_a_real_search(tokens):
            continue
        scopes = _es_scopes(tokens)
        if scopes is None:
            # No -path: Everything searches every indexed drive.
            return True
        remaining = [t for t in targets
                     if not any(winpath.is_under(t, s) for s in scopes)]
        if not remaining:
            return True
        targets = remaining
    return False


def _locate_is_a_real_search(command):
    """Is a locate/plocate stage an actual query rather than `plocate -h`?

    Its index covers the same ground whatever pattern is asked for, so the
    pattern itself is not correlated -- that would be guessing at what the
    author meant to find."""
    for tokens in _indexed_segments(command, ("locate", "plocate")):
        if _is_a_real_search(tokens):
            return True
    return False


def _command_position_is_es(command):
    """Is `es`/`es.exe` the program invoked somewhere in `command`, rather
    than text that merely follows a ;/&/| sitting inside a quoted argument,
    an escape or a comment?"""
    return _invokes_program(command, ("es", "es.exe"))


def _command_position_is_locate(command):
    """Is `locate`/`plocate` actually invoked?

    `find "$HOME" /mnt/c -name plocate; es -path C:/ x` names plocate as a
    filename pattern. Matching it anywhere in the text concluded that both
    indexes were present and left the Linux-side crawl unsteered (Codex P2,
    PR #1)."""
    return _invokes_program(command, ("locate", "plocate"))


def command_already_uses_locate(command):
    """Does the command already reach for the INDEXED tool?

    Kept under its original name because that is what the deny path calls it
    and what the tests assert. On Windows it also recognises `es`/`es.exe`,
    so the guard never tells a session to replace Everything with Everything.
    """
    return command_already_uses_indexed_search(command)


def command_already_uses_indexed_search(command, windows=None, wsl=None):
    command = command or ""
    if _command_position_is_locate(command):
        return True
    if is_windows(windows):
        if _command_position_is_es(command):
            return True
        return False
    if wsl is None:
        try:
            from . import headless
            wsl = headless.is_wsl()
        except Exception:
            wsl = False
    if wsl and _command_position_is_es(command):
        return True
    return False


def _wsl_default(wsl):
    """`wsl` as given, or detected. A detection failure is False, never
    an exception."""
    if wsl is not None:
        return wsl
    try:
        from . import headless
        return headless.is_wsl()
    except Exception:
        return False


def command_covers_roots(command, roots=None, windows=None, wsl=None,
                         db_kind=UNSET, has_es=UNSET):
    """Does the command already reach for an index that covers EVERY root it
    searches?

    `db_kind` and `has_es` carry what the CALLER knows about the machine,
    exactly as they do for filename_search_suggestion(). Detecting here
    instead put live host state back into a verdict the caller had already
    pinned: with an explicit db_kind of "system", `plocate -i x; find /opt
    -name y` answered would_deny False on a host with a system database and
    True on a host with only home.db (review finding, PR #1).

    `command_already_uses_indexed_search` answers "is an indexed tool in this
    command at all", which is the wrong question for a mixed WSL search:
    `find "$HOME" /mnt/c/Users -name x; es -path "C:\\Users" x` mentions `es`,
    but Everything indexes only the Windows half, so the expensive crawl of
    the Linux half is still unanswered (Codex P2, PR #1). With no roots to
    go on this falls back to the plain "an index is present" answer.
    """
    command = command or ""
    if is_windows(windows):
        return command_already_uses_indexed_search(command, windows, wsl)
    if not _wsl_default(wsl) or not roots:
        return command_already_uses_indexed_search(command, windows, wsl)
    kind = ASSUMED_DB_KIND if db_kind is UNSET else db_kind
    es_ok = ASSUMED_HAS_ES if has_es is UNSET else bool(has_es)
    roots = resolve_roots(roots,
                          follow_symlinks=command_follows_symlinks(command))
    if any_root_is_uncovered_linux(roots, db_kind=kind):
        # Ground no index holds: naming plocate and es cannot answer it, so
        # the crawl is not already covered however many indexes appear.
        return False
    needs_windows = any_root_is_windows_host(roots, windows)
    if any_root_is_plocate_covered(roots, db_kind=kind) \
            and not _locate_is_a_real_search(command):
        return False
    if needs_windows and not (es_ok
                              and _es_covers_windows_roots(command, roots,
                                                           windows)):
        # Naming `es` covers a Windows-host root only while Everything can
        # answer: with the service stopped the client runs and reports every
        # file as absent. `has_es` was accepted here and never read, so the
        # es half of this function ignored the machine while the plocate
        # half honoured it (review finding, PR #1).
        return False
    return True


# --- scope x search_intent policy table -------------------------------------
#
# scope (disk_wide / single_repo / single_dir / stdin / unknown) is a fact
# computed in code by airlock/scope.py, never asked of Jev. search_intent
# (filename_search / code_structure_search / literal_text_search /
# not_a_search / unclear) is the one fuzzy question Jev still answers. This
# table is the only place the two combine into a verdict.


def evaluate_search(scope, search_intent, confidence, command, root_has_graphify_graph,
                    margin=None, windows=None, roots=None, wsl=None,
                    db_kind=UNSET, has_es=UNSET):
    """Return the tool-choice-guard verdict for one Bash search command.

    would_deny (indexed-search suggestion): scope == disk_wide AND
    search_intent == filename_search AND the command doesn't already use the
    indexed tool (plocate/locate on Linux, es/es.exe on Windows or WSL),
    gated on the shared confidence+margin deny bar. The suggestion string
    itself comes from filename_search_suggestion(), so the advice is right
    for the OS and, under WSL, for which side of the filesystem `roots`
    actually lands on.

    would_deny (graphify suggestion): search_intent == code_structure_search
    AND the root already has a graphify graph, gated the same way.

    Everything else -- including every case where scope is single_repo,
    single_dir, stdin or unknown -- allows.
    """
    would_deny = False
    suggestion = None

    if meets_deny_bar(confidence, margin):
        # A root on the Windows host is deny-eligible whatever the scope
        # says. `find /mnt/c/Users -name x` is a single directory by the
        # scope table, but it is still a crawl of the Windows filesystem
        # over the 9p bridge, and Everything answers it instantly
        # (Codex P1, PR #1).
        follows = command_follows_symlinks(command)
        resolved = resolve_roots(roots, follow_symlinks=follows)
        windows_host_root = (
            not is_windows(windows)
            and _wsl_default(wsl)
            and any_root_is_windows_host(resolved, windows)
        )
        if (
            (scope == "disk_wide" or windows_host_root)
            and search_intent == "filename_search"
            and not command_covers_roots(command, roots, windows, wsl,
                                         db_kind=db_kind, has_es=has_es)
        ):
            suggestion = filename_search_suggestion(
                windows, roots, wsl, db_kind=db_kind, has_es=has_es,
                follow_symlinks=follows)
            # No usable replacement on this machine means no deny. Blocking
            # a crawl and naming a tool the box does not have takes away the
            # only command that would have answered the question.
            would_deny = suggestion is not None
        elif search_intent == "code_structure_search" and root_has_graphify_graph:
            would_deny = True
            suggestion = GRAPHIFY_SUGGESTION

    return {"would_deny": would_deny, "suggestion": suggestion}


# --- Skip table: only spend a Jev call when a deny is possible --------------
#
# The A/B bench (30 sessions) showed zero denies -- agents already pick the
# right tool almost every time, so most judgements are 100% wasted latency
# (~300ms each) for no chance of ever changing the outcome. Both deny
# policies above are gated on code-computed facts (scope, program, rung)
# BEFORE Jev is ever asked, so it is possible to know in advance, from those
# same facts, whether a deny is even reachable -- and skip the call entirely
# when it isn't. A random sample of skipped calls is still judged (never
# denying) so the tuning loop keeps seeing ordinary, ambient traffic instead
# of a corpus consisting only of already-flagged cases.

GREP_LIKE_PROGRAMS = {"grep", "egrep", "fgrep", "rg", "ag", "ack"}
SKIP_LOCATE_FAMILY = {"locate", "plocate", "es"}
DEFAULT_SAMPLE_RATE = 0.05
SAMPLE_RATE_ENV = "AIRLOCK_SAMPLE_RATE"
SAMPLE_RATE_ENV_LEGACY = ("PLUMBLINE_SAMPLE_RATE", "JEV_GUARD_SAMPLE_RATE")


def deny_possible_bash(scope, program, root_has_graphify_graph,
                       roots=None, windows=None, wsl=None, command=None):
    """True iff a Bash search-command judgement could possibly end in a deny,
    mirroring evaluate_search's own two deny branches:

    (a) scope is disk_wide and the program isn't already locate/plocate
        (the only way to reach the plocate-suggestion deny), or
    (b) the program is in the grep family (grep/egrep/fgrep/rg/ag/ack) AND
        the search root already has a graphify graph (the only way to reach
        the graphify-suggestion deny).

    Everything else -- single_repo/single_dir/stdin/unknown scope with no
    graph, or an already-locate command -- can never deny regardless of what
    Jev answers, so it is safe to skip the call."""
    # `command` decides whether a symlinked root counts as its target, on
    # the same rule evaluate_search uses: a plain `find ~/notes/vault` never
    # enters the tree the link points at. Resolving regardless said "deny
    # possible" for a command evaluate_search would never deny, and every
    # search through such a link then paid for a Jev call that could only
    # come back allow (review finding, PR #1). Omitted, it resolves, which
    # keeps the pre-filter on the safe side: a needless call costs money, a
    # missed one costs the deny.
    resolved = resolve_roots(
        roots,
        follow_symlinks=True if command is None
        else command_follows_symlinks(command))
    on_wsl = not is_windows(windows) and _wsl_default(wsl)
    # An indexed program in the command excuses the call only when that
    # index covers every root searched: naming plocate while another stage
    # crawls the Windows host leaves the crawl unanswered, and Everything
    # covers nothing on the Linux side (Codex P2, PR #1).
    indexed_program = program in SKIP_LOCATE_FAMILY
    if indexed_program and on_wsl and resolved:
        if program == "es":
            indexed_program = all(root_is_windows_host(r) for r in resolved)
        else:
            indexed_program = not (any_root_is_windows_host(resolved)
                                   or any_root_is_uncovered_linux(resolved))
    if scope == "disk_wide" and not indexed_program:
        return True
    # A root on the Windows host is deny-eligible whatever the scope says,
    # matching evaluate_search's own branch: `find /mnt/c/Users -name x`
    # scopes as single_dir and is still a crawl of the Windows filesystem.
    # Without this the guard skipped the call as "no deny possible" and the
    # branch below could never run (Codex P1, PR #1).
    if not indexed_program and on_wsl and any_root_is_windows_host(resolved):
        return True
    if program in GREP_LIKE_PROGRAMS and root_has_graphify_graph:
        return True
    return False


def deny_possible_agent(subagent_type):
    """True iff an Agent dispatch could possibly be denied. The tier guard
    can only deny when the chosen rung is strictly above the adequate rung
    for the judged task_kind (or fable without a stated prior failure).
    scout-find is the cheapest rung in RUNG_ORDER, adequate for every
    task_kind in TASK_KIND_ADEQUATE_RUNG (including the cheapest,
    "lookup"), so nothing can ever be judged as needing something cheaper
    still -- a scout-find dispatch can never be over-tiered, and it is never
    "fable", so the stated-failure rule can't fire either. Everything else
    (scout and up) keeps at least one reachable deny path, so it still gets
    judged."""
    return rung_for_agent_type(subagent_type) != tiers.rung_names()[0]


def sample_rate():
    """AIRLOCK_SAMPLE_RATE, default 0.05. Never raises -- a bad value falls
    back to the default rather than breaking the skip decision."""
    try:
        from . import paths
        return float(paths.env(SAMPLE_RATE_ENV, *SAMPLE_RATE_ENV_LEGACY,
                              default=str(DEFAULT_SAMPLE_RATE)))
    except Exception:
        return DEFAULT_SAMPLE_RATE
