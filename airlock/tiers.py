"""The sub-agent ladder: one place that knows which agent types are which rung.

Agent type names differ per machine -- one box calls the Sonnet worker
`worker`, another `workerS`, a third has a house agent nobody else has. Every
part of the tier guard (policy, the enforce-mode block, the warn line, the
rewrite) reads the ladder from here, and here alone.

Config: ~/.config/airlock/tiers.json, an ordered list of lists of equivalent
names, cheapest rung first:

    [["scout-find"],
     ["scout"],
     ["workerS", "worker"],
     ["workerO"],
     ["claude", "general-purpose", "Plan", "Explore"],
     ["fable"]]

The first name in each list is the canonical rung name AND the name the guard
suggests (or rewrites to) for that rung, so put the type you actually want
dispatched first. Anything malformed -- not a list of non-empty lists of
strings, fewer than two rungs, a duplicated name -- is ignored whole and the
built-in ladder below is used instead; a broken config can never make the
guard misjudge a rung.

The built-in ladder keeps the historical rung name "director" for the
Opus-level rung, because the log, the tuning lock files and the tests all use
it. "director" is not a dispatchable subagent_type, so it is listed in
NON_DISPATCHABLE and the suggested name for that rung is the next entry,
"claude". A machine-supplied tiers.json has no such reserved name: its first
entry is both the rung name and the suggestion.
"""
import json

from . import paths

CONFIG_NAME = "tiers.json"

# Cheapest rung first. First entry of each list = canonical rung name.
DEFAULT_LADDER = [
    ["scout-find"],
    ["scout"],
    ["workerS", "worker"],
    ["workerO"],
    ["director", "claude", "general-purpose", "Plan", "Explore"],
    ["fable"],
]

# Rung names that are not real subagent_type values and must never be
# suggested or rewritten to.
NON_DISPATCHABLE = frozenset(["director"])

# subagent_type prefixes treated as the Opus-level rung (the plugin agents
# this box ships). Unchanged by config: they name a rung, not a type.
DIRECTOR_PREFIXES = ("feature-dev:", "code-simplifier:")

# Rung a type falls into when nothing matches: the second-most expensive rung
# (the Opus-level one), since an unrecognised subagent_type is at least as
# expensive as the director dispatching it directly.
_UNKNOWN_RUNG_FROM_TOP = 2

_CACHE = {}


def _valid(ladder):
    if not isinstance(ladder, list) or len(ladder) < 2:
        return False
    seen = set()
    for rung in ladder:
        if not isinstance(rung, list) or not rung:
            return False
        for name in rung:
            if not isinstance(name, str) or not name.strip():
                return False
            if name in seen:
                return False
            seen.add(name)
    return True


def load_ladder(path=None):
    """Read the ladder from config, falling back to DEFAULT_LADDER. Never
    raises, never returns something malformed."""
    p = path or str(paths.config_file(CONFIG_NAME))
    try:
        with open(p, "r") as f:
            data = json.load(f)
    except Exception:
        return [list(r) for r in DEFAULT_LADDER]
    if isinstance(data, dict):
        data = data.get("ladder")
    if not isinstance(data, list) or not _valid(data):
        return [list(r) for r in DEFAULT_LADDER]
    return [list(r) for r in data]


def ladder(path=None):
    """Cached load_ladder. A hook process lives for milliseconds, so the cache
    only ever saves repeated reads inside one process (the eval loop);
    reset_cache() clears it for tests."""
    key = path or ""
    if key not in _CACHE:
        _CACHE[key] = load_ladder(path)
    return _CACHE[key]


def reset_cache():
    _CACHE.clear()


def rung_names(path=None):
    return [rung[0] for rung in ladder(path)]


def rung_index(path=None):
    return {name: i for i, name in enumerate(rung_names(path))}


def rung_for_agent_type(subagent_type, path=None):
    """Canonical rung name for one subagent_type. Anything unrecognised lands
    on the Opus-level rung."""
    t = subagent_type or ""
    rungs = ladder(path)
    for rung in rungs:
        if t in rung:
            return rung[0]
    # A DIRECTOR_PREFIXES name lands here too: it IS the Opus-level rung.
    return rungs[max(0, len(rungs) - _UNKNOWN_RUNG_FROM_TOP)][0]


def dispatch_name_for_rung(rung_name, path=None):
    """The subagent_type to actually dispatch for a rung, or None if that rung
    has no dispatchable name (never suggest or rewrite to one of those)."""
    for rung in ladder(path):
        if rung[0] != rung_name:
            continue
        for name in rung:
            if name not in NON_DISPATCHABLE:
                return name
        return None
    return None


def is_known_agent_type(subagent_type, path=None):
    """True only if the name appears verbatim in the ladder. Used to refuse a
    rewrite to a type this machine does not actually have."""
    t = subagent_type or ""
    return any(t in rung for rung in ladder(path))
