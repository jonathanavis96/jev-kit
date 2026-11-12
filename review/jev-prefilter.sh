#!/usr/bin/env bash
# Run jev-review over a repository's current diff, boil its findings down to a
# few lines, and hand that to a review gate as a --note argument.
#
# The point is cheapness: a Jev pass over the diff costs a fraction of what an
# Opus reviewer costs, and its output is a hint -- "look hardest at these three
# files, for these reasons" -- not a verdict. The gate still does the review.
#
# FAILS OPEN, always. If jev-review is not installed, Node 24 is missing, the
# key is absent, the API is down, the repository has no diff, or the JSON comes
# back in a shape this script does not recognise, the gate is still run, just
# without a useful note. A prefilter that can block a review is worse than no
# prefilter.
#
# JavaScript and TypeScript only: that is what jev-review screens. Against a
# Python or shell repository it will find little or nothing, and this script
# says so in the note rather than pretending otherwise.
set -uo pipefail

REPO="${AIRLOCK_REVIEW_TARGET:-$PWD}"
REVIEW_DIR="${AIRLOCK_REVIEW_DIR:-$HOME/code/jev-review}"
GATE=""
MAX_FINDINGS="${AIRLOCK_REVIEW_MAX_FINDINGS:-5}"
TIMEOUT_S="${AIRLOCK_REVIEW_TIMEOUT_S:-300}"
NODE_MAJOR="24"
PRINT_ONLY=0

usage() {
  cat >&2 <<EOF
usage: $0 [--repo <path>] [--gate '<command>'] [--print] [--max-findings N]
          [-- <extra args passed to the gate>]

  --repo <path>        repository to review (default: \$PWD)
  --gate '<command>'   the review command to run; the note is appended as
                       --note '<summary>'. Default: \$AIRLOCK_REVIEW_GATE.
  --print              print the note and exit; run no gate
  --max-findings N     how many findings to name in the note (default $MAX_FINDINGS)
EOF
  exit 2
}

EXTRA=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo) REPO="${2:-}"; [ -n "$REPO" ] || usage; shift 2 ;;
    # `shift 2` with only one argument left fails without shifting, so a
    # trailing --gate or --max-findings would loop here forever.
    --gate) [ "$#" -ge 2 ] || usage; GATE="$2"; shift 2 ;;
    --max-findings) [ "$#" -ge 2 ] || usage; MAX_FINDINGS="$2"; shift 2 ;;
    --print) PRINT_ONLY=1; shift ;;
    --) shift; EXTRA=("$@"); break ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

GATE="${GATE:-${AIRLOCK_REVIEW_GATE:-}}"

warn() { echo "jev-prefilter: $*" >&2; }

# --- produce the note ------------------------------------------------------
note=""
raw=""

run_review() {
  [ -d "$REVIEW_DIR/.git" ] || { warn "no jev-review clone at $REVIEW_DIR (review/install.sh)"; return 1; }
  [ -d "$REPO/.git" ] || { warn "$REPO is not a git repository"; return 1; }

  local nvm_dir="${NVM_DIR:-$HOME/.nvm}" node_bin=""
  if [ -s "$nvm_dir/nvm.sh" ]; then
    # shellcheck disable=SC1091
    . "$nvm_dir/nvm.sh" --no-use
    node_bin="$(dirname "$(nvm which "$NODE_MAJOR" 2>/dev/null)" 2>/dev/null)"
  fi
  if [ -z "$node_bin" ] || [ ! -x "$node_bin/node" ]; then
    warn "Node $NODE_MAJOR not available via nvm; not changing the default Node"
    return 1
  fi

  # Absolute before the cd below: a relative --repo would otherwise name a
  # path inside the jev-review clone.
  local repo_abs
  repo_abs="$(cd "$REPO" && pwd)" || { warn "cannot resolve $REPO"; return 1; }

  raw="$(cd "$REVIEW_DIR" && PATH="$node_bin:$PATH" \
        timeout "$TIMEOUT_S" npm run --silent review:changes -- "$repo_abs" 2>/dev/null)" || {
    warn "review:changes failed or timed out after ${TIMEOUT_S}s"
    return 1
  }
  [ -n "$raw" ] || { warn "review:changes produced no output"; return 1; }
  return 0
}

# The script goes in through -c, not `python3 - <<'PY'`: a heredoc on stdin
# would replace the piped review JSON, and summarise would always read "".
SUMMARISE_PY="$(cat <<'PY'
import json, os, sys

raw = sys.stdin.read()
# The CLI logs progress to stderr and prints JSON to stdout, but be tolerant:
# take the outermost JSON object if anything else slipped in.
start = raw.find("{")
end = raw.rfind("}")
if start < 0 or end <= start:
    sys.exit(1)
try:
    report = json.loads(raw[start:end + 1])
except Exception:
    sys.exit(1)

findings = report.get("findings")
if not isinstance(findings, list):
    sys.exit(1)

limit = int(os.environ.get("MAX_FINDINGS") or 5)
screened = report.get("screenedFiles")


def sort_key(f):
    return -(f.get("severity") or 0)


ranked = sorted([f for f in findings if isinstance(f, dict)], key=sort_key)

lines = []
head = "jev-review prefilter (JS/TS only)"
if isinstance(screened, int):
    head += ": screened %d file(s)" % screened
head += ", %d finding(s)." % len(ranked)
lines.append(head)

if not ranked:
    lines.append("Nothing flagged. Treat that as no signal, not as a pass.")
else:
    lines.append("Highest-severity first; these are hints to look at, not verdicts:")
    for f in ranked[:limit]:
        lines.append(
            "  - %s:%s  %s (severity %s, confidence %s)" % (
                f.get("file") or "?",
                f.get("line") if f.get("line") is not None else "?",
                f.get("dimension") or f.get("mechanism") or "unspecified",
                f.get("severity"),
                f.get("severityConfidence"),
            )
        )
    if len(ranked) > limit:
        lines.append("  ... and %d more." % (len(ranked) - limit))

print("\n".join(lines))
PY
)"

summarise() {
  MAX_FINDINGS="$MAX_FINDINGS" REPO="$REPO" python3 -c "$SUMMARISE_PY" 2>/dev/null
}

if run_review; then
  note="$(printf '%s' "$raw" | summarise)" || note=""
fi

if [ -z "$note" ]; then
  note="jev-review prefilter unavailable for this run; review without it."
  warn "producing an empty note and continuing (fail open)"
fi

if [ "$PRINT_ONLY" = "1" ]; then
  printf '%s\n' "$note"
  exit 0
fi

# --- run the gate ----------------------------------------------------------
if [ -z "$GATE" ]; then
  warn "no --gate and no \$AIRLOCK_REVIEW_GATE, so there is nothing to run."
  warn "the note follows on stdout."
  printf '%s\n' "$note"
  exit 0
fi

# GATE is a command line, so it is deliberately word-split; the note is passed
# as one argument and never interpolated into the command string.
# shellcheck disable=SC2086
exec $GATE --note "$note" ${EXTRA[@]+"${EXTRA[@]}"}
