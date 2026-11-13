#!/usr/bin/env bash
# Clone valentynkit/jev-belay at a pinned commit, keep it as an immutable
# release under releases/<sha>, flip 'current' at it, install the wrapper,
# and PRINT the Stop-hook settings.json block -- this script never edits
# settings.json itself. Apply it to whichever account's settings you mean to
# run belay in. Start with one account only, in log mode, for a week, before
# turning it on anywhere else.
set -uo pipefail

UPSTREAM_URL="https://github.com/valentynkit/jev-belay"
UPSTREAM_COMMIT="98f39e0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BELAY_HOME="${AIRLOCK_BELAY_DIR:-$HOME/.local/share/jev-belay}"
BIN_DIR="$HOME/bin"
WRAPPER="$BIN_DIR/airlock-belay-run"

usage() {
  cat >&2 <<EOF
usage: $0 [--home <dir>]

  --home <dir>   where releases live (default: \$AIRLOCK_BELAY_DIR, else
                 \$HOME/.local/share/jev-belay)

Clones $UPSTREAM_URL at $UPSTREAM_COMMIT into <home>/releases/<sha>, flips
<home>/current at it, and installs the wrapper at $WRAPPER. The key file
path is read from the shared config (AIRLOCK_KEY_FILE in
install/config.env), not hard-coded.
EOF
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --home) BELAY_HOME="${2:-}"; [ -n "$BELAY_HOME" ] || usage; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

command -v git >/dev/null 2>&1 || { echo "belay: 'git' not found" >&2; exit 1; }
command -v node >/dev/null 2>&1 || { echo "belay: 'node' not found (jev-belay needs Node >= 20)" >&2; exit 1; }

# --- clone the pinned commit into an immutable release directory -----------
TMP_CLONE="$(mktemp -d)"
trap 'rm -rf "$TMP_CLONE"' EXIT

echo "belay: cloning $UPSTREAM_URL"
git clone --quiet "$UPSTREAM_URL" "$TMP_CLONE" || { echo "belay: clone failed" >&2; exit 1; }
git -C "$TMP_CLONE" checkout -q "$UPSTREAM_COMMIT" || {
  echo "belay: commit $UPSTREAM_COMMIT not found; upstream may have rewritten history." >&2
  exit 1
}
SHA="$(git -C "$TMP_CLONE" rev-parse --short=12 HEAD)"
RELEASE_DIR="$BELAY_HOME/releases/$SHA"

if [ -d "$RELEASE_DIR" ]; then
  echo "belay: release $SHA already present at $RELEASE_DIR; leaving it alone."
else
  mkdir -p "$(dirname "$RELEASE_DIR")"
  rm -rf "$TMP_CLONE/.git"
  mv "$TMP_CLONE" "$RELEASE_DIR"
  echo "belay: release $SHA -> $RELEASE_DIR"
fi
trap - EXIT
rm -rf "$TMP_CLONE" 2>/dev/null || true

# --- flip current atomically -------------------------------------------------
mkdir -p "$BELAY_HOME"
ln -sfn "$RELEASE_DIR" "$BELAY_HOME/.current.tmp.$$"
mv -T "$BELAY_HOME/.current.tmp.$$" "$BELAY_HOME/current"
echo "belay: current -> $RELEASE_DIR"

# --- the wrapper -------------------------------------------------------------
mkdir -p "$BIN_DIR"
# run.sh reads $BELAY_HOME/current/belay.mjs directly, so nothing else lands
# in $BIN_DIR. The home is baked in: the hook runs without AIRLOCK_BELAY_DIR,
# so a --home install otherwise fell back to the default and found nothing.
BAKED_HOME="belay_default_home=$(printf '%q' "$BELAY_HOME")" \
  awk '/^belay_default_home=/ { print ENVIRON["BAKED_HOME"]; next } { print }' \
  "$SCRIPT_DIR/run.sh" > "$WRAPPER.tmp.$$"
grep -q '^belay_default_home=' "$WRAPPER.tmp.$$" || {
  rm -f "$WRAPPER.tmp.$$"; echo "belay: could not write the wrapper" >&2; exit 1; }
chmod 755 "$WRAPPER.tmp.$$"
mv -f "$WRAPPER.tmp.$$" "$WRAPPER"
echo "belay: wrapper -> $WRAPPER (uses $BELAY_HOME/current)"

# Key-file resolution: the ONE shell implementation, shared with every other
# component here. The order and the pointer-file trust rules are documented in
# airlock/keyfile.py's module docstring. Fails open if the helper is missing.
if [ -r "$SCRIPT_DIR/../install/keyfile.sh" ]; then
  . "$SCRIPT_DIR/../install/keyfile.sh"
else
  airlock_key_file() {
    local f="${AIRLOCK_KEY_FILE:-${JEVKIT_KEY_FILE:-}}"
    if [ -n "$f" ]; then printf '%s\n' "$f"; return 0; fi
    [ -r "$HOME/.config/jev-kit/env" ] && { printf '%s\n' "$HOME/.config/jev-kit/env"; return 0; }
    [ -r "$HOME/.config/airlock/env" ] && { printf '%s\n' "$HOME/.config/airlock/env"; return 0; }
    printf '%s\n' "$HOME/.config/jev-kit/env"
  }
fi
KEY_FILE="$(airlock_key_file)"
if [ -r "$KEY_FILE" ]; then
  echo "belay: key file $KEY_FILE is readable"
else
  echo "belay: no readable key file at $KEY_FILE -- the wrapper still installs; with no"
  echo "  key set it fails open (exits 0, does nothing), same as the guard."
fi

cat <<EOF

Installed. This script has NOT touched any settings.json. Add this Stop hook
to the settings.json of the account you want belay running in -- start with
one account, not every account on the machine:

    {
      "hooks": {
        "Stop": [
          {
            "matcher": "*",
            "hooks": [
              { "type": "command",
                "command": "$WRAPPER",
                "timeout": 25 }
            ]
          }
        ]
      }
    }

The command above is an absolute path, which matters: a "~" in a hook
command is never expanded and the hook silently never runs.

Run it in log mode first (already the default here: JEV_BELAY_LOG=1 is set by
the wrapper) and read ~/.claude/belay/decisions.jsonl for a week before
trusting a block from it.
EOF
