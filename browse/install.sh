#!/usr/bin/env bash
# Check that the `browse` MCP server can run here, and PRINT the block that
# registers it. Nothing is applied: ~/.claude.json is yours, and this script
# never opens it.
#
# The server drives the vendored jev-ultrafast at vendor/jev-ultrafast, which
# ships with this repository. What it still needs is that project's Python
# environment, which browser/install.sh syncs.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SERVER="$SCRIPT_DIR/server.py"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
CLONE="${JEV_ULTRAFAST_DIR:-${AIRLOCK_BROWSER_DIR:-$REPO_ROOT/vendor/jev-ultrafast}}"
CLONE="${CLONE/#\~/$HOME}"
AIRLOCK_HOME="${AIRLOCK_HOME:-$HOME/.local/share/airlock}"
VENV="${JEV_ULTRAFAST_VENV:-$AIRLOCK_HOME/jev-ultrafast-venv}"
PY="${PYTHON:-python3}"

usage() {
  cat >&2 <<USAGE
usage: $0

Verifies the vendored jev-ultrafast (\$JEV_ULTRAFAST_DIR, else
\$AIRLOCK_BROWSER_DIR, else vendor/jev-ultrafast here) and its environment,
runs the server through a real MCP handshake, and prints the mcpServers block
to add to ~/.claude.json. It never edits that file.
USAGE
  exit 2
}
[ "$#" -eq 0 ] || usage

command -v "$PY" >/dev/null 2>&1 || { echo "browse: '$PY' not found" >&2; exit 1; }
[ -f "$SERVER" ] || { echo "browse: no server at $SERVER" >&2; exit 1; }

if [ ! -f "$CLONE/jev_ultrafast/agent.py" ]; then
  echo "browse: the vendored jev-ultrafast was not found at $CLONE" >&2
  echo "  It ships at vendor/jev-ultrafast in this checkout ($REPO_ROOT)." >&2
  echo "  A copy somewhere else? Set JEV_ULTRAFAST_DIR to it." >&2
  exit 1
fi
echo "browse: agent at $CLONE"

if [ ! -x "$VENV/bin/python" ] && [ ! -x "$CLONE/.venv/bin/python" ] \
   && ! command -v uv >/dev/null 2>&1; then
  echo "browse: no environment at $VENV and 'uv' is not on PATH." >&2
  echo "  Run this first, then run me again:" >&2
  echo "      $REPO_ROOT/browser/install.sh" >&2
  exit 1
fi
echo "browse: environment at $VENV"


chmod +x "$SERVER" 2>/dev/null || true

# A real handshake over a real pipe: initialize, then tools/list.
HANDSHAKE="$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"browse-install","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | "$PY" "$SERVER" 2>/dev/null)"
if printf '%s' "$HANDSHAKE" | grep -q '"name": "browse"'; then
  echo "browse: the server answered initialize and tools/list"
else
  echo "browse: the server did not answer the MCP handshake. Try it by hand:" >&2
  echo "      $PY $SERVER" >&2
  exit 1
fi

PY_ABS="$(command -v "$PY")"
cat <<NOTE

Add this under "mcpServers" in ~/.claude.json (nothing here edits that file).
Your Playwright MCP entries stay exactly as they are. Use browse for reading and
simple click-through; Playwright stays the tool for file uploads, scripted code
and multi-step work in a signed-in profile.

NOTE
"$PY_ABS" - "$SERVER" <<'PYEOF'
import json, sys
print(json.dumps({"mcpServers": {"browse": {
    "type": "stdio", "command": sys.argv[1], "args": [], "env": {}}}}, indent=2))
PYEOF
cat <<NOTE

If Chromium refuses to start with "no usable sandbox" (Ubuntu 23.10+ and an
unprofiled binary), browse/README.md says what that means and what the
JEV_BROWSE_NO_SANDBOX=1 opt-in costs. It is never set for you.
NOTE
