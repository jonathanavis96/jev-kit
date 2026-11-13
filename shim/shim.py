#!/usr/bin/env python3
"""OpenAI-compatible chat/completions shim backed by standing `claude -p` CLI
children, for driving PageIndex's LOCAL indexing/chat lanes on a Claude
SUBSCRIPTION login (OAuth via the `claude` CLI) instead of an API key.

Listens on 127.0.0.1 ONLY. Implements:
  POST /v1/chat/completions  (non-streaming)
  GET  /v1/models

Every request spends the Claude subscription of the account in
CLAUDE_CONFIG_DIR. See README.md for measured numbers and limits.

Protocol notes (measured 2026-09-19 against a sibling implementation at
jev-ultrafast/jev_ultrafast/text_model_claude_standing.py, branch
claude-text-model, read-only reference):
  - one child: `claude -p --model <m> --input-format stream-json
    --output-format stream-json --verbose --safe-mode --no-session-persistence
    --tools ""`, env MAX_THINKING_TOKENS=0.
  - one line of {"type":"user","message":{"role":"user","content":<prompt>}}
    on stdin per request; read stdout until a `{"type":"result"}` event.
  - --safe-mode skips hooks/skills/plugins (cheap) while keeping OAuth login
    working; --bare would be faster but needs an API key, which this box
    does not have.
"""
from __future__ import annotations

import atexit
import json
import logging
import os
import queue
import signal
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("claude-cli-shim")

HOST = "127.0.0.1"
PORT = int(os.environ.get("CLAUDE_SHIM_PORT", "8931"))
# Machine-specific: which Claude account tree the shim drives. A box with a
# single account leaves CLAUDE_CONFIG_DIR unset and gets ~/.claude; a box with
# several records its own value in install/config.env. No account name is
# baked in here.
CLAUDE_CONFIG_DIR = os.environ.get("CLAUDE_CONFIG_DIR", os.path.expanduser("~/.claude"))
POOL_SIZE = int(os.environ.get("CLAUDE_SHIM_POOL_SIZE", "2"))
REQUEST_TIMEOUT = float(os.environ.get("CLAUDE_SHIM_TIMEOUT", "60"))
RECYCLE_AFTER = int(os.environ.get("CLAUDE_SHIM_RECYCLE_AFTER", "40"))

# Model names PageIndex/LiteLLM may send after stripping the openai/ prefix
# this shim is addressed under (see README: OPENAI_BASE_URL + bare model
# names like "haiku" or "sonnet"). Anything else is refused with a clear
# 400 rather than silently guessed.
ALLOWED_MODELS = {"haiku": "haiku", "sonnet": "sonnet"}


def _resolve_model(name: str) -> str:
    name = (name or "").lower()
    for key, cli_model in ALLOWED_MODELS.items():
        if key in name:
            return cli_model
    raise ValueError(f"model {name!r} not served by this shim; use haiku or sonnet")


def _cmd(cli_model: str) -> list[str]:
    return [
        "claude", "-p",
        "--model", cli_model,
        "--input-format", "stream-json",
        "--output-format", "stream-json",
        "--verbose",
        "--safe-mode",
        "--no-session-persistence",
        "--tools", "",
    ]


class Child:
    """One long-lived `claude -p --input-format stream-json` process pinned
    to one model."""

    def __init__(self, cli_model: str):
        self.cli_model = cli_model
        env = {**os.environ, "CLAUDE_CONFIG_DIR": CLAUDE_CONFIG_DIR}
        env.setdefault("MAX_THINKING_TOKENS", "0")
        self.proc = subprocess.Popen(
            _cmd(cli_model),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )
        self.requests_served = 0
        self.retired = False
        self._queue: queue.Queue = queue.Queue()
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        stdout = self.proc.stdout
        if stdout is None:
            self._queue.put(None)
            return
        try:
            for line in stdout:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("type") == "result":
                    self._queue.put(event)
        except (OSError, ValueError):
            pass
        finally:
            self._queue.put(None)

    def alive(self) -> bool:
        return self.proc.poll() is None

    def request(self, prompt: str, timeout: float) -> dict:
        """Send one message, block for the matching result event. Caller
        must retire this child on any exception here."""
        with self._lock:
            if self.retired:
                raise _ChildRetired("standing claude child was retired while this request waited")
            stdin = self.proc.stdin
            if stdin is None:
                raise RuntimeError("standing claude child has no stdin pipe")
            line = json.dumps({"type": "user", "message": {"role": "user", "content": prompt}})
            try:
                stdin.write(line + "\n")
                stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as exc:
                raise RuntimeError(f"standing claude child stdin closed: {exc}") from None
            try:
                event = self._queue.get(timeout=timeout)
            except queue.Empty:
                raise TimeoutError(f"standing claude child did not answer within {timeout}s") from None
            if event is None:
                raise RuntimeError("standing claude child exited before answering")
            self.requests_served += 1
            return event

    def terminate(self):
        try:
            if self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            try:
                self.proc.kill()
                self.proc.wait(timeout=3)
            except Exception:
                logger.warning("child pid %s (model %s) could not be reaped", self.proc.pid, self.cli_model)


class _ChildRetired(RuntimeError):
    """The child this request queued on was retired before its turn came."""


class ModelPool:
    """Up to POOL_SIZE standing children for one model, round-robin picked,
    lazily spawned, recycled after RECYCLE_AFTER requests each."""

    def __init__(self, cli_model: str, size: int = POOL_SIZE):
        self.cli_model = cli_model
        self.size = size
        self._children: list[Child] = []
        self._idx = 0
        self._lock = threading.Lock()

    def _spawn(self) -> Child:
        child = Child(self.cli_model)
        _TRACKED_CHILDREN.add(child)
        logger.info("spawned claude -p child pid=%s model=%s", child.proc.pid, self.cli_model)
        return child

    def _pick(self) -> Child:
        with self._lock:
            self._children = [c for c in self._children if c.alive()]
            if len(self._children) < self.size:
                child = self._spawn()
                self._children.append(child)
                return child
            self._idx = (self._idx + 1) % len(self._children)
            return self._children[self._idx]

    def _retire(self, child: Child):
        child.retired = True
        with self._lock:
            if child in self._children:
                self._children.remove(child)
        child.terminate()
        _TRACKED_CHILDREN.discard(child)

    def request(self, prompt: str, timeout: float) -> dict:
        # Requests queue on a child's lock. When one of them recycles or
        # retires that child, the others waiting on it move to another child
        # instead of failing: the child going away is not their fault.
        for _attempt in range(3):
            child = self._pick()
            try:
                event = child.request(prompt, timeout=timeout)
            except _ChildRetired:
                continue
            except (TimeoutError, RuntimeError) as exc:
                if child.retired:
                    continue
                logger.warning("child pid=%s failed (%s); retiring", child.proc.pid, exc)
                self._retire(child)
                raise
            break
        else:
            raise RuntimeError("no standing claude child could take the request")
        if child.requests_served >= RECYCLE_AFTER:
            logger.info("recycling child pid=%s after %d requests", child.proc.pid, child.requests_served)
            self._retire(child)
        return event

    def close(self):
        with self._lock:
            children, self._children = self._children, []
        for c in children:
            c.terminate()
            _TRACKED_CHILDREN.discard(c)


_TRACKED_CHILDREN: set[Child] = set()
_POOLS: dict[str, ModelPool] = {}
_POOLS_LOCK = threading.Lock()

# Stats for the end-to-end proof run.
_STATS_LOCK = threading.Lock()
_STATS = {"calls": 0, "total_latency_s": 0.0, "errors": 0}


def _pool_for(cli_model: str) -> ModelPool:
    with _POOLS_LOCK:
        pool = _POOLS.get(cli_model)
        if pool is None:
            pool = ModelPool(cli_model)
            _POOLS[cli_model] = pool
        return pool


def _shutdown_all():
    with _POOLS_LOCK:
        pools = list(_POOLS.values())
    for p in pools:
        p.close()
    for child in list(_TRACKED_CHILDREN):
        child.terminate()
        _TRACKED_CHILDREN.discard(child)


atexit.register(_shutdown_all)


def _messages_to_prompt(messages: list[dict]) -> str:
    """Flatten OpenAI chat messages into one prompt for a single-turn CLI
    child. PageIndex's indexing lane sends one user message per call (see
    pageindex/utils.py llm_completion); this still handles a leading system
    message and short history sanely."""
    parts = []
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", "")
        if isinstance(content, list):
            # OpenAI content-parts form; take text parts only (no vision
            # needed for PageIndex's local indexing lane).
            content = "\n".join(
                p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"
            )
        if role == "system":
            parts.append(f"[system]\n{content}")
        elif role == "assistant":
            parts.append(f"[assistant]\n{content}")
        else:
            parts.append(f"[user]\n{content}")
    return "\n\n".join(parts)


def _looks_like_json(text: str) -> bool:
    text = text.strip()
    if text.startswith("```"):
        # strip a ```json ... ``` fence PageIndex's own extract_json also
        # tolerates, but response_format:json_object callers expect bare JSON.
        text = text.strip("`")
        nl = text.find("\n")
        if nl != -1 and text[:nl].strip().lower() in ("json", ""):
            text = text[nl + 1:]
    try:
        json.loads(text)
        return True
    except json.JSONDecodeError:
        return False


def _strip_json_fence(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        nl = t.find("\n")
        if nl != -1 and t[:nl].strip().lower() in ("json", ""):
            t = t[nl + 1:]
    return t.strip()


def run_completion(model_field: str, messages: list[dict], response_format: dict | None) -> dict:
    cli_model = _resolve_model(model_field)
    pool = _pool_for(cli_model)
    prompt = _messages_to_prompt(messages)

    want_json = bool(response_format and response_format.get("type") == "json_object")
    if want_json:
        prompt += (
            "\n\n[system]\nRespond with ONLY valid JSON. No markdown code "
            "fences, no commentary before or after the JSON."
        )

    t0 = time.perf_counter()
    event = pool.request(prompt, timeout=REQUEST_TIMEOUT)
    latency = time.perf_counter() - t0
    content = event.get("result")
    if event.get("is_error") or not isinstance(content, str):
        raise RuntimeError(f"claude CLI returned an error result: {event}")

    if want_json and not _looks_like_json(content):
        retry_prompt = prompt + (
            f"\n\n[assistant]\n{content}\n\n[user]\nThat was not valid JSON. "
            "Respond again with ONLY valid JSON, nothing else."
        )
        t1 = time.perf_counter()
        event2 = pool.request(retry_prompt, timeout=REQUEST_TIMEOUT)
        latency += time.perf_counter() - t1
        content2 = event2.get("result")
        if isinstance(content2, str) and _looks_like_json(_strip_json_fence(content2)):
            content = content2
            event = event2
        # else: fall through with the original (invalid) content; caller sees it.

    if want_json:
        content = _strip_json_fence(content)

    usage = event.get("usage") or {}
    with _STATS_LOCK:
        _STATS["calls"] += 1
        _STATS["total_latency_s"] += latency

    return {
        "content": content,
        "cli_model": cli_model,
        "latency_s": latency,
        "usage": usage,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "claude-cli-shim/0.1"

    def log_message(self, format, *args):
        logger.info("%s - %s", self.address_string(), format % args)

    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.rstrip("/") == "/v1/models":
            now = int(time.time())
            self._send_json(200, {
                "object": "list",
                "data": [
                    {"id": "haiku", "object": "model", "created": now, "owned_by": "claude-cli-shim"},
                    {"id": "sonnet", "object": "model", "created": now, "owned_by": "claude-cli-shim"},
                ],
            })
            return
        if self.path.rstrip("/") in ("/", "/healthz"):
            with _STATS_LOCK:
                stats = dict(_STATS)
            self._send_json(200, {"status": "ok", "stats": stats})
            return
        self._send_json(404, {"error": {"message": f"no such route {self.path}"}})

    def do_POST(self):
        if self.path.rstrip("/") != "/v1/chat/completions":
            self._send_json(404, {"error": {"message": f"no such route {self.path}"}})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"error": {"message": "invalid Content-Length"}})
            return
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            req = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._send_json(400, {"error": {"message": f"invalid JSON body: {exc}"}})
            return
        # A body of the wrong shape raised AttributeError out of this handler
        # and the client got a dropped connection instead of a 400.
        if not isinstance(req, dict):
            self._send_json(400, {"error": {"message": "the JSON body must be an object"}})
            return

        model_field = req.get("model", "")
        messages = req.get("messages") or []
        response_format = req.get("response_format")
        if not isinstance(model_field, str) or not isinstance(messages, list) \
                or not all(isinstance(m, dict) for m in messages) \
                or not (response_format is None or isinstance(response_format, dict)):
            self._send_json(400, {"error": {"message":
                "expected model: string, messages: list of objects, response_format: object"}})
            return
        if req.get("stream"):
            self._send_json(400, {"error": {"message": "streaming not implemented by this shim"}})
            return

        try:
            result = run_completion(model_field, messages, response_format)
        except ValueError as exc:
            self._send_json(400, {"error": {"message": str(exc)}})
            return
        except (TimeoutError, RuntimeError, OSError) as exc:
            # OSError: the child could not be spawned (no `claude` on PATH).
            with _STATS_LOCK:
                _STATS["errors"] += 1
            self._send_json(502, {"error": {"message": f"claude CLI backend failed: {exc}"}})
            return
        except Exception as exc:
            with _STATS_LOCK:
                _STATS["errors"] += 1
            logger.exception("unexpected failure handling a completion")
            self._send_json(500, {"error": {"message": f"shim failed: {type(exc).__name__}"}})
            return

        usage = result["usage"] or {}
        prompt_tokens = usage.get("input_tokens", 0) or 0
        completion_tokens = usage.get("output_tokens", 0) or 0
        resp = {
            "id": f"chatcmpl-{uuid.uuid4().hex}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model_field or result["cli_model"],
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": result["content"]},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        }
        self._send_json(200, resp)


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)

    def _handle_signal(signum, _frame):
        logger.info("signal %s received, shutting down", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    logger.info(
        "claude-cli-shim listening on http://%s:%d (CLAUDE_CONFIG_DIR=%s, pool size=%d)",
        HOST, PORT, CLAUDE_CONFIG_DIR, POOL_SIZE,
    )
    try:
        server.serve_forever()
    finally:
        _shutdown_all()
        with _STATS_LOCK:
            logger.info("final stats: %s", _STATS)


if __name__ == "__main__":
    main()
