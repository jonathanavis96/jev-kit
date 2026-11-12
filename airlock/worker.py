#!/usr/bin/env python3
"""Detached worker invoked by hooks/airlock.py.

Does the real Jev call and log write, running after the PreToolUse hook
process has already exited 0 -- so nothing here can add latency to the tool
call it is judging, or block it. Reads the hook's stdin payload from the temp
file path given as argv[1], deletes that file immediately, then dispatches to
the matching guard.

Fail-open everywhere: any exception anywhere in main() just means this one
judgement is silently lost, never surfaced.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    if len(sys.argv) < 2:
        return
    path = sys.argv[1]
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except Exception:
        return
    finally:
        try:
            os.remove(path)
        except Exception:
            pass

    try:
        data = json.loads(raw)
    except Exception:
        return

    try:
        from airlock import enforce
    except Exception:
        return

    tool_name = data.get("tool_name") or ""
    try:
        # Shadow mode runs the SAME rules table as enforce and logs what
        # enforce would have done for every rule that fired -- it just never
        # emits anything (see enforce.handle's mode argument).
        enforce.handle(data, tool_name, mode="shadow")
    except Exception:
        return


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
