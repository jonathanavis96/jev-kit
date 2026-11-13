#!/usr/bin/env python3
"""python3 -m logtriage.cli -- read log lines on stdin, emit JSON lines out.

    journalctl --user -u airlock-daemon -n 500 --no-pager | python3 -m logtriage.cli
    python3 -m logtriage.cli --no-model < app.log        # local rules only, offline
    python3 -m logtriage.cli --only investigate,attention < app.log

Every line is redacted before anything else happens, and a line no local rule
settles is the only kind that costs a model call. `--stats` prints, on stderr,
how many lines each stage actually settled -- which is the number that says
whether the local rules are pulling their weight.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logtriage.triage import LABELS, Triager, load_config


def _default_ask(body):
    from airlock import client
    response, _latency = client.ask({
        "state": body["state"], "model": client.MODEL, "questions": body["questions"],
    })
    return response


def main(argv=None):
    parser = argparse.ArgumentParser(description=next(iter((__doc__ or "").splitlines()), ""))
    parser.add_argument("--config", default=None,
                        help="JSON with 'rules' and/or 'protected' (default: the built-ins)")
    parser.add_argument("--no-model", action="store_true",
                        help="local rules only: no network call at all")
    parser.add_argument("--only", default=None,
                        help="comma-separated labels to emit (e.g. investigate,attention)")
    parser.add_argument("--no-cache", action="store_true",
                        help="do not reuse an answer for an identical redacted line")
    parser.add_argument("--stats", action="store_true", help="print counts to stderr at the end")
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except Exception as exc:
        print("logtriage: bad config: %s" % exc, file=sys.stderr)
        return 2

    wanted = None
    if args.only:
        wanted = {w.strip() for w in args.only.split(",") if w.strip()}
        unknown = wanted - set(LABELS)
        if unknown:
            print("logtriage: unknown label(s): %s" % ", ".join(sorted(unknown)), file=sys.stderr)
            return 2

    triager = Triager(
        config=config,
        ask=None if args.no_model else _default_ask,
        use_model=not args.no_model,
        cache=not args.no_cache,
    )

    try:
        # A log line with bytes that are not UTF-8 must not end the stream.
        sys.stdin.reconfigure(errors="replace")
    except Exception:
        pass
    for raw in sys.stdin:
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        record = triager.triage(line)
        if wanted is not None and record["label"] not in wanted:
            continue
        sys.stdout.write(json.dumps(record) + "\n")
        sys.stdout.flush()

    if args.stats:
        s = triager.stats
        print("logtriage: %d line(s): %d by local rule, %d by model (%d cached), "
              "%d protected, %d error(s)"
              % (s["lines"], s["by_rule"], s["by_model"], s["cached"],
                 s["protected"], s["errors"]), file=sys.stderr)
        if s["lines"]:
            print("           %.0f%% settled without a model call"
                  % (100.0 * (s["by_rule"] + s["protected"]) / s["lines"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
