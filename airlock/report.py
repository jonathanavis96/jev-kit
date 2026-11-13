"""python3 -m airlock.report -- summarize the shadow log for a human.

Prints: calls per guard, would_deny count and rate, mean/p95 latency, total
tokens, and the 20 most recent would_deny rows, so a human can judge the
false-deny rate after a week of shadow-mode running.
"""
import json
import statistics
import sys
from pathlib import Path

from . import paths
from .log import LOG_FILE

TUNE_LOG_FILE = Path(paths.env("AIRLOCK_TUNE_STATE_DIR", "PLUMBLINE_TUNE_STATE_DIR", "JEV_TUNE_STATE_DIR")
                     or paths.state_dir()) / "tune_log.jsonl"


def _load_rows():
    rows = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    except FileNotFoundError:
        pass
    return rows


def _percentile(values, pct):
    if not values:
        return 0.0
    values = sorted(values)
    k = (len(values) - 1) * pct
    lo = int(k)
    hi = min(lo + 1, len(values) - 1)
    if lo == hi:
        return values[lo]
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def _load_tune_rows():
    rows = []
    try:
        with open(TUNE_LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    except FileNotFoundError:
        pass
    return rows


def print_tuning_summary():
    rows = _load_tune_rows()
    if not rows:
        print("No tuning runs logged yet at %s" % TUNE_LOG_FILE)
        return

    committed = [r for r in rows if r.get("committed")]
    print("airlock tuning loop summary")
    print("log file: %s" % TUNE_LOG_FILE)
    print("total runs: %d  committed: %d" % (len(rows), len(committed)))
    print()

    total_tokens = sum(r.get("tokens_jev", 0) or 0 for r in rows)
    total_wall = sum(r.get("wall_time_s", 0) or 0 for r in rows)
    print("total Jev tokens spent tuning: %d" % total_tokens)
    print("total wall time: %.0fs" % total_wall)
    print()

    print("most recent 20 runs:")
    for r in rows[-20:]:
        print(
            "  %s new=%-4s judged=%-4s wrong=%-4s err=%.0f%% before=%s after=%s "
            "committed=%-5s next_interval=%-5s reason=%s"
            % (
                r.get("ts", "?"),
                r.get("new_rows"),
                r.get("judged"),
                r.get("wrong"),
                (r.get("error_rate") or 0.0) * 100,
                "%.3f" % r["accuracy_before"] if r.get("accuracy_before") is not None else "-",
                "%.3f" % r["accuracy_after"] if r.get("accuracy_after") is not None else "-",
                r.get("committed"),
                r.get("interval_min_next"),
                str(r.get("reason"))[:80],
            )
        )


def print_enforce_summary(rows):
    enforce_rows = [r for r in rows if r.get("mode") == "enforce"]
    print()
    print("enforce-mode summary")
    if not enforce_rows:
        print("  (no enforce-mode calls logged yet)")
        return

    denies = sum(1 for r in enforce_rows if r.get("enforced"))
    overrides = sum(1 for r in enforce_rows if r.get("override"))
    refused = sum(1 for r in enforce_rows if r.get("override_refused"))
    loop_allows = sum(1 for r in enforce_rows if r.get("loop_allow"))
    fail_open = sum(1 for r in enforce_rows if r.get("error"))

    print("  judged calls: %d" % len(enforce_rows))
    print("  denies emitted (enforced=true): %d" % denies)
    print("  overrides ([airlock-ok: ...] stamps): %d" % overrides)
    if refused:
        print("  stamps refused (strict rule, denied anyway): %d" % refused)
    print("  loop allows (repeat within 10min): %d" % loop_allows)
    print("  fail-open (error set): %d" % fail_open)

    latencies = [r.get("elapsed_ms") for r in enforce_rows if isinstance(r.get("elapsed_ms"), (int, float))]
    if latencies:
        print(
            "  added latency ms: p50=%.0f p95=%.0f n=%d"
            % (_percentile(latencies, 0.50), _percentile(latencies, 0.95), len(latencies))
        )


def main():
    if "--tuning" in sys.argv:
        print_tuning_summary()
        return

    rows = _load_rows()
    if not rows:
        print("No shadow log entries yet at %s" % LOG_FILE)
        return

    by_guard = {}
    latencies = []
    total_in = 0
    total_out = 0
    deny_rows = []

    for row in rows:
        guard = row.get("guard", "unknown")
        stats = by_guard.setdefault(guard, {"calls": 0, "would_deny": 0})
        stats["calls"] += 1
        if row.get("would_deny"):
            stats["would_deny"] += 1
            deny_rows.append(row)

        lat = row.get("latency_ms")
        if isinstance(lat, (int, float)):
            latencies.append(lat)

        usage = row.get("usage") or {}
        total_in += usage.get("input_tokens", 0) or 0
        total_out += usage.get("output_tokens", 0) or 0

    print("airlock shadow log summary")
    print("log file: %s" % LOG_FILE)
    print("total judged calls: %d" % len(rows))
    print()
    for guard, stats in sorted(by_guard.items()):
        calls = stats["calls"]
        denies = stats["would_deny"]
        rate = (denies / calls * 100.0) if calls else 0.0
        print("  %-18s calls=%-6d would_deny=%-6d rate=%.1f%%" % (guard, calls, denies, rate))

    if latencies:
        print()
        print(
            "latency ms: mean=%.0f p95=%.0f n=%d"
            % (statistics.mean(latencies), _percentile(latencies, 0.95), len(latencies))
        )
    print("tokens: input=%d output=%d" % (total_in, total_out))

    deny_rows.sort(key=lambda r: r.get("ts", ""), reverse=True)
    print()
    print("most recent would_deny rows (up to 20):")
    if not deny_rows:
        print("  (none)")
    for row in deny_rows[:20]:
        ts = row.get("ts", "?")
        guard = row.get("guard", "?")
        summary = row.get("input_summary", {})
        suggestion = row.get("suggestion")
        summ_str = json.dumps(summary, ensure_ascii=False)[:160]
        print("  %s %-18s suggest=%s summary=%s" % (ts, guard, suggestion, summ_str))

    print_enforce_summary(rows)


if __name__ == "__main__":
    main()
