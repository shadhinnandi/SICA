"""E6 --- Efficiency of the deployed detector.

What is measured is the monitor's ``observe`` call on a request stream that has
already been parsed: that is the work a server would do in the request path.
Log parsing and sessionisation are offline preparation of the benchmark, not
part of the detector, and are timed separately and reported separately rather
than being folded in or silently omitted.

Three quantities are measured rather than asserted.

*Throughput* is timed over an uninstrumented loop, because a ``perf_counter``
pair around every call costs a measurable fraction of a 14 µs operation and
would be charged to the detector.  *Per-request latency percentiles* need
per-call timing, so they come from a separate instrumented pass whose absolute
numbers are therefore slightly pessimistic; both are reported.

*Scaling in the number of concurrently live sessions.*  The monitor holds fixed
state per session and performs no scan over session history, so per-request cost
must be flat in the number of open sessions.  The earlier version of this
project asserted an ``O(1)`` claim from a benchmark whose total time did not
grow with input size at all --- i.e. one that was not timing the detector.  Here
the claim is tested against a stream that actually grows.

*Memory per live session*, as both the analytic design bound and the measured
resident size of the state object and everything it references.
"""
from __future__ import annotations

import gc
import platform
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.common import WORKLOADS, Timer, base_config, load, parsed, write_meta, write_table
from sica.harness import run_experiment
from sica.monitor import ContinuityMonitor, MonitorConfig, SessionState
from sica.fingerprint import binding_of

REPEATS = 7
WARMUP = 2


def _stream(sessions):
    """Flatten sessions into one globally time-ordered request stream."""
    events = [(r.ts, s.session_id, r.ip, r.ua, r.path, r.referrer)
              for s in sessions for r in s.requests]
    events.sort(key=lambda e: e[0])
    return events


def _deep_size(obj, seen=None) -> int:
    """Recursive resident size of an object and everything it references."""
    seen = seen if seen is not None else set()
    if id(obj) in seen:
        return 0
    seen.add(id(obj))
    size = sys.getsizeof(obj)
    if isinstance(obj, dict):
        size += sum(_deep_size(k, seen) + _deep_size(v, seen) for k, v in obj.items())
    elif isinstance(obj, (list, tuple, set, frozenset)) or type(obj).__name__ == "deque":
        size += sum(_deep_size(v, seen) for v in obj)
    elif hasattr(obj, "__slots__"):
        size += sum(_deep_size(getattr(obj, s), seen)
                    for s in obj.__slots__ if hasattr(obj, s))
    elif hasattr(obj, "__dict__"):
        size += _deep_size(obj.__dict__, seen)
    return size


def throughput(cfg: MonitorConfig, events) -> tuple[float, float, dict]:
    """Uninstrumented timing of the request path. Returns (seconds, req/s, state)."""
    monitor = ContinuityMonitor(cfg)
    observe = monitor.observe
    gc.disable()
    try:
        t0 = time.perf_counter()
        for ts, sid, ip, ua, path, ref in events:
            observe(sid, ip, ua, ts, path, ref)
        elapsed = time.perf_counter() - t0
    finally:
        gc.enable()
    state = {"live_sessions": len(monitor.sessions),
             "state_bytes_per_session":
                 _deep_size(monitor.sessions) / max(1, len(monitor.sessions))}
    return elapsed, len(events) / elapsed, state


def latency_percentiles(cfg: MonitorConfig, events) -> dict:
    """Per-call timing. Absolute values include the timer overhead they measure."""
    monitor = ContinuityMonitor(cfg)
    observe = monitor.observe
    per = np.empty(len(events), dtype=float)
    gc.disable()
    try:
        for i, (ts, sid, ip, ua, path, ref) in enumerate(events):
            a = time.perf_counter()
            observe(sid, ip, ua, ts, path, ref)
            per[i] = time.perf_counter() - a
    finally:
        gc.enable()
    return {"latency_us_median": 1e6 * float(np.median(per)),
            "latency_us_p95": 1e6 * float(np.quantile(per, 0.95)),
            "latency_us_p99": 1e6 * float(np.quantile(per, 0.99)),
            "latency_us_max": 1e6 * float(per.max())}


def measure(cfg: MonitorConfig, events) -> dict:
    for _ in range(WARMUP):
        throughput(cfg, events)
    runs = [throughput(cfg, events) for _ in range(REPEATS)]
    tputs = [r[1] for r in runs]
    lat = [latency_percentiles(cfg, events) for _ in range(3)]
    return {"requests": len(events),
            "live_sessions": runs[0][2]["live_sessions"],
            "throughput_req_per_s": float(np.median(tputs)),
            "throughput_req_per_s_min": float(np.min(tputs)),
            "throughput_req_per_s_max": float(np.max(tputs)),
            "us_per_request_uninstrumented":
                1e6 * float(np.median([r[0] for r in runs])) / max(1, len(events)),
            **{k: float(np.median([d[k] for d in lat])) for k in lat[0]},
            "state_bytes_per_session": float(np.median(
                [r[2]["state_bytes_per_session"] for r in runs]))}


def scaling(cfg: MonitorConfig, events) -> pd.DataFrame:
    """Per-request cost as the number of concurrently live sessions grows."""
    ids = sorted({e[1] for e in events})
    rows = []
    for share in (0.05, 0.1, 0.25, 0.5, 1.0):
        keep = set(ids[: max(1, int(share * len(ids)))])
        subset = [e for e in events if e[1] in keep]
        if len(subset) < 50:
            continue
        rows.append(measure(cfg, subset))
    return pd.DataFrame(rows)


def preparation_cost() -> pd.DataFrame:
    """Offline log parsing and sessionisation, timed separately from detection."""
    rows = []
    for workload in WORKLOADS:
        t0 = time.perf_counter()
        frame = parsed(workload)
        parse_s = time.perf_counter() - t0
        t0 = time.perf_counter()
        sessions = load(workload)
        sess_s = time.perf_counter() - t0
        rows.append({"workload": workload, "requests": len(frame),
                     "parse_seconds": parse_s, "sessionise_seconds": sess_s,
                     "parse_us_per_request": 1e6 * parse_s / max(1, len(frame))})
    return pd.DataFrame(rows)


if __name__ == "__main__":
    rows, scale_rows = [], []
    with Timer("E6 efficiency"):
        prep = preparation_cost()      # also warms the caches used below
        for workload in WORKLOADS:
            sessions = load(workload)
            res = run_experiment(sessions, base_config(0))
            cfg = res["monitor_cfg"]
            events = _stream(res["sessions"])

            row = {"workload": workload, "invariants": len(cfg.enabled), **measure(cfg, events)}
            first = res["sessions"][0].requests[0]
            row["state_bytes_design_bound"] = SessionState(
                binding_of(first.ip, first.ua), (), 0.0
            ).nbytes(cfg.ring_size, cfg.path_window)
            rows.append(row)

            sc = scaling(cfg, events)
            sc.insert(0, "workload", workload)
            scale_rows.append(sc)

        write_table(pd.DataFrame(rows), "e6_efficiency")
        write_table(pd.concat(scale_rows, ignore_index=True), "e6_scaling")
        write_table(prep, "e6_preparation_cost")
        write_meta({
            "repeats": REPEATS, "warmup_runs": WARMUP,
            "aggregation": "median over repeats",
            "gc": "disabled during timed loops",
            "throughput_method": "uninstrumented loop over pre-parsed requests",
            "latency_method": "per-call perf_counter; includes timer overhead",
            "complexity_time": "O(1) per request: bounded agent parse, three prefix "
                               "comparisons, a ring membership test (|ring|=4), a "
                               "hash-set membership test, and an EWMA update",
            "complexity_memory": "O(1) per live session; O(S) for S live sessions",
            "python": sys.version.split()[0],
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
            "numpy": np.__version__, "pandas": pd.__version__,
        }, "e6_environment")
        print(pd.DataFrame(rows).to_string(index=False))
