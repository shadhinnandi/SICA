"""E0 --- Corpus audit: provenance, scale and session structure of the real logs.

Produces the dataset table used in the paper and the statistics that justify
the sessionisation parameters.  Nothing here depends on the detector.
"""
from __future__ import annotations

import sys
from collections import Counter

import numpy as np
import pandas as pd

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
from pipeline.common import (IDLE_SECONDS, MIN_REQUESTS, RAW, WORKLOADS, Timer,
                             load, parsed, write_meta, write_table)
from sica.fingerprint import ip_prefix24, ip_scope16, parse_user_agent
from sica.sessionize import parse_log


def corpus_rows() -> pd.DataFrame:
    rows = []
    for key, spec in WORKLOADS.items():
        frame = parsed(key)
        sessions = load(key)
        lens = np.array([s.n for s in sessions])
        span = (frame.ts.max() - frame.ts.min()) / 86400.0
        cores = {parse_user_agent(u)[0::2] for u in frame.ua.unique()}
        rows.append({
            "workload": key,
            "description": spec["label"],
            "source_file": spec["file"],
            "requests_parsed": len(frame),
            "unique_addresses": int(frame.ip.nunique()),
            "unique_scope16": int(frame.ip.map(ip_scope16).nunique()),
            "unique_prefix24": int(frame.ip.map(ip_prefix24).nunique()),
            "unique_user_agents": int(frame.ua.nunique()),
            "unique_agent_cores": len(cores),
            "referrer_coverage": float((frame.referrer.astype(str) != "-").mean()),
            "span_days": round(float(span), 2),
            "sessions": len(sessions),
            "requests_in_sessions": int(lens.sum()),
            "requests_per_session_median": float(np.median(lens)),
            "requests_per_session_mean": round(float(lens.mean()), 2),
            "requests_per_session_p90": float(np.quantile(lens, 0.9)),
            "requests_per_session_max": int(lens.max()),
        })
    return pd.DataFrame(rows)


def sensitivity_rows() -> pd.DataFrame:
    """Session yield as a function of the sessionisation parameters."""
    rows = []
    for key in WORKLOADS:
        for idle in (900.0, 1800.0, 3600.0):
            for min_req in (5, 7, 10, 15):
                sessions = load(key, min_requests=min_req, idle=idle)
                if not sessions:
                    continue
                lens = np.array([s.n for s in sessions])
                rows.append({"workload": key, "idle_seconds": idle,
                             "min_requests": min_req, "sessions": len(sessions),
                             "requests": int(lens.sum()),
                             "median_length": float(np.median(lens))})
    return pd.DataFrame(rows)


def agent_mix() -> pd.DataFrame:
    rows = []
    for key, spec in WORKLOADS.items():
        frame = parsed(key)
        counts = Counter(parse_user_agent(u)[0] for u in frame.ua)
        total = sum(counts.values())
        for browser, n in counts.most_common(6):
            rows.append({"workload": key, "agent_family": browser,
                         "requests": n, "share": round(n / total, 4)})
    return pd.DataFrame(rows)


if __name__ == "__main__":
    with Timer("E0 corpus audit"):
        corpus = corpus_rows()
        write_table(corpus, "e0_corpus")
        write_table(sensitivity_rows(), "e0_sessionisation_sensitivity")
        write_table(agent_mix(), "e0_agent_mix")
        write_meta({"idle_seconds": IDLE_SECONDS, "min_requests": MIN_REQUESTS},
                   "e0_sessionisation")
        print(corpus.to_string(index=False))
