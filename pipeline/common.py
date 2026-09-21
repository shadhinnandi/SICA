"""Shared configuration, data loading and I/O for the experiment pipeline."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pandas as pd

import sica

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
TABLES = ROOT / "results" / "tables"
FIGURES = ROOT / "results" / "figures"
META = ROOT / "results" / "metadata"
for _d in (TABLES, FIGURES, META):
    _d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Frozen study configuration.  Every experiment reads these values; nothing is
# selected against evaluation labels.
# ---------------------------------------------------------------------------
SEEDS = tuple(range(30))
ALPHA = 0.01                      # primary session-level false-alarm budget
ALPHA_GRID = (0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.10)
IDLE_SECONDS = 1800.0
MIN_REQUESTS = 7
ATTACK_RATE = 0.20
ATTACK_FRACTION = 0.40
MONOTONE_CHURN = 0.15
FLAPPING_CHURN = 0.05

# The ``label`` is a descriptive string only.  It is consumed exactly once, by
# ``pipeline/exp01_corpus.py``, which writes it into the ``description`` column of
# ``results/tables/e0_corpus.csv``.  Nothing else reads it: no figure, no generated
# LaTeX table and no validation check depends on it, so it carries no experimental
# meaning.
#
# W2's label was corrected on 2026-09-13.  It previously read "Package-manager
# clients (Nginx access log)", which the dataset verification showed to be
# misleading: the corpus is Elastic demo/sample data whose entire URL universe is
# three placeholder paths, not traffic from a real package mirror.  See
# ``docs/DATASET_FREEZE.md`` and ``docs/DATASET_VERIFICATION.md``.  The frozen
# ``e0_corpus.csv`` still carries the old wording because regenerating it would
# mean re-running E0 for a cosmetic change; that discrepancy is recorded in
# ``RESEARCH_RECORD.md`` and will resolve itself on the next full pipeline run.
WORKLOADS = {
    "W1_web": {"file": "apache_sample_1.log", "dialect": "combined",
               "label": "Apache combined access log, human web browsing "
                        "(Elastic Examples sample corpus)"},
    "W2_apt": {"file": "nginx_real.log", "dialect": "combined",
               "label": "Elastic Nginx demo/sample access-log corpus "
                        "(APT-style clients; not production traffic)"},
}

_PARSE_CACHE: dict[str, object] = {}
_SESSION_CACHE: dict[str, list] = {}


def parsed(workload: str):
    """Parsed request table for a workload, cached within a process."""
    if workload not in _PARSE_CACHE:
        spec = WORKLOADS[workload]
        _PARSE_CACHE[workload] = sica.parse_log(str(RAW / spec["file"]), spec["dialect"])
    return _PARSE_CACHE[workload]


def load(workload: str, min_requests: int = MIN_REQUESTS,
         idle: float = IDLE_SECONDS):
    """Sessionise a workload, reusing the cached parse."""
    key = f"{workload}:{min_requests}:{idle}"
    if key not in _SESSION_CACHE:
        _SESSION_CACHE[key] = sica.sessionize(parsed(workload), idle_seconds=idle,
                                              min_requests=min_requests)
    return _SESSION_CACHE[key]


def base_config(seed: int, **kwargs) -> sica.ExperimentConfig:
    """The frozen experiment configuration, with explicit overrides."""
    from sica.churn import ChurnConfig
    from sica.monitor import MonitorConfig
    churn = kwargs.pop("churn", None) or ChurnConfig(
        monotone_rate=kwargs.pop("monotone_rate", MONOTONE_CHURN),
        flapping_rate=kwargs.pop("flapping_rate", FLAPPING_CHURN))
    monitor = kwargs.pop("monitor", None) or MonitorConfig(
        migrate_reference=kwargs.pop("migrate_reference", True),
        evidence=kwargs.pop("evidence", "max"))
    return sica.ExperimentConfig(
        alpha=kwargs.pop("alpha", ALPHA),
        attack_rate=kwargs.pop("attack_rate", ATTACK_RATE),
        attack_fraction=kwargs.pop("attack_fraction", ATTACK_FRACTION),
        earliest_takeover=kwargs.pop("earliest_takeover", 0.25),
        latest_takeover=kwargs.pop("latest_takeover", 0.50),
        theft_delay_s=kwargs.pop("theft_delay_s", None),
        split=kwargs.pop("split", "temporal"),
        weighting=kwargs.pop("weighting", "rarity"),
        seed=seed, churn=churn, monitor=monitor, **kwargs)


def write_table(frame: pd.DataFrame, name: str) -> Path:
    path = TABLES / f"{name}.csv"
    frame.to_csv(path, index=False)
    print(f"  wrote {path.relative_to(ROOT)}  ({len(frame)} rows)")
    return path


def write_meta(obj, name: str) -> Path:
    path = META / f"{name}.json"
    path.write_text(json.dumps(obj, indent=2, default=str))
    print(f"  wrote {path.relative_to(ROOT)}")
    return path


def summarise(frame: pd.DataFrame, group: list[str], metrics: list[str],
              n_boot: int = 10000) -> pd.DataFrame:
    """Mean, SD and bootstrap 95% CI of each metric within each group."""
    from sica.metrics import bootstrap_ci
    rows = []
    for key, g in frame.groupby(group, sort=True):
        key = key if isinstance(key, tuple) else (key,)
        row = dict(zip(group, key))
        row["n_runs"] = len(g)
        for m in metrics:
            values = g[m].dropna().to_numpy()
            lo, hi = bootstrap_ci(values, n_boot=n_boot)
            row[f"{m}_mean"] = float(values.mean()) if values.size else float("nan")
            row[f"{m}_sd"] = float(values.std(ddof=1)) if values.size > 1 else 0.0
            row[f"{m}_ci_lo"], row[f"{m}_ci_hi"] = lo, hi
        rows.append(row)
    return pd.DataFrame(rows)


class Timer:
    def __init__(self, label: str):
        self.label = label

    def __enter__(self):
        self.t0 = time.perf_counter()
        print(f"== {self.label}")
        return self

    def __exit__(self, *exc):
        print(f"   done in {time.perf_counter() - self.t0:.1f}s")
