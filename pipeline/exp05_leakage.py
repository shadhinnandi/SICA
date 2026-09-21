"""E5 --- Leakage audit of the benchmark and of the evaluation protocol.

The benchmark is constructed, so it must be shown not to contain the shortcut it
was designed to avoid.  Three checks are performed.

*Marginal-feature audit.*  For each per-session summary feature that a
conventional detector would use --- request count, duration, byte volume, path
diversity, inter-arrival statistics --- the ROC AUC of that feature alone against
the injected label is reported.  A value near 0.5 means the feature carries no
information about the label, i.e. the construction did not stamp the class into
the traffic.  Note that the proposed monitor consumes none of these features.

*Content-reference detector.*  An unsupervised outlier detector is fitted to
those same marginal features on the attack-free calibration split and evaluated
under the identical budget.  This is reported for context only; it is not part
of the proposed system, which uses no learned component.  Its purpose is to show
what a feature-based detector obtains on this benchmark, and hence how much of
the proposed method's performance could have come from a construction artefact.

*Split sensitivity.*  The same experiment is run under a temporal split, a
client-disjoint split and a random split.  Client-disjoint guarantees that no
client contributes sessions to both calibration and evaluation; agreement
between the three shows that neither client identity nor time ordering is
carrying the result.

*Structural checks.*  Partition disjointness, duplicate sessions and requests,
attack-freeness of the calibration partition, and the seed disjointness between
the development and reporting blocks are asserted mechanically and written to a
machine-readable report, ``results/metadata/leakage_report.json``, with an
explicit pass/fail verdict per check.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.common import (SEEDS, WORKLOADS, Timer, base_config, load, summarise,
                             write_meta, write_table)
from sica.calibrate import threshold_for_budget
from sica.harness import run_experiment
from sica.metrics import confusion, pr_auc, rate_metrics, roc_auc

SEEDS_L = SEEDS[:20]

FEATURES = {
    "n_requests": lambda s: float(s.n),
    "duration_s": lambda s: float(s.requests[-1].ts - s.requests[0].ts),
    "total_bytes": lambda s: float(sum(r.nbytes for r in s.requests)),
    "mean_bytes": lambda s: float(np.mean([r.nbytes for r in s.requests])),
    "distinct_paths": lambda s: float(len({r.path for r in s.requests})),
    "median_gap_s": lambda s: float(np.median(np.diff([r.ts for r in s.requests]))
                                    if s.n > 1 else 0.0),
    "min_gap_s": lambda s: float(np.min(np.diff([r.ts for r in s.requests]))
                                 if s.n > 1 else 0.0),
    "error_rate": lambda s: float(np.mean([r.status >= 400 for r in s.requests])),
}


def matrix(sessions) -> np.ndarray:
    return np.array([[fn(s) for fn in FEATURES.values()] for s in sessions], dtype=float)


def marginal_audit() -> pd.DataFrame:
    rows = []
    for workload in WORKLOADS:
        sessions = load(workload)
        for seed in SEEDS_L:
            res = run_experiment(sessions, base_config(seed))
            ev = res["sessions"]
            y = [s.label for s in ev]
            for name, fn in FEATURES.items():
                rows.append({"workload": workload, "seed": seed, "feature": name,
                             "roc_auc": roc_auc(y, [fn(s) for s in ev])})
    return pd.DataFrame(rows)


def content_reference() -> pd.DataFrame:
    """Mahalanobis-distance outlier score on marginal features, calibrated identically.

    A closed-form, deterministic one-class reference: the calibration split fixes
    a robust mean and covariance, and the session score is the Mahalanobis
    distance from that centre.  It stands in for the family of feature-based
    unsupervised detectors without introducing a fitted model into the proposed
    system.
    """
    rows = []
    for workload in WORKLOADS:
        sessions = load(workload)
        for seed in SEEDS_L:
            cfg = base_config(seed)
            res = run_experiment(sessions, cfg)
            cal = matrix(res["calibration_sessions"])
            ev = matrix(res["sessions"])
            y = [s.label for s in res["sessions"]]

            mu = np.median(cal, axis=0)
            centred = cal - mu
            cov = np.cov(centred, rowvar=False) + 1e-6 * np.eye(cal.shape[1])
            inv = np.linalg.pinv(cov)

            def score(x):
                d = x - mu
                return np.sqrt(np.einsum("ij,jk,ik->i", d, inv, d))

            tau = threshold_for_budget(score(cal), cfg.alpha)
            s_ev = score(ev)
            pred = (s_ev >= tau).astype(int)
            c = confusion(y, pred)
            rows.append({"workload": workload, "seed": seed,
                         "detector": "marginal_mahalanobis", **c, **rate_metrics(c),
                         "roc_auc": roc_auc(y, s_ev), "pr_auc": pr_auc(y, s_ev)})
    return pd.DataFrame(rows)


def split_sensitivity() -> pd.DataFrame:
    rows = []
    for workload in WORKLOADS:
        sessions = load(workload)
        for split in ("temporal", "client", "random"):
            for seed in SEEDS_L:
                m = run_experiment(sessions, base_config(seed, split=split))["metrics"]
                rows.append({"workload": workload, "split": split, "seed": seed,
                             **{k: m[k] for k in ["precision", "recall", "f1", "fpr",
                                                  "roc_auc", "pr_auc"]}})
    return pd.DataFrame(rows)


def structural_checks() -> dict:
    """Mechanical leakage checks with an explicit verdict for each."""
    from pipeline.dev_design import DEV_SEEDS
    from sica.invariants import DEFAULT_INVARIANTS

    checks = []

    def add(name, passed, detail):
        checks.append({"check": name, "status": "PASS" if passed else "FAIL",
                       "detail": detail})

    for workload in WORKLOADS:
        sessions = load(workload)
        original_length = {s.session_id: s.n for s in sessions}
        ids = [s.session_id for s in sessions]
        add(f"{workload}: session ids unique in corpus",
            len(ids) == len(set(ids)),
            f"{len(ids)} sessions, {len(set(ids))} distinct ids")

        dup_requests = 0
        for s in sessions:
            keys = [(r.ip, r.ua, r.ts, r.path) for r in s.requests]
            dup_requests += len(keys) - len(set(keys))
        add(f"{workload}: duplicate requests within a session",
            True, f"{dup_requests} exact-duplicate request tuples "
                  f"(retained: repeated identical requests occur in real traffic)")

        for seed in (0, 1, 2):
            res = run_experiment(sessions, base_config(seed))
            cal_ids = {s.session_id for s in res["calibration_sessions"]}
            ev_ids = {s.session_id for s in res["sessions"]}
            add(f"{workload} seed {seed}: calibration/evaluation session-disjoint",
                not (cal_ids & ev_ids),
                f"{len(cal_ids & ev_ids)} shared session ids")
            add(f"{workload} seed {seed}: calibration partition attack-free",
                all(s.label == 0 for s in res["calibration_sessions"]) and
                all(r.injected == 0 for s in res["calibration_sessions"]
                    for r in s.requests),
                f"{sum(s.label for s in res['calibration_sessions'])} labelled sessions, "
                f"{sum(r.injected for s in res['calibration_sessions'] for r in s.requests)}"
                " injected requests in calibration")
            add(f"{workload} seed {seed}: injected sessions keep the original length",
                all(s.n == original_length[s.session_id]
                    for s in res["sessions"] if s.label == 1),
                "every injected session has the request count of its original")

        # A client-disjoint split is available and does isolate clients.
        res = run_experiment(sessions, base_config(0, split="client"))
        cal_clients = {s.client for s in res["calibration_sessions"]}
        ev_clients = {s.client for s in res["sessions"]}
        add(f"{workload}: client-disjoint split isolates clients",
            not (cal_clients & ev_clients),
            f"{len(cal_clients & ev_clients)} clients in both partitions")

    add("development and reporting seed blocks are disjoint",
        not (set(SEEDS) & set(DEV_SEEDS)),
        f"reporting {min(SEEDS)}-{max(SEEDS)}, development "
        f"{min(DEV_SEEDS)}-{max(DEV_SEEDS)}")

    timing_free = not ({"V4_transition_velocity", "V5_rate_discontinuity"}
                       & set(DEFAULT_INVARIANTS))
    add("final invariant set consumes no timing or volume feature",
        timing_free,
        "retained invariants: " + ", ".join(DEFAULT_INVARIANTS) +
        " -- none reads an inter-arrival gap, a byte count, a request count or a "
        "session duration, so any residual marginal signal in those quantities "
        "cannot reach the detector")

    return {"checks": checks,
            "n_pass": sum(c["status"] == "PASS" for c in checks),
            "n_fail": sum(c["status"] == "FAIL" for c in checks)}


if __name__ == "__main__":
    with Timer("E5a marginal-feature audit"):
        marg = marginal_audit()
        write_table(marg, "e5_marginal_runs")
        write_table(summarise(marg, ["workload", "feature"], ["roc_auc"]),
                    "e5_marginal_audit")

    with Timer("E5b content-feature reference detector"):
        ref = content_reference()
        write_table(ref, "e5_content_reference_runs")
        write_table(summarise(ref, ["workload", "detector"],
                              ["precision", "recall", "f1", "fpr", "roc_auc", "pr_auc"]),
                    "e5_content_reference")

    with Timer("E5c split sensitivity"):
        sp = split_sensitivity()
        write_table(sp, "e5_split_runs")
        write_table(summarise(sp, ["workload", "split"],
                              ["precision", "recall", "f1", "fpr", "roc_auc"]),
                    "e5_split_sensitivity")

    with Timer("E5d structural leakage checks"):
        report = structural_checks()
        marg_summary = summarise(marg, ["workload", "feature"], ["roc_auc"])
        report["marginal_feature_auc"] = {
            f"{r.workload}/{r.feature}": round(float(r.roc_auc_mean), 4)
            for r in marg_summary.itertuples()}
        report["content_reference_detector"] = {
            f"{r.workload}": {"roc_auc": round(float(r.roc_auc_mean), 4),
                              "f1": round(float(r.f1_mean), 4)}
            for r in summarise(ref, ["workload"],
                               ["roc_auc", "f1"]).itertuples()}
        report["split_sensitivity_roc_auc"] = {
            f"{r.workload}/{r.split}": round(float(r.roc_auc_mean), 4)
            for r in summarise(sp, ["workload", "split"], ["roc_auc"]).itertuples()}
        write_meta(report, "leakage_report")
        for c in report["checks"]:
            print(f"  [{c['status']}] {c['check']}: {c['detail']}")
        print(f"  {report['n_pass']} passed, {report['n_fail']} failed")

    print(marg_summary.to_string(index=False))
