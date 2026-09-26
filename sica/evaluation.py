"""Evaluation: one calibrate-then-evaluate run, metrics and non-ML baselines.

``run_experiment`` implements the protocol used by every experiment:

1. Split the real sessions into a calibration half and an evaluation half
   (temporal split by default).
2. Apply benign churn to both halves.
3. Inject hijacks into the evaluation half only, so calibration stays
   attack-free.
4. Calibrate weights and threshold on the calibration half (``calibrate``).
5. Replay the evaluation half through the frozen detector.
6. Read the ground-truth labels only to compute session-level metrics.

Baselines are the pinning rules deployed applications use (pin address, /24,
/16, User-Agent, ...) and three scored rules calibrated to the same budget.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from .benchmark import (LEVELS_ALL, MODES, ChurnConfig, InjectionConfig, apply_churn,
                        build_donor_pool, inject_session)
from .detector import ContinuityMonitor, MonitorConfig, calibrate, threshold_for_budget
from .fingerprint import ip_prefix24, ip_scope16, parse_user_agent
from .invariants import DEFAULT_INVARIANTS

__all__ = ["ExperimentConfig", "split_sessions", "inject_mixture", "run_experiment",
           "run_baselines", "PINNING_BASELINES", "SCORED_BASELINES", "session_scores",
           "pinning_predictions", "confusion", "rate_metrics", "roc_auc", "pr_auc",
           "evaluate_sessions", "index_records", "bootstrap_ci"]


# ============================================================================
# Metrics
# ============================================================================

def confusion(y_true, y_pred) -> dict[str, int]:
    y = np.asarray(y_true, dtype=int)
    p = np.asarray(y_pred, dtype=int)
    return {"TP": int(((y == 1) & (p == 1)).sum()),
            "TN": int(((y == 0) & (p == 0)).sum()),
            "FP": int(((y == 0) & (p == 1)).sum()),
            "FN": int(((y == 1) & (p == 0)).sum())}


def rate_metrics(c: dict[str, int]) -> dict[str, float]:
    tp, tn, fp, fn = c["TP"], c["TN"], c["FP"], c["FN"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1,
            "fpr": fp / (fp + tn) if fp + tn else 0.0,
            "fnr": fn / (fn + tp) if fn + tp else 0.0,
            "specificity": specificity,
            "balanced_accuracy": 0.5 * (recall + specificity)}


def roc_auc(y_true, scores) -> float:
    """Rank-based ROC AUC with correct handling of tied scores."""
    y = np.asarray(y_true, dtype=int)
    s = np.asarray(scores, dtype=float)
    npos, nneg = int((y == 1).sum()), int((y == 0).sum())
    if npos == 0 or nneg == 0:
        return float("nan")
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s), dtype=float)
    sorted_s = s[order]
    i = 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and sorted_s[j + 1] == sorted_s[i]:
            j += 1
        ranks[order[i:j + 1]] = 0.5 * (i + j) + 1.0
        i = j + 1
    return float((ranks[y == 1].sum() - npos * (npos + 1) / 2.0) / (npos * nneg))


def pr_auc(y_true, scores) -> float:
    """Average precision, with tied scores collapsed into a single operating point.

    A threshold cannot separate samples that carry the same score, so every tie group is one
    operating point on the PR curve and must contribute once, with the precision that the
    whole group yields.  Walking the sorted list sample by sample instead makes the result a
    function of the order in which equally-scored samples happen to appear: optimistic when
    positives precede negatives inside a group, pessimistic otherwise.  That is not an edge
    case here --- the session risk statistic is coarse and heavily tied, and an all-tied
    sample was scored at 0.83 by the sample-wise form where the correct average precision is
    the prevalence, 0.5.
    """
    y = np.asarray(y_true, dtype=int)
    s = np.asarray(scores, dtype=float)
    npos = int((y == 1).sum())
    if npos == 0:
        return float("nan")
    order = np.argsort(-s, kind="mergesort")
    y, s = y[order], s[order]
    tp = np.cumsum(y == 1)
    fp = np.cumsum(y == 0)
    # Keep only the last index of each run of equal scores.
    last = np.append(np.flatnonzero(np.diff(s) != 0), len(s) - 1)
    tp, fp = tp[last], fp[last]
    precision = tp / np.maximum(1, tp + fp)
    recall = tp / npos
    return float(np.sum(np.diff(np.concatenate(([0.0], recall))) * precision))


def index_records(records) -> dict[str, list[dict]]:
    """Group monitor records by session id once, for repeated evaluation."""
    out: dict[str, list[dict]] = {}
    for r in records:
        out.setdefault(r["session_id"], []).append(r)
    return out


def evaluate_sessions(sessions, records, threshold: float, index=None) -> dict:
    """Score sessions from per-request monitor records under a frozen threshold.

    Returns session-level confusion and rates, ranking AUCs on session peak
    risk, attacker-request detection rate, and detection latency measured in
    attacker requests and in seconds after the first attacker request.

    .. warning::
       ``latency_seconds_median`` is **not** a real-world timing result on this
       benchmark and must not be reported as one.  The source logs carry a
       degenerate minute field, so every session spans at most 59 seconds and all
       inter-arrival times are artefacts of the upstream generator
       (see README, Dataset).  ``latency_requests_*`` ---
       how many attacker requests elapse before the alert --- is unaffected and is
       the latency measure this study may quote.  Computational latency from E6 is
       also unaffected: it times the detector, not the traffic.
    """
    by_session = index if index is not None else index_records(records)
    peak = {sid: max((r["risk"] for r in rs), default=0.0)
            for sid, rs in by_session.items()}

    y_true, y_pred, scores = [], [], []
    lat_requests, lat_seconds = [], []
    atk_req_total = atk_req_flagged = 0

    for s in sessions:
        rs = by_session.get(s.session_id, [])
        score = peak.get(s.session_id, 0.0)
        y_true.append(s.label)
        scores.append(score)
        y_pred.append(int(score >= threshold))

        if s.label == 1:
            first = s.first_injected_index
            t_first = s.requests[first].ts if first is not None else None
            fired = None
            for r in rs:
                idx = r["request_index"]
                if r["risk"] >= threshold and (first is None or idx >= first):
                    fired = idx
                    break
            if fired is not None and first is not None:
                n_atk_before = sum(1 for i in range(first, fired + 1)
                                   if s.requests[i].injected == 1)
                lat_requests.append(max(1, n_atk_before))
                lat_seconds.append(max(0.0, s.requests[fired].ts - t_first))
            for r in rs:
                idx = r["request_index"]
                if idx < len(s.requests) and s.requests[idx].injected == 1:
                    atk_req_total += 1
                    if r["risk"] >= threshold:
                        atk_req_flagged += 1

    c = confusion(y_true, y_pred)
    out = {**c, **rate_metrics(c),
           "roc_auc": roc_auc(y_true, scores),
           "pr_auc": pr_auc(y_true, scores),
           "n_sessions": len(sessions),
           "n_attack_sessions": int(sum(y_true)),
           "attack_request_detection_rate":
               atk_req_flagged / atk_req_total if atk_req_total else float("nan"),
           "n_attack_requests": atk_req_total}
    out["latency_requests_median"] = float(np.median(lat_requests)) if lat_requests else float("nan")
    out["latency_requests_mean"] = float(np.mean(lat_requests)) if lat_requests else float("nan")
    out["latency_requests_p90"] = float(np.quantile(lat_requests, 0.9)) if lat_requests else float("nan")
    out["latency_seconds_median"] = float(np.median(lat_seconds)) if lat_seconds else float("nan")
    return out


def bootstrap_ci(values, n_boot: int = 10000, alpha: float = 0.05,
                 seed: int = 0) -> tuple[float, float]:
    """Percentile bootstrap confidence interval for the mean of ``values``."""
    v = np.asarray([x for x in values if np.isfinite(x)], dtype=float)
    if v.size == 0:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    means = v[rng.integers(0, v.size, size=(n_boot, v.size))].mean(axis=1)
    return (float(np.quantile(means, alpha / 2)), float(np.quantile(means, 1 - alpha / 2)))


# ============================================================================
# Baselines (non-ML)
# ============================================================================

# ---------------------------------------------------------------------------
# Pinning rules: session -> {0,1}
# ---------------------------------------------------------------------------

def _pin_ip(session) -> int:
    first = session.requests[0].ip
    return int(any(r.ip != first for r in session.requests))


def _pin_prefix24(session) -> int:
    first = ip_prefix24(session.requests[0].ip)
    return int(any(ip_prefix24(r.ip) != first for r in session.requests))


def _pin_scope16(session) -> int:
    first = ip_scope16(session.requests[0].ip)
    return int(any(ip_scope16(r.ip) != first for r in session.requests))


def _pin_ua(session) -> int:
    first = session.requests[0].ua
    return int(any(r.ua != first for r in session.requests))


def _ua_core(ua) -> tuple[str, str, str]:
    """Version-insensitive agent identity, identical to the one ``v_1`` uses.

    The baseline must see exactly the same derived quantity as the invariant it
    is being compared against, or the comparison measures the parser rather than
    the rule.
    """
    browser, _version, os_family, device = parse_user_agent(ua)
    return (browser, os_family, device)


def _pin_ua_core(session) -> int:
    first = _ua_core(session.requests[0].ua)
    return int(any(_ua_core(r.ua) != first for r in session.requests))


def _pin_ip_or_ua(session) -> int:
    return int(_pin_ip(session) or _pin_ua(session))


def _pin_ip_and_ua(session) -> int:
    return int(_pin_ip(session) and _pin_ua(session))


PINNING_BASELINES = {
    "pin_ip": _pin_ip,
    "pin_prefix24": _pin_prefix24,
    "pin_scope16": _pin_scope16,
    "pin_useragent": _pin_ua,
    "pin_useragent_core": _pin_ua_core,
    "pin_ip_or_useragent": _pin_ip_or_ua,
    "pin_ip_and_useragent": _pin_ip_and_ua,
}


# ---------------------------------------------------------------------------
# Scored rules: session -> float
# ---------------------------------------------------------------------------

def _score_distinct_bindings(session) -> float:
    """Number of distinct (prefix, agent-core) bindings beyond the first."""
    seen = {(ip_prefix24(r.ip), _ua_core(r.ua)) for r in session.requests}
    return float(len(seen) - 1)


def _score_max_rate(session) -> float:
    """Inverse of the shortest inter-arrival gap: a fixed request-rate rule."""
    ts = [r.ts for r in session.requests]
    gaps = [max(1e-3, ts[i] - ts[i - 1]) for i in range(1, len(ts))]
    return float(1.0 / min(gaps)) if gaps else 0.0


def _score_burstiness(session) -> float:
    """Ratio of the session's median gap to its shortest gap."""
    ts = [r.ts for r in session.requests]
    gaps = np.array([max(1e-3, ts[i] - ts[i - 1]) for i in range(1, len(ts))])
    return float(np.median(gaps) / gaps.min()) if gaps.size else 0.0


SCORED_BASELINES = {
    "score_distinct_bindings": _score_distinct_bindings,
    "score_max_request_rate": _score_max_rate,
    "score_burstiness": _score_burstiness,
}


def pinning_predictions(sessions, name: str) -> np.ndarray:
    rule = PINNING_BASELINES[name]
    return np.array([rule(s) for s in sessions], dtype=int)


def session_scores(sessions, name: str) -> np.ndarray:
    rule = SCORED_BASELINES[name]
    return np.array([rule(s) for s in sessions], dtype=float)


# ============================================================================
# Experiment protocol
# ============================================================================

@dataclass
class ExperimentConfig:
    alpha: float = 0.01                       # session-level false-alarm budget
    attack_rate: float = 0.20                 # share of evaluation sessions targeted
    split: str = "temporal"                   # temporal | client | random
    calibration_share: float = 0.5
    weighting: str = "rarity"                 # rarity | equal
    enabled: tuple[str, ...] = DEFAULT_INVARIANTS
    # The reported envelope spans the address-visible levels L0-L3 *and* the co-located
    # levels L4/L5.  Restricting it to L0-L3 would give any address-pinning rule perfect
    # recall by construction and would reduce the benchmark to address-change detection.
    levels: tuple[str, ...] = LEVELS_ALL
    modes: tuple[str, ...] = MODES
    attack_fraction: float = 0.4
    earliest_takeover: float = 0.25
    latest_takeover: float = 0.50
    theft_delay_s: float | None = None
    seed: int = 0
    churn: ChurnConfig = field(default_factory=ChurnConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------

def split_sessions(sessions, cfg: ExperimentConfig):
    """Partition sessions into calibration and evaluation sets."""
    rng = np.random.default_rng(cfg.seed)
    if cfg.split == "temporal":
        ordered = sorted(sessions, key=lambda s: s.requests[0].ts)
        cut = int(round(cfg.calibration_share * len(ordered)))
        return ordered[:cut], ordered[cut:]
    if cfg.split == "client":
        clients = sorted({s.client for s in sessions})
        idx = rng.permutation(len(clients))
        cut = int(round(cfg.calibration_share * len(clients)))
        cal_clients = {clients[int(i)] for i in idx[:cut]}
        cal = [s for s in sessions if s.client in cal_clients]
        ev = [s for s in sessions if s.client not in cal_clients]
        return cal, ev
    if cfg.split == "random":
        idx = rng.permutation(len(sessions))
        cut = int(round(cfg.calibration_share * len(sessions)))
        return ([sessions[int(i)] for i in idx[:cut]],
                [sessions[int(i)] for i in idx[cut:]])
    raise ValueError(f"unknown split: {cfg.split}")


# ---------------------------------------------------------------------------
# Injection over a scenario mixture
# ---------------------------------------------------------------------------

def inject_mixture(evaluation, cfg: ExperimentConfig, rng: np.random.Generator):
    """Inject attacks drawn uniformly from the configured scenario grid."""
    donors = build_donor_pool(evaluation, min_len=3)
    grid = [(lv, md) for lv in cfg.levels for md in cfg.modes]
    reasons: dict[str, int] = {}
    out, stats = [], {"targeted": 0, "injected": 0, "per_scenario": {},
                      "refused_per_scenario": {}}
    target = rng.random(len(evaluation)) < cfg.attack_rate
    for i, s in enumerate(evaluation):
        if not target[i]:
            out.append(s)
            continue
        lv, md = grid[int(rng.integers(0, len(grid)))]
        stats["targeted"] += 1
        key = f"{lv}_{md}"
        made = inject_session(
            s, donors,
            InjectionConfig(level=lv, mode=md, attack_fraction=cfg.attack_fraction,
                            earliest_takeover=cfg.earliest_takeover,
                            latest_takeover=cfg.latest_takeover,
                            theft_delay_s=cfg.theft_delay_s),
            rng, reasons=reasons)
        if made is None:
            # The requested condition could not be realised for this victim.  It is counted
            # per scenario so that the *effective* experimental condition is reported: a
            # theft window that a workload's session lengths cannot supply shows up here
            # rather than being silently replaced by a different theft point.
            out.append(s)
            stats["refused_per_scenario"][key] = \
                stats["refused_per_scenario"].get(key, 0) + 1
        else:
            out.append(made)
            stats["injected"] += 1
            stats["per_scenario"][key] = stats["per_scenario"].get(key, 0) + 1
    stats["n_evaluation_sessions"] = len(out)
    stats["attack_prevalence"] = stats["injected"] / max(1, len(out))
    stats["refusal_reasons"] = reasons
    stats["theft_window"] = [cfg.earliest_takeover, cfg.latest_takeover]
    return out, stats


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------

def _replay(sessions, monitor_cfg: MonitorConfig) -> list[dict]:
    monitor = ContinuityMonitor(monitor_cfg)
    out = []
    for s in sessions:
        for r in s.requests:
            out.append(monitor.observe(s.session_id, r.ip, r.ua, r.ts,
                                       r.path, r.referrer))
    return out


def run_experiment(sessions, cfg: ExperimentConfig) -> dict:
    """Execute one complete calibrate-then-evaluate run and return all outputs."""
    rng = np.random.default_rng(cfg.seed)
    cal, ev = split_sessions(sessions, cfg)
    if len(cal) < 20 or len(ev) < 20:
        raise ValueError("split produced too few sessions to calibrate or evaluate")

    # Benign binding churn is applied to BOTH partitions with the same declared
    # rates: the calibration traffic an operator would use is itself subject to
    # legitimate mobility, so the false-alarm budget must be met in its presence.
    cal, cal_churn = apply_churn(cal, cfg.churn, rng)
    ev, ev_churn = apply_churn(ev, cfg.churn, rng)

    ev_injected, inj_stats = inject_mixture(ev, cfg, rng)

    monitor_cfg, cal_info = calibrate(
        cal, alpha=cfg.alpha, enabled=cfg.enabled, weighting=cfg.weighting,
        base_cfg=cfg.monitor)

    records = _replay(ev_injected, monitor_cfg)
    idx = index_records(records)
    result = evaluate_sessions(ev_injected, records, monitor_cfg.threshold, index=idx)

    # Per-scenario breakdown, evaluated against the shared benign population so
    # that precision and FPR remain interpretable in every cell.
    benign = [s for s in ev_injected if s.label == 0]
    by_scenario: dict[str, list] = {}
    for s in ev_injected:
        if s.label == 1:
            by_scenario.setdefault(s.scenario, []).append(s)
    per_scenario = {}
    for scenario in sorted(by_scenario):
        subset = benign + by_scenario[scenario]
        per_scenario[scenario] = evaluate_sessions(subset, records,
                                                   monitor_cfg.threshold, index=idx)

    # Benign false alarms broken down by the legitimate churn phenomenon that
    # caused them, so that the cost of each invariant on real mobility is visible.
    fp_by_churn: dict[str, dict] = {}
    peak = {sid: max((r["risk"] for r in rs), default=0.0) for sid, rs in idx.items()}
    for s in ev_injected:
        if s.label != 0:
            continue
        row = fp_by_churn.setdefault(s.scenario, {"sessions": 0, "false_alarms": 0})
        row["sessions"] += 1
        row["false_alarms"] += int(peak.get(s.session_id, 0.0) >= monitor_cfg.threshold)
    for row in fp_by_churn.values():
        row["fpr"] = row["false_alarms"] / max(1, row["sessions"])

    return {"metrics": result, "per_scenario": per_scenario,
            "fp_by_churn": fp_by_churn,
            "churn": {"calibration": cal_churn, "evaluation": ev_churn},
            "calibration": cal_info, "injection": inj_stats,
            "n_calibration_sessions": len(cal), "n_evaluation_sessions": len(ev_injected),
            "threshold": monitor_cfg.threshold, "weights": monitor_cfg.weights,
            "sessions": ev_injected, "records": records, "monitor_cfg": monitor_cfg,
            "calibration_sessions": cal}


def run_baselines(cal_sessions, ev_sessions, alpha: float) -> list[dict]:
    """Evaluate every baseline on the same evaluation sessions.

    Pinning rules are parameter-free.  Scored rules are calibrated to the same
    false-alarm budget on the same attack-free calibration partition.

    **Reporting treatment of binary rules.**  A pinning rule emits a decision, not a score:
    it has one operating point and no ranking to measure.  Its ROC curve therefore has a
    single interior point and the area under it collapses identically to
    ``(TPR + TNR) / 2`` --- balanced accuracy --- which
    ``tests/test_regressions.py::test_binary_rule_auc_is_exactly_balanced_accuracy``
    asserts.  Reporting that quantity in the same ``roc_auc`` column as a ranking AUC over a
    continuous risk score would imply a score resolution the rule does not have, and would
    invite a comparison that is not meaningful.  So ranking metrics are withheld for these
    rules (``NaN``) and their operating-point metrics --- recall, FPR, precision, F1,
    balanced accuracy --- carry the comparison instead.  No continuous score is invented for
    them: none exists.  ``score_resolution`` marks which treatment each row received, so the
    distinction survives into every generated table.
    """
    y = [s.label for s in ev_sessions]
    rows = []
    for name in PINNING_BASELINES:
        pred = pinning_predictions(ev_sessions, name)
        c = confusion(y, pred)
        rows.append({"baseline": name, "family": "pinning", "threshold": float("nan"),
                     "score_resolution": "binary",
                     **c, **rate_metrics(c),
                     "roc_auc": float("nan"), "pr_auc": float("nan")})
    for name in SCORED_BASELINES:
        cal_scores = session_scores(cal_sessions, name)
        tau = threshold_for_budget(cal_scores, alpha)
        ev_scores = session_scores(ev_sessions, name)
        pred = (ev_scores >= tau).astype(int)
        c = confusion(y, pred)
        rows.append({"baseline": name, "family": "scored", "threshold": float(tau),
                     "score_resolution": "continuous",
                     **c, **rate_metrics(c),
                     "roc_auc": roc_auc(y, ev_scores), "pr_auc": pr_auc(y, ev_scores)})
    return rows
