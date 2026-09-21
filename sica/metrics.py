"""Session-level and request-level evaluation metrics.

The primary unit is the *session*: an operator responds to a session, not to an
individual request.  Request-level statistics are reported as a secondary view
because they determine detection latency, which is the operationally decisive
quantity for hijack response.
"""
from __future__ import annotations

import numpy as np

__all__ = ["confusion", "rate_metrics", "roc_auc", "pr_auc", "evaluate_sessions",
           "index_records", "bootstrap_ci"]


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
       (``docs/DATASET_VERIFICATION.md`` section 6).  ``latency_requests_*`` ---
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
