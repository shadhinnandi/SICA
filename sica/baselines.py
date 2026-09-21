"""Non-machine-learning baselines for session-hijack detection.

Every baseline is a deterministic rule over the same request stream and the
same session boundaries used by the proposed monitor, so the comparison isolates
the detection logic rather than the data pipeline.

Two families are included.

*Pinning rules* are the defences that deployed applications actually use: bind
the session identifier to the address, the address prefix, or the User-Agent
string, and terminate on any change.  They are parameter-free, so their
false-alarm rate is whatever the traffic makes it; they cannot be calibrated to
a budget.  This is precisely the operational complaint against them and is
reported rather than hidden.

*Scored rules* emit a continuous session score and are calibrated with exactly
the same protocol as the proposed method --- the :math:`(1-\\alpha)` quantile of
benign calibration scores --- so that they are compared at an equal false-alarm
budget.
"""
from __future__ import annotations

import numpy as np

from .fingerprint import ip_prefix24, ip_scope16, parse_user_agent

__all__ = ["PINNING_BASELINES", "SCORED_BASELINES", "session_scores",
           "pinning_predictions"]


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
