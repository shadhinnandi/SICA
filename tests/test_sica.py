"""Regression and protocol tests.

The protocol tests are the important ones: they assert the properties that make
the reported numbers meaningful --- that calibration never sees an attack label,
that the threshold is frozen before evaluation, that the injection is
length-matched, and that the monitor's state really is bounded.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

import sica
from sica.calibrate import applicability, benign_rarity_weights, threshold_for_budget
from sica.churn import ChurnConfig, apply_churn
from sica.fingerprint import binding_of, ip_prefix24, ip_scope16, parse_user_agent
from sica.inject import InjectionConfig, inject_session
from sica.invariants import InvariantParams, v3_binding_fork, v5_rate_discontinuity
from sica.metrics import pr_auc, roc_auc
from sica.monitor import ContinuityMonitor, MonitorConfig

CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"


# --- fingerprinting --------------------------------------------------------

def test_prefix_and_scope():
    assert ip_prefix24("203.0.113.45") == "203.0.113"
    assert ip_scope16("203.0.113.45") == "203.0"


def test_agent_parsing_distinguishes_family_and_version():
    b1, v1, os1, d1 = parse_user_agent(CHROME)
    b2, v2, os2, d2 = parse_user_agent(FIREFOX)
    assert (b1, os1, d1) == ("Chrome", "Windows", "Desktop")
    assert (b2, os2, d2) == ("Firefox", "Linux", "Desktop")
    assert v1 == "120" and v2 == "121"


def test_missing_agent_is_an_explicit_identity():
    assert parse_user_agent("-")[0] == "unknown"
    assert parse_user_agent(None)[0] == "unknown"


def test_binding_key_separates_hosts_in_one_subnet():
    a = binding_of("203.0.113.5", CHROME)
    b = binding_of("203.0.113.6", CHROME)
    assert a.prefix24 == b.prefix24 and a.key != b.key


# --- invariants ------------------------------------------------------------

def test_network_grading_is_ordered():
    p = InvariantParams()
    pin = binding_of("203.0.113.5", CHROME)
    from sica.invariants import v2_scope_discontinuity as v2
    assert v2(binding_of("203.0.113.5", CHROME), pin, p) == 0.0
    assert v2(binding_of("203.0.113.9", CHROME), pin, p) == p.host_severity
    assert v2(binding_of("203.0.99.9", CHROME), pin, p) == p.subnet_severity
    assert v2(binding_of("198.51.100.9", CHROME), pin, p) == 1.0


def test_agent_grading_separates_upgrade_from_substitution():
    p = InvariantParams()
    pin = binding_of("203.0.113.5", CHROME)
    from sica.invariants import v1_agent_mutation as v1
    assert v1(binding_of("203.0.113.5", CHROME), pin, p) == 0.0
    assert v1(binding_of("203.0.113.5", CHROME.replace("120.0", "121.0")), pin, p) \
        == p.version_severity
    assert v1(binding_of("203.0.113.5", FIREFOX), pin, p) == 1.0


def test_fork_fires_only_on_a_revisit():
    assert v3_binding_fork(True) == 1.0
    assert v3_binding_fork(False) == 0.0


def test_rate_invariant_is_silent_during_warmup():
    p = InvariantParams()
    assert v5_rate_discontinuity(0.001, 10.0, 1, p) == 0.0
    assert v5_rate_discontinuity(0.001, 10.0, 9, p) > 0.9


def test_monotone_move_scores_once_then_settles():
    """Reference migration charges a legitimate move a single time."""
    m = ContinuityMonitor(MonitorConfig(threshold=10.0, migrate_reference=True))
    m.observe("s", "203.0.113.5", CHROME, 0.0)
    for t in (10.0, 20.0):
        m.observe("s", "203.0.113.5", CHROME, t)
    first = m.observe("s", "198.51.100.9", CHROME, 30.0)
    second = m.observe("s", "198.51.100.9", CHROME, 40.0)
    assert first["V2_scope_discontinuity"] == 1.0
    assert second["V2_scope_discontinuity"] == 0.0


def test_interleaving_raises_the_fork_invariant_but_a_move_does_not():
    cfg = MonitorConfig(threshold=10.0)
    move = ContinuityMonitor(cfg)
    fork = ContinuityMonitor(cfg)
    for t, ip in enumerate(["203.0.113.5"] * 3 + ["198.51.100.9"] * 3):
        r_move = move.observe("s", ip, CHROME, 10.0 * t)
    for t, ip in enumerate(["203.0.113.5", "203.0.113.5", "203.0.113.5",
                            "198.51.100.9", "203.0.113.5", "198.51.100.9"]):
        r_fork = fork.observe("s", ip, CHROME, 10.0 * t)
    assert r_move["V3_binding_fork"] == 0.0
    assert r_fork["V3_binding_fork"] == 1.0


def test_state_is_bounded():
    cfg = MonitorConfig(threshold=10.0, ring_size=4, path_window=8)
    m = ContinuityMonitor(cfg)
    for i in range(500):
        m.observe("s", f"203.0.{i % 200}.{i % 250 + 1}", CHROME, float(i), f"/p{i}")
    st = m.sessions["s"]
    assert len(st.ring) <= cfg.ring_size
    assert len(st.paths) <= cfg.path_window


# --- calibration -----------------------------------------------------------

def test_weights_are_larger_for_rarer_invariants():
    records = [{"V1_agent_mutation": 0.0, "V2_scope_discontinuity": 0.5}
               for _ in range(10)]
    w = benign_rarity_weights(records, ("V1_agent_mutation", "V2_scope_discontinuity"))
    assert w["V1_agent_mutation"] > w["V2_scope_discontinuity"]
    assert abs(sum(w.values()) - 1.0) < 1e-9


def test_threshold_meets_the_budget_on_its_own_sample():
    values = np.linspace(0, 1, 1000)
    tau = threshold_for_budget(values, 0.01)
    assert (values >= tau).mean() <= 0.011


def test_applicability_detects_an_unexercisable_invariant():
    records = [{"A_V6_navigation_break": False, "A_V1_agent_mutation": True}
               for _ in range(50)]
    a = applicability(records, ("V1_agent_mutation", "V6_navigation_break"))
    assert a["V6_navigation_break"] == 0.0 and a["V1_agent_mutation"] == 1.0


# --- injection and protocol ------------------------------------------------

DATA = Path(__file__).resolve().parents[1] / "data" / "raw" / "apache_sample_1.log"


@pytest.fixture(scope="module")
def sessions():
    return sica.load_sessions(str(DATA), min_requests=7)


def test_injection_is_length_matched(sessions):
    rng = np.random.default_rng(0)
    donors = [s for s in sessions if s.n >= 3]
    made = 0
    for victim in sessions[:120]:
        for level in sica.LEVELS:
            out = inject_session(victim, donors,
                                 InjectionConfig(level=level, mode="concurrent"), rng)
            if out is not None:
                assert out.n == victim.n
                assert any(r.injected for r in out.requests)
                made += 1
    assert made > 20


def test_takeover_is_a_real_takeover(sessions):
    """After the theft, a takeover session must contain no victim request.

    An earlier revision derived the theft point and the attacker's share
    independently, so the victim kept issuing requests after the theft and
    "takeover" was silently a partially concurrent hijack --- which let the fork
    invariant fire on a scenario that by definition contains no fork.
    """
    rng = np.random.default_rng(0)
    donors = [s for s in sessions if s.n >= 3]
    checked = 0
    for victim in sessions[:150]:
        for level in sica.LEVELS:
            out = inject_session(victim, donors,
                                 InjectionConfig(level=level, mode="takeover"), rng)
            if out is None:
                continue
            first = out.first_injected_index
            assert all(r.injected == 1 for r in out.requests[first:])
            assert out.n == victim.n
            checked += 1
    assert checked > 20


def test_concurrent_hijack_actually_interleaves(sessions):
    rng = np.random.default_rng(1)
    donors = [s for s in sessions if s.n >= 3]
    interleaved = total = 0
    for victim in sessions[:150]:
        out = inject_session(victim, donors,
                             InjectionConfig(level="L0", mode="concurrent"), rng)
        if out is None:
            continue
        total += 1
        tail = [r.injected for r in out.requests[out.first_injected_index:]]
        interleaved += int(0 in tail)          # a victim request follows the theft
    assert total > 20
    assert interleaved / total > 0.8


def test_calibration_partition_contains_no_attacks(sessions):
    res = sica.run_experiment(sessions, sica.ExperimentConfig(seed=1))
    assert all(s.label == 0 for s in res["calibration_sessions"])
    assert all(r.injected == 0 for s in res["calibration_sessions"] for r in s.requests)


def test_calibration_ignores_labels_entirely(sessions):
    """Relabelling the calibration traffic must not move the weights or threshold.

    This is the property whose absence produced the oracle operating points that
    the earlier version of this project had to retract.
    """
    import copy
    from sica.calibrate import calibrate
    res = sica.run_experiment(sessions, sica.ExperimentConfig(seed=2))
    cal = res["calibration_sessions"]
    cfg_a, info_a = calibrate(cal, alpha=0.01)
    relabelled = copy.deepcopy(cal)
    for s in relabelled:
        s.label = 1
        s.scenario = "adversarial-relabelling"
    cfg_b, info_b = calibrate(relabelled, alpha=0.01)
    assert cfg_a.threshold == pytest.approx(cfg_b.threshold)
    assert cfg_a.weights == pytest.approx(cfg_b.weights)


def test_run_is_reproducible_from_the_seed(sessions):
    a = sica.run_experiment(sessions, sica.ExperimentConfig(seed=7))
    b = sica.run_experiment(sessions, sica.ExperimentConfig(seed=7))
    assert a["threshold"] == pytest.approx(b["threshold"])
    assert a["metrics"] == b["metrics"]


def test_detector_is_deterministic(sessions):
    a = sica.run_experiment(sessions, sica.ExperimentConfig(seed=3))["metrics"]
    b = sica.run_experiment(sessions, sica.ExperimentConfig(seed=3))["metrics"]
    assert a == b


def test_churn_is_applied_only_to_benign_sessions(sessions):
    """Churn models the legitimate client, so an attack session must pass through untouched.

    The session under test is deep-copied.  An earlier revision mutated the module-scoped
    fixture in place and restored it on the last line, so any failure before that line left
    every subsequent test running against a corrupted corpus -- making results depend on
    execution order and on whether an unrelated test had already failed.
    """
    import copy

    rng = np.random.default_rng(0)
    marked = copy.deepcopy(sessions)
    marked[0].label = 1
    out, stats = apply_churn(marked, ChurnConfig(), rng)
    assert out[0].scenario == marked[0].scenario
    assert out[0].label == 1
    assert stats["churned_sessions"] > 0


def test_the_session_fixture_is_not_mutated_by_any_test(sessions):
    """Fixture integrity: the shared corpus must still be pristine for later tests.

    Placed after the tests that do the most mutation-prone work, so that it fails loudly if
    any of them writes through to the shared fixture rather than to a copy.
    """
    assert all(s.label == 0 for s in sessions), "a test wrote a label into the fixture"
    assert all(s.scenario == "benign" for s in sessions), \
        "a test wrote a scenario into the fixture"
    assert all(r.injected == 0 for s in sessions for r in s.requests), \
        "a test injected into the fixture"


# --- metrics ---------------------------------------------------------------

def test_auc_edge_cases():
    assert roc_auc([0, 0, 1, 1], [0.0, 0.1, 0.9, 1.0]) == 1.0
    assert roc_auc([0, 1], [0.5, 0.5]) == 0.5
    assert 0.0 <= pr_auc([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9]) <= 1.0
