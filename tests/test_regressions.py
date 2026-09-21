"""Regression tests for the defects found in the architecture audit.

Each test here corresponds to a numbered finding in ``docs/ARCHITECTURE_AUDIT.md`` and was
written *before* the corresponding correction, and confirmed to fail against the old
behaviour.  They exist to stop a repaired defect from returning silently; the property each
one asserts is stated in ``docs/TEST_PLAN.md``.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

import sica
from sica.calibrate import calibrate, threshold_for_budget

DATA = Path(__file__).resolve().parents[1] / "data" / "raw" / "apache_sample_1.log"

# A coarse, heavily tied population of session peak risks.  This is the shape the real
# statistic has: a large mass at zero (sessions with no binding change at all) and a few
# discrete plateaus produced by the fixed invariant severities.  The old implementation was
# only ever exercised against a continuum, which is why it passed while the deployed system
# missed its budget by a factor of two.
TIED_PEAKS = [0.0] * 900 + [0.29] * 40 + [0.33] * 30 + [0.44] * 20 + [0.62] * 10


@pytest.fixture(scope="module")
def sessions():
    return sica.load_sessions(str(DATA), min_requests=7)


# --- C1: the false-alarm budget ---------------------------------------------

def test_threshold_meets_the_budget_under_heavy_ties():
    """The declared guarantee must hold under the alert rule actually deployed.

    The monitor alerts on ``peak >= tau``.  A quantile that lands on a plateau of tied
    values therefore admits the whole plateau, so taking the (1-alpha) quantile does not
    bound the alarm rate by alpha.
    """
    peaks = np.asarray(TIED_PEAKS, dtype=float)
    for alpha in (0.001, 0.005, 0.01, 0.02, 0.05):
        tau = threshold_for_budget(peaks, alpha)
        realised = float((peaks >= tau).mean())
        assert realised <= alpha + 1e-12, (
            f"alpha={alpha}: tau={tau} admits {realised:.4f} of the calibration sample")


def test_threshold_is_the_smallest_meeting_the_budget():
    """Minimality: no smaller observed value also satisfies the budget.

    Without this the budget could be met trivially by thresholding above every observation,
    which would satisfy alpha while detecting nothing.
    """
    peaks = np.asarray(TIED_PEAKS, dtype=float)
    for alpha in (0.005, 0.01, 0.02, 0.05):
        tau = threshold_for_budget(peaks, alpha)
        smaller = [v for v in np.unique(peaks) if v < tau]
        for v in smaller:
            assert float((peaks >= v).mean()) > alpha, (
                f"alpha={alpha}: {v} also meets the budget, so tau={tau} is not minimal")


def test_threshold_is_unattainable_when_the_sample_is_too_coarse():
    """When no observed value meets the budget, alert nothing rather than overshoot.

    With 10 sessions tied at the maximum and alpha=0.001, admitting the maximum would alarm
    on 1% of the sample -- ten times the budget.  The conservative choice is the only one
    that keeps the declared guarantee.
    """
    peaks = np.asarray([0.0] * 990 + [0.62] * 10, dtype=float)
    tau = threshold_for_budget(peaks, 0.001)
    assert float((peaks >= tau).mean()) == 0.0
    assert tau > peaks.max()


def test_calibration_achieves_its_declared_budget_end_to_end(sessions):
    """On real calibration traffic the realised in-sample alarm rate must respect alpha."""
    res = sica.run_experiment(sessions, sica.ExperimentConfig(seed=11))
    info = res["calibration"]
    assert info["calibration_alarm_rate"] <= info["alpha"] + 1e-12, (
        f"calibration alarm rate {info['calibration_alarm_rate']:.4f} "
        f"exceeds the declared budget {info['alpha']}")


# --- C2: the evaluation envelope must measure hijacking, not address change ---

def test_reported_envelope_contains_colocated_attackers():
    """The reported envelope must contain attacks with no address difference at all.

    If every evaluated attack gives the attacker a different address, then "alert on any
    address change" detects all of them by construction, the recall axis of the baseline
    comparison carries no information, and the benchmark measures address-change detection
    rather than session-hijack detection.
    """
    from sica.inject import LEVELS_COLOCATED
    reported = set(sica.ExperimentConfig().levels)
    assert set(LEVELS_COLOCATED) <= reported, (
        f"reported envelope {sorted(reported)} excludes the co-located levels "
        f"{sorted(LEVELS_COLOCATED)}, so address pinning is perfect by construction")


def test_every_masquerade_level_has_its_declared_address_relation(sessions):
    """Each level must bear its documented relation to the victim's address and agent."""
    from sica.fingerprint import ip_prefix24, ip_scope16
    from sica.inject import LEVELS_ALL, InjectionConfig, inject_session

    rng = np.random.default_rng(0)
    donors = [s for s in sessions if s.n >= 3]
    checked = {lv: 0 for lv in LEVELS_ALL}
    for victim in sessions[:120]:
        for level in LEVELS_ALL:
            out = inject_session(victim, donors,
                                 InjectionConfig(level=level, mode="concurrent"), rng)
            if out is None:
                continue
            atk = out.requests[out.first_injected_index]
            vic_ip, vic_ua = victim.client
            if level in ("L0", "L1"):
                assert ip_scope16(atk.ip) != ip_scope16(vic_ip)
            elif level == "L2":
                assert ip_scope16(atk.ip) == ip_scope16(vic_ip)
                assert ip_prefix24(atk.ip) != ip_prefix24(vic_ip)
            elif level == "L3":
                assert ip_prefix24(atk.ip) == ip_prefix24(vic_ip)
                assert atk.ip != vic_ip
            else:                                   # L4, L5: co-located
                assert atk.ip == vic_ip
            if level in ("L1", "L3", "L4"):
                assert atk.ua == vic_ua             # agent cloned
            if level == "L5":
                assert atk.ua != vic_ua             # co-located, different client software
            checked[level] += 1
    for level, n in checked.items():
        assert n > 10, f"too few {level} injections exercised ({n})"


# --- H1: the masquerade level must be relative to the victim's live binding ---

def _victim_with_churn_before_theft(base, new_ip, new_ua, cut_at=2):
    """A victim whose address and agent change partway through, before any theft point."""
    import copy
    from sica.sessionize import Session
    reqs = [copy.copy(r) for r in base.requests]
    for r in reqs[cut_at:]:
        r.ip, r.ua = new_ip, new_ua
    return Session(session_id=base.session_id, client=base.client, requests=reqs,
                   label=0, scenario="M3_combined:scope")


def test_masquerade_level_uses_the_post_churn_victim_binding(sessions):
    """Levels must be defined against the binding the victim actually presents.

    Benign churn is applied before injection, so a victim's live address at the theft point
    need not be the address its session started from.  Deriving L2/L3/L4/L5 from the
    original address makes those levels mean something other than what they claim -- and in
    the favourable direction, because the attacker then looks further from the victim than
    the level declares.
    """
    from sica.fingerprint import ip_prefix24, ip_scope16
    from sica.inject import InjectionConfig, inject_session

    rng = np.random.default_rng(3)
    donors = [s for s in sessions if s.n >= 3]
    victims = [s for s in sessions if s.n >= 12][:40]
    assert len(victims) > 5

    checked = 0
    for base in victims:
        # Move the victim to a different /16 early, so every theft point lands after it.
        victim = _victim_with_churn_before_theft(base, "198.51.100.7", FIREFOX_UA)
        for level in ("L2", "L3", "L4", "L5"):
            out = inject_session(victim, donors,
                                 InjectionConfig(level=level, mode="concurrent"), rng)
            if out is None:
                continue
            first = out.first_injected_index
            atk = out.requests[first]
            # The victim's binding immediately before the theft is the reference.
            live = [r for r in out.requests[:first] if r.injected == 0][-1]
            if level == "L2":
                assert ip_scope16(atk.ip) == ip_scope16(live.ip)
                assert ip_prefix24(atk.ip) != ip_prefix24(live.ip)
            elif level == "L3":
                assert ip_prefix24(atk.ip) == ip_prefix24(live.ip)
                assert atk.ip != live.ip
            else:
                assert atk.ip == live.ip
            if level == "L4":
                assert atk.ua == live.ua
            checked += 1
    assert checked > 20, f"too few injections exercised ({checked})"


FIREFOX_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"


# --- H2: benign agent churn must be observable on the agent families in the data ---

REAL_AGENTS = {
    "Chrome": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/32.0.1700.107 Safari/537.36",
    "Firefox": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:27.0) Gecko/20100101 Firefox/27.0",
    "Safari": "Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 "
              "(KHTML, like Gecko) Version/6.0 Mobile/10A403 Safari/8536.25",
    "AptHTTP": "Debian APT-HTTP/1.3 (0.9.7.9)",
    "Wget": "Wget/1.13.4 (linux-gnu)",
    "Curl": "curl/7.35.0",
}


def test_version_bump_is_observable_for_every_parsed_family():
    """An agent update must move the version the fingerprinter actually reads.

    The previous implementation appended a token the parser ignores whenever the agent was
    not a mainstream browser, so on a workload dominated by one such family the benign
    agent-update class existed in name only.
    """
    from sica.churn import bump_agent_version
    from sica.fingerprint import binding_of

    for family, ua in REAL_AGENTS.items():
        before = binding_of("203.0.113.5", ua)
        assert before.browser == family, f"{family}: parsed as {before.browser}"
        assert before.version != "", f"{family}: no version parsed from a real agent"
        updated = bump_agent_version(ua)
        assert updated is not None, f"{family}: no observable update available"
        after = binding_of("203.0.113.5", updated)
        assert after.core == before.core, f"{family}: update must not change the agent core"
        assert after.version != before.version, (
            f"{family}: update left the parsed version at {before.version!r} "
            f"({ua!r} -> {updated!r})")


def test_agent_churn_is_observable_on_the_apt_workload():
    """On package-manager traffic, M2-churned sessions must actually exercise V1."""
    from sica.churn import ChurnConfig, apply_churn
    from sica.monitor import ContinuityMonitor, MonitorConfig
    from pipeline.common import load

    w2 = load("W2_apt")[:400]
    churned, stats = apply_churn(
        w2, ChurnConfig(monotone_rate=1.0, flapping_rate=0.0), np.random.default_rng(0))
    m2 = [s for s in churned if s.scenario.startswith("M2_agent_update")]
    assert len(m2) > 20, f"too few M2 sessions produced ({len(m2)})"

    monitor = ContinuityMonitor(MonitorConfig(threshold=float("inf")))
    fired = 0
    for s in m2:
        for r in s.requests:
            rec = monitor.observe(s.session_id, r.ip, r.ua, r.ts, r.path, r.referrer)
            if rec["V1_agent_mutation"] > 0.0:
                fired += 1
                break
    assert fired > 0, (
        "no M2-churned session on W2 produced a V1 firing: the benign agent-update class "
        "is inactive on this workload, so V1's false-alarm cost there is not measured")


# --- H5: a deterministic binary rule has no ranking curve to report ---

def test_binary_rule_auc_is_exactly_balanced_accuracy():
    """Why the AUC of a pinning rule is withdrawn rather than reported.

    A parameter-free rule emits one decision, not a score, so its ROC curve has a single
    interior point and the area under it collapses to ``(TPR + TNR) / 2``.  Publishing that
    in the same column as a ranking AUC over a continuous risk implies a score resolution the
    rule does not have.
    """
    from sica.metrics import confusion, rate_metrics, roc_auc

    rng = np.random.default_rng(0)
    for _ in range(20):
        y = rng.integers(0, 2, size=200)
        pred = rng.integers(0, 2, size=200)
        if y.sum() == 0 or y.sum() == len(y):
            continue
        ba = rate_metrics(confusion(y, pred))["balanced_accuracy"]
        assert roc_auc(y, pred.astype(float)) == pytest.approx(ba)


def test_pinning_baselines_report_no_ranking_metrics(sessions):
    """Binary baselines must carry their operating-point metrics and no ranking metric."""
    from sica.harness import run_baselines

    cfg = sica.ExperimentConfig(seed=4)
    res = sica.run_experiment(sessions, cfg)
    rows = run_baselines(res["calibration_sessions"], res["sessions"], cfg.alpha)
    assert rows, "no baseline rows produced"
    assert sum(s.label for s in res["sessions"]) > 10, "too few attacks to rank"

    pinning = [r for r in rows if r["family"] == "pinning"]
    scored = [r for r in rows if r["family"] == "scored"]
    assert pinning and scored

    for r in pinning:
        assert r["score_resolution"] == "binary"
        assert np.isnan(r["roc_auc"]), f"{r['baseline']} reports a ranking AUC"
        assert np.isnan(r["pr_auc"]), f"{r['baseline']} reports an average precision"
        for key in ("recall", "fpr", "precision", "f1", "balanced_accuracy"):
            assert np.isfinite(r[key]), f"{r['baseline']} is missing {key}"
    for r in scored:
        assert r["score_resolution"] == "continuous"
        assert np.isfinite(r["roc_auc"]), f"{r['baseline']} lost its ranking AUC"


# --- M2: a requested theft window must not be silently overridden ---

def _synthetic_session(sid: str, ip: str, ua: str, n: int, t0: float = 0.0):
    """A session of exactly ``n`` requests, one second apart."""
    from sica.sessionize import Request, Session
    reqs = [Request(ip=ip, ua=ua, ts=t0 + i, path=f"/p{i}", referrer="-",
                    status=200, nbytes=100) for i in range(n)]
    return Session(session_id=sid, client=(ip, ua), requests=reqs)


CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
OTHER_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"


@pytest.mark.parametrize("earliest,latest,label", [
    (0.70, 0.80, "below the cap"),     # k required ~19-30
    (0.58, 0.62, "spanning the cap"),  # k required ~37-42, straddles 40
    (0.20, 0.30, "above the cap"),     # k required ~69-80
])
def test_takeover_respects_its_theft_window(earliest, latest, label):
    """The theft position is an experimental condition and must appear as requested.

    In a takeover the attacker replaces the whole remaining tail, so the attacker's share is
    fixed by the theft point.  The old implementation capped that share at
    ``max_attacker_requests`` and then re-derived the theft point from the cap, so an early
    theft in a long session was silently relocated to wherever the cap put it -- roughly 59%
    of the session regardless of what the sweep asked for.  E4's theft-position sweep was
    inert for exactly the sessions it was meant to probe.
    """
    from sica.inject import InjectionConfig, inject_session

    n = 100
    rng = np.random.default_rng(0)
    donor = _synthetic_session("donor", "198.51.100.9", OTHER_UA, 200, t0=5000.0)
    produced = []
    for i in range(30):
        victim = _synthetic_session(f"v{i}", "203.0.113.5", CHROME_UA, n)
        out = inject_session(
            victim, [donor],
            InjectionConfig(level="L0", mode="takeover",
                            earliest_takeover=earliest, latest_takeover=latest), rng)
        if out is None:
            continue
        theft = out.first_injected_index / n
        produced.append(theft)

    assert len(produced) >= 20, f"{label}: only {len(produced)} of 30 sessions produced"
    tol = 1.0 / n                       # one request, for ceil/floor rounding of the window
    for theft in produced:
        assert earliest - tol <= theft <= latest + tol, (
            f"{label}: requested theft window [{earliest}, {latest}] but the session was "
            f"stolen at {theft:.3f} -- the requested condition was overridden")


def test_takeover_reports_rejections_rather_than_relocating_the_theft():
    """When no donor can supply the tail, the session is refused and the refusal counted."""
    from sica.inject import InjectionConfig, inject_session

    rng = np.random.default_rng(0)
    short_donor = _synthetic_session("donor", "198.51.100.9", OTHER_UA, 8, t0=5000.0)
    victim = _synthetic_session("v", "203.0.113.5", CHROME_UA, 100)
    reasons: dict[str, int] = {}
    out = inject_session(
        victim, [short_donor],
        InjectionConfig(level="L0", mode="takeover",
                        earliest_takeover=0.20, latest_takeover=0.30), rng,
        reasons=reasons)
    assert out is None
    assert sum(reasons.values()) == 1, f"no rejection recorded: {reasons}"


# --- D1: a concurrent hijack must interleave at every swept theft delay ---

@pytest.mark.parametrize("delay", [None, 0.0, 1.0, 60.0, 600.0])
def test_concurrent_interleaves_at_every_swept_theft_delay(sessions, delay):
    """The defining property of the concurrent mode must survive its own sweep.

    Sessions in these corpora span at most 59 seconds, because the source logs carry a
    degenerate minute field (see docs/DATASET_VERIFICATION.md).  E4 nevertheless sweeps
    ``theft_delay_s`` over 0/1/60/600 s.  At 60 s and above the attacker's first request was
    placed after the victim's session had already ended, so the victim's surviving requests
    all preceded the attacker's and the session became a takeover wearing a concurrent
    label -- measured at only 34% still interleaving.  The sweep was then varying the
    scenario type rather than the delay it claimed to vary.
    """
    from sica.inject import InjectionConfig, inject_session

    rng = np.random.default_rng(1)
    donors = [s for s in sessions if s.n >= 3]
    produced = interleaved = 0
    for victim in sessions[:150]:
        out = inject_session(
            victim, donors,
            InjectionConfig(level="L0", mode="concurrent", theft_delay_s=delay), rng)
        if out is None:
            continue
        produced += 1
        tail = [r.injected for r in out.requests[out.first_injected_index:]]
        interleaved += int(0 in tail)
    assert produced > 20, f"delay={delay}: only {produced} sessions produced"
    assert interleaved == produced, (
        f"delay={delay}: {produced - interleaved} of {produced} concurrent sessions contain "
        f"no victim request after the theft -- they are takeovers mislabelled as concurrent")


# --- M1/M7: identifiers must not depend on process-local hash randomisation ---

_ID_PROBE = r"""
import sys
sys.path.insert(0, %r)
import sica
sessions = sica.load_sessions(%r, min_requests=7)
print(len(sessions))
for s in sessions[:40]:
    print(s.session_id)
"""


def _session_ids_under(hashseed: str) -> list[str]:
    """Sessionise in a *separate* interpreter with a chosen PYTHONHASHSEED."""
    import os
    import subprocess

    root = str(Path(__file__).resolve().parents[1])
    env = dict(os.environ, PYTHONHASHSEED=hashseed)
    out = subprocess.run([sys.executable, "-c", _ID_PROBE % (root, str(DATA))],
                         capture_output=True, text=True, env=env, timeout=300)
    assert out.returncode == 0, out.stderr[-2000:]
    return out.stdout.strip().splitlines()


def test_session_ids_are_deterministic_across_processes():
    """Session identifiers must be reproducible, not a function of the interpreter's salt.

    ``hash()`` on a ``str`` is salted per process unless ``PYTHONHASHSEED`` is pinned, so an
    identifier built from it differs between runs.  That contradicts the reproducibility
    claim and makes the uniqueness of the identifier a matter of luck rather than of
    construction.
    """
    a = _session_ids_under("0")
    b = _session_ids_under("12345")
    assert a and a[0].isdigit() and int(a[0]) > 50, "probe produced no sessions"
    assert a == b, "session identifiers change with PYTHONHASHSEED"


def test_session_ids_are_unique_on_both_corpora():
    """Distinct sessions must never collide onto one identifier.

    A collision would merge two sessions' state inside the monitor and corrupt both.
    """
    from pipeline.common import WORKLOADS, load

    for workload in WORKLOADS:
        sessions = load(workload)
        ids = [s.session_id for s in sessions]
        assert len(set(ids)) == len(ids), (
            f"{workload}: {len(ids) - len(set(ids))} duplicate session identifiers")


# --- H3: PR AUC must be a function of the data, not of the input order ---

def test_pr_auc_is_invariant_to_input_order_under_ties():
    """Equally-scored samples must not be ranked by their position in the input.

    The session risk statistic is coarse and heavily tied -- the same property that makes
    the threshold plateau in C1 -- so ties are the normal case here, not an edge case.  An
    average precision that walks the sorted list without grouping ties is optimistic when
    positives happen to precede negatives inside a tie group and pessimistic otherwise.
    """
    from sica.metrics import pr_auc

    rng = np.random.default_rng(0)
    y = np.array([1, 0, 1, 0, 0, 1, 0, 0, 0, 0])
    s = np.array([0.4] * 10)                      # one single tie group
    reference = pr_auc(y, s)
    for _ in range(25):
        idx = rng.permutation(len(y))
        assert pr_auc(y[idx], s[idx]) == pytest.approx(reference), (
            "PR AUC changed under a permutation of equally-scored samples")


def test_pr_auc_matches_known_values():
    """Closed-form cases: all scores tied gives the prevalence; separable gives 1.0."""
    from sica.metrics import pr_auc

    assert pr_auc([1, 0, 1, 0], [0.5, 0.5, 0.5, 0.5]) == pytest.approx(0.5)
    assert pr_auc([1, 0, 0, 0], [0.5, 0.5, 0.5, 0.5]) == pytest.approx(0.25)
    assert pr_auc([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9]) == pytest.approx(1.0)
    # A partially tied case computed by hand: the tie group at 0.5 holds one positive and
    # one negative, so it contributes precision 2/3 at recall 1.0.
    assert pr_auc([1, 1, 0], [0.9, 0.5, 0.5]) == pytest.approx(1.0 * 0.5 + 0.5 * (2 / 3))


def test_roc_auc_matches_known_values():
    """Tie handling in ROC AUC re-verified alongside, as a regression guard."""
    from sica.metrics import roc_auc

    assert roc_auc([0, 0, 1, 1], [0.0, 0.1, 0.9, 1.0]) == pytest.approx(1.0)
    assert roc_auc([1, 0, 1, 0], [0.5, 0.5, 0.5, 0.5]) == pytest.approx(0.5)
    # One positive above a tie, one inside it: 0.5*(1.0) + 0.5*(0.5) = 0.75.
    assert roc_auc([1, 1, 0], [0.9, 0.5, 0.5]) == pytest.approx(0.75)


def test_pin_ip_is_not_perfect_by_construction(sessions):
    """Address pinning must not attain recall 1.0 on the reported envelope by definition."""
    from sica.baselines import pinning_predictions

    res = sica.run_experiment(sessions, sica.ExperimentConfig(seed=5))
    ev = res["sessions"]
    y = np.array([s.label for s in ev])
    pred = pinning_predictions(ev, "pin_ip")
    recall = float(pred[y == 1].mean())
    assert y.sum() > 20, "too few attack sessions to make the claim"
    assert recall < 1.0, (
        "pin_ip attains perfect recall: every attack in the reported envelope carries an "
        "address change, so the benchmark measures address change rather than hijacking")
