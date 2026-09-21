# Architecture and Research Audit

**Project.** SICA — Stateful Invariant-based Continuity Analysis for HTTP session-hijack detection.
**Audit date.** 2026-09-12.
**Audit type.** Inspection-only. No experiment was run, no pipeline stage executed, no
existing file modified. The only file created is this one.
**Scope.** The entire repository at `the repository`: source, pipeline, tests,
configuration, generated result artifacts, documentation, paper source, bibliography.

**Method.** Every claim below is either (a) read directly out of a source file, with the
file and the construct named, or (b) computed from an artifact already on disk in
`results/tables/`, with the file named. Nothing is inferred from memory of previous
sessions. Where the evidence on disk does not settle a question, the item is marked
**UNKNOWN** and the specific evidence needed is stated.

**Status of the artifacts this audit reads.** The last pipeline run **did not complete**.
`results/RUN_ALL.log` ends at `== E4c address-churn crossover against baselines` with no
completion line; neither `results/PIPELINE_DONE` nor `results/PIPELINE_ERR` exists; no
process is alive. 24 of 27 expected result tables exist. Missing: `e4_crossover`,
`e7_baseline_tests`, `e7_base_rate`. `results/figures/` and `paper/tables/` are empty.
Result numbers quoted in this audit therefore come from **stages that did complete**
(E0, E1, E2, E3, E4a, E4b, E5, E6), all written after the final invariant lock
(`sica/invariants.py` mtime 12:58; `e1_*` written 13:01). They are **provisional**: they
are the output of a run whose validation stage never executed.

---

# PART I — WHAT THE PROJECT CURRENTLY IS

## 1. Research question

As implemented and as written in `paper/paper.tex`: *can intra-session HTTP session
hijacking be detected server-side, at constant cost per request, by checking a small set
of declared continuity invariants against bounded per-session state, without any machine
learning and without any attack-labelled training data?*

The question is operationalised as two measurable sub-questions, both present in the code:
ranking quality (ROC AUC of session peak risk) and the false-alarm cost of achieving it
(realised session-level FPR against a declared budget α).

## 2. Problem definition

Detect, *within a live session*, that requests bearing one session identifier originate
from more than one client, or from a different client than the one that established the
session. The unit of analysis is the request, evaluated statefully; the unit of decision
and of reporting is the session (`sica/metrics.py::evaluate_sessions`).

## 3. Threat model

From `paper/paper.tex` §Threat Model and `CHECKPOINT.md` §1:

* The adversary has obtained a valid, already-authenticated session identifier by a means
  outside the model (XSS, network capture, log leakage, malware).
* The adversary replays it against the same server.
* The defender sees only what a web server logs: address, User-Agent, timestamp, path,
  referrer, status, byte count. No TLS fingerprint, no client-side JS, no token binding.
* Explicitly out of scope: session fixation, credential theft, replay of a *completed*
  transaction, and any attack that does not involve a second party using a live identifier.

## 4. What constitutes session hijacking here

A session is hijacked iff at least one request inside it was issued by a party other than
the session's owner while the identifier was live. The benchmark realises this as
`Request.injected == 1` (`sica/sessionize.py`), and `Session.label == 1` iff any request
in it is injected. Two concurrency regimes are distinguished and are treated as different
phenomena rather than as one:

* **takeover** — the victim falls silent at the theft point; every subsequent request is
  the attacker's.
* **concurrent** — victim and attacker use the identifier at the same time.

This distinction is load-bearing: the mechanism the method claims (§6, V3) can only exist
in the concurrent regime.

## 5. Current SICA architecture

```
access log ──parse──> request table ──sessionize──> sessions
                                                      │
                            ┌──────── split (temporal | client | random)
                            │
                  calibration partition            evaluation partition
                            │                              │
                     benign churn                    benign churn
                            │                              │
                            │                       attack injection
                            │                              │
                   calibrate (2 passes)                    │
                    ├ applicability gate                   │
                    ├ benign-rarity weights                │
                    └ threshold τ at budget α              │
                            │                              │
                            └──── frozen MonitorConfig ────┤
                                                           │
                                            ContinuityMonitor.observe(...)
                                                per request:
                                                  binding_of(ip, ua)
                                                  v_i(request, state) → [0,1]
                                                  risk = Σ w_i · v_i
                                                  state update (O(1))
                                                           │
                                            session peak risk ≥ τ → alert
```

Modules: `fingerprint.py` (binding extraction), `invariants.py` (the v_i),
`monitor.py` (state machine, risk, decision), `calibrate.py` (weights, τ),
`churn.py` (benign mobility), `inject.py` (attack construction),
`sessionize.py` (parsing, grouping), `baselines.py`, `metrics.py`, `harness.py`
(protocol orchestration).

## 6. Every invariant currently implemented

Six are implemented; three are in the locked deployed set. Source: `sica/invariants.py`.
Benign firing mass ε and applicability are measured values from
`results/tables/e1_calibration_summary.csv` (30 seeds, mean).

| | Name | Signal | Grading | ε (W1) | ε (W2) | app (W1) | app (W2) | Status |
|---|---|---|---|---|---|---|---|---|
| V1 | `agent_mutation` | client software identity vs pinned | 1.0 core change, 0.35 version-only | 0.0020 | **0.0000** | 0.959 | 1.000 | **retained** |
| V2 | `scope_discontinuity` | network location vs pinned | 1.0 new /16, 0.45 new /24, 0.15 new host | 0.0088 | 0.0096 | 1.000 | 1.000 | **retained** |
| V3 | `binding_fork` | binding *revisit* (interleaving) | 1.0 | 0.0192 | 0.0205 | 1.000 | 1.000 | **retained** |
| V4 | `transition_velocity` | scope change faster than it can settle | ramp over `t_settle`=300 s | 0.0046 | 0.0047 | 1.000 | 1.000 | rejected |
| V5 | `rate_discontinuity` | cadence break vs session's own EWMA gap | ramp | 0.190 | 0.127 | 0.855 | 0.841 | rejected |
| V6 | `navigation_break` | in-site referrer to an unvisited page | 1.0 | 0.344 | 0.000 | 0.653 | **0.000** | rejected |

Resulting weights (`w ∝ log(1/(ε+0.01))`, measured): W1 — V1 0.368, V2 0.332, V3 0.300;
W2 — V1 0.383, V2 0.327, V3 0.290. I recomputed these from the recorded ε and they match
the declared formula exactly; the weighting implementation is correct.

## 7. Why each invariant exists

* **V1** — a browser does not change family/OS/device class mid-session; a major-version
  change is possible in principle but does not preserve in-memory session state, hence
  graded weak rather than zero.
* **V2** — a session identifier is a bearer token; presentation from a different
  administrative network than the one that obtained it is the canonical observable of
  replay. The three-level grading is what separates it from address pinning: a rule that
  treats a host change like a /16 change inherits the false-alarm rate of the commonest
  event.
* **V3** — the discriminating invariant. Legitimate roaming is *monotone* (A A A B B B);
  a live concurrent hijack necessarily produces a *revisit* (A A B A B) because the victim
  keeps browsing. A revisit has no single-client explanation; a forward transition has
  several.
* **V4** — rejected: in a log without geolocation it fires on the same event V2 already
  reports, double-counting one piece of evidence.
* **V5** — rejected: fires on 12–19% of benign requests (measured ε above) because real
  page loads are bursty, while the attacker's timing in this benchmark *is* a real
  client's timing, so the benchmark cannot credit it with signal it might carry against a
  scripted adversary.
* **V6** — rejected: applicability 0.000 on W2 (referrer coverage 0.00025, from
  `e0_corpus.csv`), and on W1 it fires on 34% of benign requests. It is also the only
  invariant requiring a corpus-level parameter (the first-party host set).

All six remain implemented and the ablation restores each rejected one, so the rejections
stay auditable.

## 8. Per-session state

`sica/monitor.py::SessionState` (`slots=True`): pinned `Binding`, `last_key`, `last_ts`,
`n_seen`, `ewma_gap`, a bounded `ring` of distinct binding keys (`ring_size`=4), a bounded
`paths` deque (`path_window`=32) with a parallel `path_set` membership index,
`accumulator`, `peak_risk`, `evidence_peak`, `alerted_at`. Analytic design bound
`nbytes()` = 2000 B/session. Measured resident cost (`e6_efficiency.csv`): 4767 B/session
(W1), 3366 B/session (W2) — i.e. the **measured** cost exceeds the declared design bound
by ~1.7–2.4×, which is consistent with Python object overhead but means the two numbers
must not be presented as bound-and-confirmation.

## 9. Request-level processing flow

`ContinuityMonitor.observe`: build binding → on first sight, pin and return a zero record
(`established=True`) → otherwise compute `dt`, `changed_binding`, `is_revisit`
(`key in ring`), `changed_scope` → evaluate **only the enabled** invariants (the ablation
switch reaches the hot path, so disabled invariants cost nothing) → `risk = Σ w_i v_i` →
evidence = risk (`evidence="max"`) or decayed accumulator → bounded state update, including
reference migration on a monotone change only → record peak, set `alerted_at` on first
crossing. Time and space per request are O(1).

## 10. Sessionization

`sica/sessionize.py`. Combined/JSON log parse; group by `(remote address, User-Agent)`;
cut on idle gap > `IDLE_SECONDS`=1800 s; discard sessions with < `MIN_REQUESTS`=7 requests.
The grouping key is **ground truth only** — it defines which requests genuinely belong to
one client. The detector sees only `session_id`. Corpus outcome (`e0_corpus.csv`):

| | source | requests parsed | sessions | requests in sessions | median len | referrer coverage | span |
|---|---|---|---|---|---|---|---|
| W1_web | `apache_sample_1.log` | 10,000 | 254 | 3,874 | 9 | 0.593 | 3.46 d |
| W2_apt | `nginx_real.log` | 51,462 | 3,126 | 43,307 | 12 | 0.00025 | 17.96 d |

## 11. Attack injection

`sica/inject.py`. Attacker requests are **real requests taken verbatim from a different
real client of the same server**; only the binding is substituted. Length-matched: an
injected session has exactly the victim's original request count. Masquerade levels L0
(donor address + donor agent, different /16) → L1 (donor address, cloned agent) → L2
(synthetic address in victim's /16, different /24; donor agent) → L3 (synthetic address in
victim's /24; cloned agent) → L4 (victim's own address, cloned agent — the shared-NAT case,
reported separately and excluded from the headline mixture). Modes: takeover, concurrent.
Attacker cadence is the donor's own real inter-arrival gaps, compressed in concurrent mode
so the attacker's activity fits inside the victim's remaining window.

## 12. Calibration

`sica/calibrate.py`. Two passes over attack-free calibration traffic and no more.
Pass 1 replays with unit weights over **all six** invariants to obtain benign firing mass
ε_i and applicability; invariants below `APPLICABILITY_FLOOR`=0.01 are disabled and their
weight redistributed; weights `w_i ∝ log(1/(ε_i + 0.01))`. Pass 2 replays with those
weights through **the same evidence pipeline evaluation uses**, and τ is the (1−α) quantile
of session peak risk over that pass. Labels are read nowhere in this module; asserted by
`tests/test_sica.py::test_calibration_ignores_labels_entirely`, which relabels the entire
calibration partition adversarially and requires weights and τ to be unchanged.

## 13. Detection / evidence aggregation

Per request, `risk = Σ_i w_i · v_i ∈ [0,1]`. Session evidence is the **peak** per-request
risk (locked choice; the decayed accumulator is implemented and was rejected on development
seeds). A session alerts iff its peak evidence ≥ τ. Every alert carries the invariants that
fired and their degrees (`rec["explanation"]`).

## 14. Threshold selection

`threshold_for_budget(peaks, alpha)` = `np.quantile(values, 1−α, method="higher")`, with the
alert rule `evidence >= τ`. **This does not achieve its stated guarantee** — see finding
**C1**. Measured: calibration alarm rate 2.15% (W1) / 1.85% (W2) against α = 1.0%, i.e. the
budget is missed *on the very sample the quantile was computed from*. τ is also strongly
seed-dependent (W1 0.354–0.646, W2 0.428–0.623 across 30 seeds), so the operating point,
and hence every threshold-dependent metric, carries variance that is not detection variance.

## 15. Baselines

`sica/baselines.py`. Pinning (parameter-free, session-level, retrospective): `pin_ip`,
`pin_prefix24`, `pin_scope16`, `pin_useragent`, `pin_useragent_core`,
`pin_ip_or_useragent`, `pin_ip_and_useragent`. Scored (calibrated to the same budget by the
same procedure on the same partition): `score_distinct_bindings`, `score_max_request_rate`,
`score_burstiness`. `pin_useragent_core` reads exactly the agent core V1 reads, via a shared
`_ua_core()` helper. Measured (`e2_baselines.csv`, 30 seeds):

| workload | detector | recall | FPR | F1 | ROC AUC |
|---|---|---|---|---|---|
| W1 | **SICA** | 0.567 | **0.019** | 0.674 | **0.965** |
| W1 | `pin_ip` | **1.000** | 0.147 | **0.732** | 0.926 |
| W1 | `pin_prefix24` | 0.784 | 0.072 | 0.732 | 0.856 |
| W2 | **SICA** | 0.428 | **0.018** | 0.566 | **0.960** |
| W2 | `pin_ip` | **1.000** | 0.150 | **0.762** | 0.925 |
| W2 | `pin_prefix24` | 0.758 | 0.074 | 0.733 | 0.842 |

This is the single most consequential fact in the current result set. See **C2**.

## 16. Dataset sources

Two real access logs shipped in `data/raw/`: `apache_sample_1.log` (W1, human web
browsing, Apache combined) and `nginx_real.log` (W2, package-manager clients, Nginx).
Both are unauthenticated public traffic; session identity is *reconstructed*, not observed.
Provenance and redistribution status are documented in `DATASET.md` and
`CITATION_OF_INPUTS.txt`.

## 17. Real vs synthetic / injected data

* **Real and unmodified:** every request's path, status, byte count, referrer, and the
  inter-arrival structure of benign traffic.
* **Constructed:** the session labels; benign binding churn (`churn.py`); attacker
  bindings; attacker placement and, in concurrent mode, attacker gap scaling.
* **Synthetic values:** only the L2/L3 attacker addresses, and churned addresses/agents.
No request *content* anywhere in the benchmark is synthetic.

## 18. Leakage risks

Audited in `pipeline/exp05_leakage.py`; `results/metadata/leakage_report.json` records
**26 structural checks, 26 passed, 0 failed** (session-id uniqueness, calibration/evaluation
disjointness, calibration attack-freeness, length matching, client-disjoint isolation,
dev/reporting seed disjointness, and "the final invariant set consumes no timing or volume
feature"). Split sensitivity (`e5_split_sensitivity.csv`) shows ROC AUC 0.962–0.967 (W1)
and 0.960–0.962 (W2) across temporal / client-disjoint / random splits — no split-induced
leakage. **However**, the marginal audit finds a real residual shortcut on W2:
`distinct_paths` reaches ROC AUC **0.732**, and the ML-free Mahalanobis content-reference
detector reaches **0.731**. See **H4**.

## 19. Class imbalance

`ATTACK_RATE`=0.20 of evaluation sessions targeted; realised prevalence is reported rather
than assumed (`inject_corpus`/`inject_mixture` return it). Measured attack sessions per run:
21.4 of ~2,900 evaluated (W1), 302.9 of ~34,000 (W2). Because 20% is far above any
plausible deployment prevalence, `exp07_stats.py` is designed to report precision at
realistic base rates — **that stage has not run**, so the base-rate analysis does not
currently exist.

## 20. Evaluation methodology

30 reporting seeds (0–29) for E1/E2; 20 (0–19) for E3/E4/E5; development seeds 100–119,
disjoint and asserted. Per seed: split → churn both partitions → inject evaluation only →
calibrate on calibration only → replay evaluation under frozen τ → compute metrics.
Reported: precision, recall, F1, FPR, specificity, balanced accuracy, ROC AUC, PR AUC,
attacker-request detection rate, detection latency (requests and seconds), plus per-scenario
and per-benign-class breakdowns. Aggregation: mean, SD, and percentile bootstrap 95% CI
(10,000 resamples, seed 0).

## 21. Reproducibility

`run_all.sh` runs preflight → tests → E1…E7 → tables → figures → `validate.py`, writing
`results/PIPELINE_DONE` only on complete success and `results/PIPELINE_ERR` naming a failed
stage. `pipeline/validate.py` asserts artifact existence, zero failed leakage checks, no
decisive marginal feature, that `sica/` imports no ML library, that reporting seeds are
exactly 0–29, that the adversary grid has all 20 cells, that the ablation covers retained
and rejected invariants, and that generated table bodies match their LaTeX column counts.
`REPRODUCIBILITY.md` documents setup, seeds, determinism and troubleshooting. Weaknesses:
no resume (**M5**), non-deterministic session identifiers (**M1**), and cross-process
determinism untested (**M7**).

## 22. Computational complexity

Claimed and implemented O(1) time and space per request; the two constructs that would have
broken it (rebuilding a path set per request; evaluating disabled invariants) were fixed and
the fixes are visible in `monitor.py`. Measured (`e6_efficiency.csv`): 71,987 req/s (W1) and
67,300 req/s (W2) uninstrumented; median instrumented latency 12.3 µs / 13.0 µs; p99 42 µs.
`e6_scaling.csv` (10 rows) exercises growing live-session counts to test flatness.

## 23. Privacy / security assumptions

Server-side only; no client cooperation, no JS, no TLS fingerprint, no cookie/token
rewriting. Inputs are IP addresses and User-Agent strings — personal data under most
regimes; the logs are public archival traffic from 2015 and are redistributed as such.
The detector stores only bounded derived state, never request bodies or credentials.
Deployment-side response policy (terminate / step-up / log) is explicitly out of scope.

## 24. Existing tests

`tests/test_sica.py`: **23 tests**, covering fingerprinting, invariant grading, reference
migration, fork-vs-move discrimination, state boundedness, rarity weighting, applicability
gating, label-free calibration (adversarial relabelling), length-matched injection, real
takeover, genuine concurrent interleaving, determinism, churn scoping, and AUC edge cases.
`tests/conftest.py` and `pytest.ini` make them runnable from any directory.
**Latest result: UNKNOWN.** The root `.pytest_cache` dates to 11:32, *before*
`tests/test_sica.py` was last edited at 12:28, and its `lastfailed` entry still names
`test_sica.py`. No artifact on disk records a run of the final code.

## 25. Existing experiment scripts

`exp01_corpus`, `exp02_main` (E1 main + budget sweep, E2 baselines), `exp03_ablation`,
`exp04_robustness` (E4a grid, E4b sweeps, E4c crossover), `exp05_leakage`,
`exp06_efficiency`, `exp07_stats`, `exp08_figures`, `make_tables`, `validate`, plus the two
development studies `dev_design` and `dev_invariants`.

## 26. Existing result artifacts

24 of 27 expected tables present. **Missing: `e4_crossover.csv`, `e7_baseline_tests.csv`,
`e7_base_rate.csv`.** `results/figures/` empty (0 of 6). `paper/tables/` empty (0 of 12).
`results/metadata/` has `leakage_report.json`, `e6_environment.json`,
`e0_sessionisation.json`. Development-study tables (`dev_design*`, `dev_invariants*`) present.

## 27. Existing documentation

`README.md` (18 KB), `DATASET.md` (16 KB), `EXPERIMENTS.md` (13 KB),
`REPRODUCIBILITY.md` (8.6 KB), `CHECKPOINT.md` (7.5 KB), `AUDIT.md` (11 KB).
**`RESEARCH_RECORD.md` does not exist.** `AUDIT.md` §R4 is stale (**I1**).

## 28. Existing paper source

`paper/paper.tex`, 48 KB, IEEEtran, 27 sections/subsections, 10 tables, 6 figures,
`paper/IEEEtran.cls` vendored. Structure: Introduction · Threat Model · Method (bindings,
invariants, three rejected, reference migration, risk and calibration, complexity) ·
Benchmark Construction · Evaluation (setup, leakage, main, envelope, false alarms, baseline
comparison, base rates, ablation, robustness, efficiency) · Discussion and Limitations ·
Conclusion. **Cannot currently compile**: every `\input{tables/…}` target is missing.
No PDF, no build log, never compiled with real data. Written to an 8–9 page target; the
new target is 10–12 (**I3**).

## 29. Existing bibliography

`paper/ref.bib`, 24 entries, 21 with DOIs, spanning session-security (Calzavara, Sivakorn,
RFC 6265/8471/9449, OWASP), fingerprinting (Eckersley, Laperdrix, Vastel, Unger), risk-based
authentication (Freeman, Wiefling), NIST zero trust, network-behaviour context (Padmanabhan,
Richter CGN, Poese), and evaluation methodology (Axelsson base rate, Sommer & Paxson, Arp
*Dos and Don'ts*, Rossow *Prudent Practices*, alert fatigue, web-log sessionisation).
Entries were previously verified against Crossref. No verification was re-run today.

---

# PART II — FINDINGS

Each finding gives: exact problem · why it is scientifically wrong · files · code area ·
proposed correction · how it will be tested · whether it changes methodology · whether it
risks invalidating previous results.

---

## CRITICAL

### C1 — The operating threshold does not meet its declared false-alarm budget, on its own calibration sample

**Exact problem.** `threshold_for_budget` returns `np.quantile(values, 1−α, method="higher")`
and the monitor alerts on `evidence >= τ`. The risk statistic is coarse-valued: with three
invariants and fixed severities it takes a small number of distinct values, so the (1−α)
quantile lands on a large plateau of tied values, *all* of which then alert. Measured
calibration alarm rate is **2.15% (W1) and 1.85% (W2) against α = 1.00%**
(`e1_calibration_summary.csv`, columns `calibration_alarm_rate_mean`). The docstring says
"smallest threshold meeting a session-level false-alarm budget `alpha`". It does not.

**Why it is scientifically wrong.** The budget is the paper's central operational claim —
it is what distinguishes a calibrated detector from a pinning rule. A budget that is missed
by 85–115% *in-sample*, before any generalisation question arises, is not a budget; it is a
mislabelled quantile. Every threshold-dependent number in the study (recall, precision, F1,
FPR, per-scenario recall, per-benign-class FPR, all baseline comparisons at "equal budget")
is reported at an operating point that is not the one declared. The same defect also
propagates into the *baselines*, which are calibrated with the identical function, so the
"compared at an equal false-alarm budget" claim is doubly wrong: neither side is at α.

**Files affected.** `sica/calibrate.py` (primary); `sica/harness.py::run_baselines` (uses
the same function); `tests/test_sica.py`.

**Code area.** `threshold_for_budget()`, lines 92–99 of `sica/calibrate.py`.

**Proposed correction.** Keep the definition, fix the implementation: select the smallest
value τ among the observed peaks such that the *realised* in-sample alarm rate
`mean(peaks >= τ) ≤ α`; if no such observed value exists, return
`nextafter(max(peaks), +inf)` (alert nothing) and record that the budget is unattainable at
this granularity. Record the achieved in-sample rate in `info` (the field
`calibration_alarm_rate` already exists) and have `validate.py` assert it is ≤ α.

**How it will be tested.** A new test on a deliberately tied sample — e.g. peaks drawn from
`{0.0, 0.29, 0.33, 0.44, 0.62}` with heavy repetition — asserting
`(peaks >= tau).mean() <= alpha` for α ∈ {0.001, 0.01, 0.05}. The existing test (**M4**)
must be kept *and* extended, not replaced. Plus an end-to-end assertion in `validate.py`
that every run's `calibration_alarm_rate ≤ ALPHA`.

**Changes methodology?** **No.** The declared definition is unchanged; only its
implementation is corrected to match.

**Risks invalidating previous results?** **Yes, partially and predictably.** All
threshold-dependent metrics change: recall will fall, FPR will fall toward ≤1%, F1 will
move. All **threshold-free** metrics — ROC AUC, PR AUC — are unaffected. Critically, the
**invariant-set lock is not at risk**, because that selection was made on ROC AUC, a
threshold-free criterion, on development seeds. This is the single strongest argument for
the lock surviving the fix.

---

### C2 — The evaluated attack envelope guarantees that address pinning achieves perfect recall

**Exact problem.** The headline mixture is levels L0–L3 (`ExperimentConfig.levels = LEVELS`,
which excludes L4). Every one of L0–L3 gives the attacker a network address **different
from the victim's**: L0/L1 use the donor's address, L2 a synthetic address in a different
/24, L3 a synthetic address in the victim's /24 but a different host. Therefore *every*
attack session in the headline mixture contains an address change, and the rule "alert on
any address change" detects **all** of them by construction. This is exactly what is
measured: `pin_ip` recall = **1.0000** on both workloads (`e2_baselines.csv`), with F1
**0.732 / 0.762** against SICA's **0.674 / 0.566**.

**Why it is scientifically wrong.** Two distinct problems. (i) The recall axis of the
baseline comparison carries no information: it is a property of how the benchmark was built,
not of the detectors. (ii) The strongest naive baseline beats the proposed method on the
aggregate metric a reviewer looks at first, on both workloads, and the paper's contribution
therefore rests entirely on the FPR axis (1.9% vs 14.7%) and on ranking quality
(0.965 vs 0.926). That is a defensible and interesting claim — an order of magnitude fewer
false alarms at comparable or better ranking — but it is *not* the claim that "SICA detects
hijacking better", and any framing that implies the latter is unsupported by the project's
own numbers.

**Files affected.** `sica/harness.py` (`ExperimentConfig.levels`), `pipeline/exp02_main.py`,
`paper/paper.tex` (§Comparison with deployed rules, §Main result, abstract and contributions).

**Code area.** The default level mixture, and every table/claim that compares SICA to
pinning on recall or F1.

**Proposed correction.** No code change is *required* for correctness, and none should be
made to improve a number. Required changes are to reporting: (a) state explicitly and
prominently that L0–L3 all involve an address change, so `pin_ip` recall = 1.0 is
constructional; (b) lead the comparison with FPR at matched recall, or recall at matched
FPR, rather than with F1; (c) report a secondary mixture **including L4** — where `pin_ip`
recall necessarily drops — as the honest envelope, since L4 is the one cell that separates
"detects a different address" from "detects a hijack"; (d) if a single headline number is
needed, use ROC AUC, which is the only metric here not determined by the construction.

**How it will be tested.** An assertion in `pipeline/validate.py` that
`pin_ip` recall == 1.0 on the L0–L3 mixture (turning the artifact into a checked, declared
property rather than an accidental finding), and a per-level recall table for `pin_ip`
showing where it falls to 0 (L4).

**Changes methodology?** Reporting yes; detector and benchmark construction no. Adding an
L4-inclusive secondary mixture is an additive reporting change, not a redesign.

**Risks invalidating previous results?** No existing number becomes wrong. The *interpretation*
of the baseline table changes substantially.

---

## HIGH

### H1 — Masquerade level is computed from the victim's pre-churn address

**Exact problem.** `inject_session` derives the attacker's address from
`victim.client[0]` — the session's *original* ground-truth address — for L2, L3 and L4, and
derives `victim_scope` from it for the L0/L1 donor-admissibility check. But churn is applied
to the evaluation partition **before** injection (`harness.py::run_experiment` calls
`apply_churn(ev, …)` then `inject_mixture(ev, …)`), and `apply_churn` rewrites the addresses
of requests after its change point while leaving `Session.client` untouched. When the theft
point falls after a churn point in an address-changing churn class, the victim's *live*
binding is no longer `victim.client[0]`.

**Why it is scientifically wrong.** The masquerade levels are the paper's independent
variable — the detectability envelope is the claim that detection degrades monotonically as
the attacker reproduces more of the victim's binding. If L3's "synthetic address in the
victim's /24" is in fact in a *different* /24 or /16 from the victim's live address, that
cell is more detectable than its definition states, and the envelope is measured against a
mislabelled axis. The bias is in the favourable direction for the proposed method.
Affected population: ~20% of sessions receive address-changing churn, of which the theft
point falls after the churn point in some fraction — order 5–10% of injected sessions,
concentrated in exactly the hardest cells.

**Files affected.** `sica/inject.py`, `sica/harness.py`.

**Code area.** `inject_session()` lines 120, 177–181 (`victim_scope`, `_synthetic_ip(victim.client[0], …)`,
L4's `atk_ip = victim.client[0]`).

**Proposed correction.** Derive the attacker's binding from the victim's **live binding at
the theft point** — `victim.requests[cut].ip` and `victim.requests[cut].ua` — rather than
from `Session.client`. This makes each level mean what it says regardless of churn.

**How it will be tested.** A new property test: construct a victim with a forced cross-/16
churn before the theft point, inject at L3, and assert
`ip_prefix24(attacker_ip) == ip_prefix24(victim.requests[cut].ip)`; likewise assert L2 shares
the /16 but not the /24, and L4 shares the full address. Run over many seeds and both
workloads.

**Changes methodology?** It corrects the benchmark to match its stated definition. The
definition does not change.

**Risks invalidating previous results?** **Yes** — per-level results (E1 per-scenario, the
whole E4a adversary grid, the detectability-envelope figure and section) must be regenerated.
Aggregate headline numbers will shift slightly.

---

### H2 — Benign agent churn is a no-op on W2, and measurably so

**Exact problem.** `churn.py::_bump_version` increments the first match of
`\b(chrome|firefox|version|edg|opr|safari)/(\d+)`; if there is no match it appends
`" Build/2"`. W2 is 91.96% `AptHTTP` agents (`e0_agent_mix.csv`), which match none of those
tokens. For those sessions the appended suffix changes the raw UA string but leaves
`parse_user_agent` output — browser, **version**, OS, device — completely unchanged.
Confirmed by measurement: **ε(V1) = 0.00000 on W2** (`e1_calibration_summary.csv`), with
1,898 sessions labelled `M2_agent_update` producing **zero** V1 firings and zero false
alarms (`e1_false_alarms_by_benign_class.csv`).

**Why it is scientifically wrong.** Three consequences. (i) 1,898 W2 sessions are labelled
as carrying a benign agent change that does not exist, so the negative class is
mischaracterised in the published breakdown. (ii) V1's benign cost on W2 is understated —
it is reported as exactly zero when the phenomenon it is supposed to cost against never
occurred. (iii) It produces a spurious cross-workload asymmetry: `M3_combined:scope` has
30.3% FPR on W1 but **0.0%** on W2, and the entire difference is that on W1 the agent half
of M3 fires V1 (adding ~0.13 to the risk, enough to cross τ) while on W2 it cannot. Any
discussion of "why the workloads differ" that does not name this is attributing a parser
artifact to traffic. Direction of bias: favourable to SICA on W2, and unfavourable to the
exact-string `pin_useragent` baseline, which *does* see the meaningless suffix change and is
charged a false alarm for it.

**Files affected.** `sica/churn.py`; consequentially `sica/fingerprint.py` (the version-token
table), `DATASET.md`, `paper/paper.tex` (§Where the false alarms come from).

**Code area.** `_VER` regex and `_bump_version()`, lines 44 and 98–103.

**Proposed correction.** Make `_bump_version` version-aware for every browser family the
fingerprinter can parse — reuse `fingerprint._major_version`'s key table as the single source
of truth so the churn model and the parser cannot diverge — and, when no version is
advertised at all, either skip M2/M3's agent half for that session (and record it) or select
a genuinely different agent core. Do **not** silently append a token the parser ignores.

**How it will be tested.** A test asserting that for every agent family in
`fingerprint._BROWSERS` that advertises a version, `binding_of(ip, _bump_version(ua)).version
!= binding_of(ip, ua).version`; and a corpus-level assertion that M2-churned sessions produce
a non-zero V1 firing rate on **both** workloads.

**Changes methodology?** It repairs the benign-churn model to do what it is documented to do.
The model's *rates* are unchanged.

**Risks invalidating previous results?** **Yes.** ε(V1) on W2 will become non-zero, which
changes the weights, which changes τ, which changes every W2 operating-point number. W2's
false-alarm breakdown changes materially. AUCs will move slightly.

---

### H3 — PR AUC ignores tied scores while ROC AUC handles them

**Exact problem.** `metrics.roc_auc` implements explicit mid-rank tie correction.
`metrics.pr_auc` does not: it sorts by `-score` with a stable sort and walks the list, so
among tied scores the result depends on the order sessions happen to appear in the input
list. The risk statistic is coarse and heavily tied (that is the same property that causes
**C1**), so ties are the normal case, not an edge case.

**Why it is scientifically wrong.** A reported metric must be a function of the data, not of
an incidental list order. As implemented, PR AUC is optimistic when positives happen to
precede negatives within a tie group and pessimistic otherwise, and the direction is
arbitrary per seed. PR AUC is reported for every run, every baseline and every ablation cell.

**Files affected.** `sica/metrics.py`; every table carrying `pr_auc`.

**Code area.** `pr_auc()` lines 65–78, and `_auc_inputs()`.

**Proposed correction.** Compute average precision over **tie groups**: accumulate TP and FP
per distinct score value and evaluate precision/recall once per group, so all samples sharing
a score are treated as one decision point.

**How it will be tested.** A test asserting PR AUC is invariant to input permutation on a
tied sample (`y = [1,0,1,0]`, `s = [0.5]*4`), and that it equals the analytically correct
value there (0.5); plus a regression check that the untied case is unchanged.

**Changes methodology?** No — it corrects a metric implementation to its standard definition.

**Risks invalidating previous results?** All reported PR AUC values change slightly.
ROC AUC, recall, precision, F1, FPR are unaffected.

---

### H4 — The benchmark's "no feature-based detector can separate the classes" claim is contradicted by the project's own measurement

**Exact problem.** `sica/inject.py`'s module docstring states that because attacker requests
are real requests from a real client, "no classifier of per-request features can separate the
classes". `results/tables/e5_marginal_audit.csv` measures `distinct_paths` at ROC AUC
**0.7323** (CI 0.7278–0.7369) on W2, and `e5_content_reference.csv` measures the ML-free
Mahalanobis content-reference detector at ROC AUC **0.7314** on W2. Additionally,
`validate.py`'s guard is `abs(auc − 0.5) < 0.30`, a tolerance wide enough to pass 0.732 —
so the automated check does not flag it.

**Why it is scientifically wrong.** The claim as written is falsified by the project's own
data. The underlying cause is real and explainable — an apt client's donor traffic fetches a
different set of package paths, so injected W2 sessions carry more distinct paths — but it
means the benchmark does contain a content shortcut worth ~0.73 AUC on W2. The defensible
claim is narrower and is already supported: the *retained invariants read no path, timing,
volume or byte feature* (a PASSing structural check), so this shortcut cannot reach SICA,
and SICA's 0.960 is far above the 0.731 a content detector achieves. Overclaiming where the
narrow claim suffices is the kind of thing that loses a paper its credibility on one line.

**Files affected.** `sica/inject.py` (docstring), `DATASET.md`, `paper/paper.tex`
(§Does the benchmark leak?), `pipeline/validate.py` (tolerance).

**Code area.** Module docstring lines 1–13; `validate.py` marginal-feature check.

**Proposed correction.** Replace the absolute claim with the measured one, stating the
0.73 figure, its cause, and why it cannot reach the detector. Tighten `validate.py` to assert
the measured value against a *declared* bound rather than a loose one, and add an explicit
check that no retained invariant reads a leaking feature (that check already exists in the
leakage report — surface it in `validate.py` too). Optionally, and only if the cost is
acceptable, reduce the shortcut by matching donors on distinct-path count — but this is a
benchmark change and must be decided deliberately, not to improve a number.

**How it will be tested.** `validate.py` asserts the marginal maximum against a declared
threshold and fails if it rises; the leakage report already records the per-feature values.

**Changes methodology?** The wording fix does not. Donor path-matching would — it is
therefore **not** recommended as part of the repair, only as a declared option.

**Risks invalidating previous results?** The wording fix invalidates nothing. Donor matching
would require a full re-run.

---

### H5 — ROC AUC is tabulated for binary pinning rules alongside a ranking detector's AUC

**Exact problem.** `harness.run_baselines` computes `roc_auc(y, pred.astype(float))` for
pinning rules, whose predictions are in {0,1}. For a binary predictor ROC AUC reduces
exactly to balanced accuracy, `(TPR+TNR)/2` — a point statistic, not a ranking quality. It is
then reported in the same `roc_auc` column as SICA's AUC over a continuous risk score
(`e2_baselines.csv`).

**Why it is scientifically wrong.** The two quantities are not the same measure and are not
comparable as "how well does it rank". SICA's 0.965 vs `pin_ip`'s 0.926 reads as a ranking
comparison and is not one; `pin_ip`'s "AUC" is just `(1.000 + 0.853)/2`. A reviewer who
notices will treat the whole table as careless, and the claim most at stake (**C2**) depends
on this table being read correctly.

**Files affected.** `sica/harness.py`, `pipeline/exp02_main.py`, `pipeline/make_tables.py`,
`paper/paper.tex` (baselines table).

**Code area.** `run_baselines()` lines 199–205.

**Proposed correction.** Report balanced accuracy for binary rules under its own name, leave
the `roc_auc` cell empty (or marked "n/a — binary rule") for them, and add a footnote stating
that a parameter-free binary rule has no ranking curve. Keep AUC for the scored baselines,
which do produce continuous scores.

**How it will be tested.** `validate.py` asserts that any row with `family == "pinning"` has
a null `roc_auc` and a populated `balanced_accuracy`.

**Changes methodology?** No. It renames and re-scopes a reported quantity.

**Risks invalidating previous results?** No number changes; one column is relabelled and one
is withdrawn.

---

## MEDIUM

### M1 — Session identifiers embed Python's salted `hash()`

`sessionize.py` builds `session_id = f"{ip}|{hash(ua) & 0xffffff}|{local}"`. `hash()` on a
`str` is randomised per process unless `PYTHONHASHSEED` is fixed, so session identifiers
differ between runs, and uniqueness over 24 bits is probabilistic rather than guaranteed.
A collision would silently merge two sessions' state in the monitor. Empirically the ids were
unique in the runs that were checked (254/254 and 3126/3126, per `leakage_report.json`), but
that is an observation, not a guarantee, and `REPRODUCIBILITY.md` §8 claims bit-identical
reproduction. **Fix:** use a deterministic digest (`blake2s(ua.encode()).hexdigest()[:8]`).
**Tested by:** asserting identical session ids across two subprocesses with different
`PYTHONHASHSEED`, and asserting global id uniqueness on both corpora.
**Methodology:** unchanged. **Invalidates:** nothing — ids are opaque to the detector, and
the splits do not order by id (verified: temporal sorts by timestamp, client/random permute
indices).

### M2 — The takeover theft point silently ignores its configured window for long sessions

In takeover mode `k = min(n − cut − 1, donor.n, max_attacker_requests)` and then
`cut = n − k − 1`. When the 40-request cap or the donor's length binds, `cut` is forced to
`n − k − 1` regardless of `earliest_takeover`/`latest_takeover`. For sessions longer than
~80 requests the configured window has no effect, so E4's `theft_position` sweep is partially
inert for takeover. **Magnitude: UNKNOWN** — see U2. **Fix:** clamp `k` to the window rather
than re-deriving `cut` past it, and skip sessions where the window and the cap are
incompatible, recording how often that happens. **Tested by:** asserting the realised theft
fraction lies inside `[earliest, latest]` for every produced takeover session.
**Methodology:** restores the declared construction. **Invalidates:** E4's theft-position
sweep rows, and slightly, any takeover cell on long sessions.

### M3 — The invariant-selection criterion as documented is not exactly the rule that was applied

`invariants.py` and `CHECKPOINT.md` describe the criterion as threshold-free ROC AUC on
development seeds, "required to agree across both workloads". On the development data
(`dev_invariants.csv`) the retained set `V1_V2_V3` **is** the W1 argmax (0.9613), but on W2
the argmax is `V1_V2_V3_V4_V6` at 0.9608 versus 0.9589 for `V1_V2_V3` — a 0.0019 difference
with overlapping CIs, while that same candidate is clearly worse on W1 (0.9409, CI
non-overlapping). So the rule actually applied was "best on one workload and statistically
tied on the other", which is a reasonable cross-workload consistency rule but is not
"argmax". **This does not justify changing the lock** — `V1_V2_V3` satisfies the consistency
rule and no competitor dominates it on both workloads. **Fix:** state the applied rule
precisely, publish the dev table, and note the tie. **Tested by:** nothing to test; this is a
documentation correction. **Methodology:** unchanged. **Invalidates:** nothing.

*Related and worth recording:* `V1_V2` (dropping the fork invariant) has **higher F1 on both
workloads** on development seeds (W1 0.705 vs 0.649; W2 0.694 vs 0.539) while having lower
AUC. V3 is retained because the pre-declared criterion is AUC. Because **C1** shows the
operating point is itself mis-set, the F1 comparison is currently being made at the wrong
threshold — so the magnitude of V3's F1 cost should be re-measured **on development seeds
only** after C1 is fixed. See U4.

### M4 — The threshold test cannot fail on the condition that actually fails

`test_threshold_meets_the_budget_on_its_own_sample` uses `np.linspace(0, 1, 1000)` — 1,000
distinct values, no ties — so it verifies the budget only in the case where plateaus do not
exist. It passes today while the real system misses its budget by a factor of two. **Fix:**
keep it and add the tied-sample case described under C1. **Methodology:** unchanged.
**Invalidates:** nothing.

### M5 — `run_all.sh` cannot resume, and `exp04_robustness` bundles three sub-stages

The script deletes both markers at start and runs strictly serially; a failure two-thirds
through (exactly what happened at E4c) discards nothing already written to CSV but forces a
full ~45-minute re-run, and re-running `exp04_robustness.py` recomputes E4a and E4b even
though their outputs exist. **Fix:** add a `--resume` mode that skips a stage whose declared
outputs are all present and newer than the sources, and split E4 into three stages with their
own logs. **Tested by:** a dry-run assertion that `--resume` on a complete tree executes no
stage. **Methodology:** unchanged. **Invalidates:** nothing.

### M6 — A test mutates the shared module-scoped fixture

`test_churn_is_applied_only_to_benign_sessions` sets `marked[0].label = 1` on a session
object from the module-scoped `sessions` fixture and restores it at the end. Any failure
before the restore leaves the fixture corrupted for subsequent tests, making the suite
order- and failure-dependent. **Fix:** deep-copy the session under test.
**Methodology:** unchanged. **Invalidates:** nothing.

### M7 — Cross-process determinism is untested

`test_run_is_reproducible_from_the_seed` calls `run_experiment` twice inside one process,
which cannot detect the `hash()` issue of **M1** or any other process-scoped nondeterminism.
**Fix:** add a test that runs a short experiment in two subprocesses with different
`PYTHONHASHSEED` and compares the metrics dict. **Methodology:** unchanged.
**Invalidates:** nothing.

---

## LOW

* **L1** — `rate_metrics` returns `precision = 0.0` when `TP+FP == 0` rather than NaN, so a
  seed that raises no alert drags the mean precision down instead of being excluded.
  `sica/metrics.py`.
* **L2** — `_parse_ts` drops the timezone offset (`text.split(" ")[0]`). Harmless while a log
  uses one offset throughout; silently wrong for a log that mixes them. `sica/sessionize.py`.
* **L3** — Combined-format timestamps have 1-second resolution, so many requests tie; the
  merge in `inject_session` is stable, placing victim before attacker within a tie. Affects
  only time-reading invariants, all of which are rejected. `sica/inject.py`.
* **L4** — Dead branch: `if not any(r.injected for r in merged): return None` is unreachable
  because `k ≥ min_attacker_requests = 3`. `sica/inject.py` line 237.
* **L5** — `sessionize()`'s default `min_requests=6` diverges from the pipeline's
  `MIN_REQUESTS=7`. Only the pipeline value is ever used for reported results, but the
  divergent default is a trap for anyone calling the library directly — and
  `tests/test_sica.py` passes `min_requests=7` explicitly, which is what keeps them aligned.

---

## INFO

* **I1** — `AUDIT.md` §R4 is titled "Two invariants were harmful and were removed" and
  discusses only V4 and V5. Three were rejected; V6 was dropped in a later round. The file
  contradicts `CHECKPOINT.md` §2 and `invariants.py`.
* **I2** — `RESEARCH_RECORD.md` does not exist.
* **I3** — `paper/paper.tex` is written to an 8–9 page target; the stated new target is 10–12
  pages. Not a defect; a scope note for later.
* **I4** — No git repository exists (`.git` absent); no `CITATION.cff`; `__pycache__/` ×3 and
  `.pytest_cache/` ×2 present on disk (all gitignored).
* **I5** — W1 yields only 254 sessions from 10,000 requests; its confidence intervals are
  correspondingly wide, and it should never carry a claim on its own.
* **I6** — Measured per-session state (4,767 B W1 / 3,366 B W2) exceeds the analytic design
  bound (2,000 B) by 1.7–2.4×. Both are reported, but they must not be presented as
  bound-and-confirmation; the design bound counts payload, the measurement counts Python
  object overhead.

---

## UNKNOWN — evidence required before these can be settled

* **U1** — Does takeover-mode injection inflate session duration? In takeover mode the
  attacker's timeline uses the donor's raw gaps with **no** compression (the window-fitting
  logic applies only to concurrent mode), so an injected takeover session can end later than
  the victim's original last request. Aggregate `duration_s` marginal AUC is ~0.49 (chance),
  but that is over the whole mixture. **Evidence needed:** the marginal audit stratified by
  scenario, specifically `duration_s` and `total_bytes` AUC within `*_takeover` cells only.
* **U2** — How often does **M2** actually bind? **Evidence needed:** a count, over both
  corpora, of takeover injections where `max_attacker_requests` or `donor.n` forced `cut`
  outside `[earliest_takeover·n, latest_takeover·n]`.
* **U3** — Does the current test suite pass on the current code? The only on-disk record
  predates the final edits and names `test_sica.py` as failed. **Evidence needed:** one
  `pytest -q` run (seconds, not an experiment).
* **U4** — Does fixing **C1** change V3's cost/benefit? V3 is retained on AUC and costs
  substantial F1; the F1 measurement was taken at a mis-set operating point. **Evidence
  needed:** re-run `dev_invariants.py` on **development seeds 100–119 only** after C1 is
  fixed, and compare. This must not touch reporting seeds, and must not be used to change the
  lock unless it reveals a correctness problem rather than a preference.
* **U5** — Are the 24 bibliography entries still resolvable? They were verified against
  Crossref in an earlier session; no verification was run today.

---

# PART III — REQUIRED SUMMARY SECTIONS

## A. Current architecture summary

A stateful, non-learning, per-request continuity monitor. Each request is reduced to a
*binding* (address, /24, /16, browser, version, OS, device class). Three locked invariants
score the binding against bounded per-session state: V1 agent mutation, V2 network-scope
discontinuity, V3 binding fork (interleaving). Each returns a graded violation in [0,1];
their weighted sum is the request's risk; the session's evidence is its peak risk. Weights
come from benign rarity on attack-free calibration traffic; the threshold is a quantile of
calibration session peak risk at a declared budget. A *reference migration* policy re-pins
the binding after a monotone transition but never after a revisit, which is what converts
"the binding changed" into "the bindings are interleaved" — the mechanism the method rests
on. Work is O(1) per request in time and space; measured throughput ~67–72k req/s. No
machine learning appears anywhere, enforced mechanically.

## B. Current data flow

```
data/raw/*.log
  → parse_log()                     real requests, sorted by time
  → sessionize()                    group by (address, UA) [ground truth only];
                                    idle 1800 s; drop < 7 requests
  → split_sessions()                temporal 50/50 (client / random as controls)
        ├── calibration partition ──→ apply_churn()  [benign mobility]
        │                        └──→ calibrate()    [ε → weights → τ]  ⟹ frozen config
        └── evaluation partition ──→ apply_churn()   [benign mobility]
                                 └──→ inject_mixture()  [L0–L3 × {takeover, concurrent}]
                                        → ContinuityMonitor replay under frozen config
                                        → per-request records (v_i, risk, applicability)
                                        → session peak risk ≥ τ → alert
                                        → metrics (labels read here for the first time)
```

Labels enter at exactly one point: metric computation, after every decision exists.

## C. Current experiment flow

`run_all.sh`: preflight (Python ≥3.10, modules, input logs) → `pytest` → E0 corpus →
E1 main + budget sweep and E2 baselines → E3 ablation and restoration → E5 leakage audit →
E6 efficiency → E4 robustness (E4a adversary grid, E4b assumption sweeps, E4c address-churn
crossover) → E7 statistics and base rates → `make_tables` → `exp08_figures` → `validate` →
write `results/PIPELINE_DONE`. Any non-zero exit writes `results/PIPELINE_ERR` naming the
stage and stops. Reporting seeds 0–29 (E1/E2) and 0–19 (E3/E4/E5); development seeds 100–119
used only by `dev_design.py` and `dev_invariants.py`, which are not part of the default run.

**Current state: stopped inside E4c; E7, tables, figures and validation never ran.**

## D. All critical and high problems

| ID | Severity | Problem | Invalidates prior results? |
|---|---|---|---|
| **C1** | CRITICAL | Threshold misses its declared budget on its own calibration sample (2.15% / 1.85% vs α=1%) | Yes — all threshold-dependent metrics; **not** AUC/PR-AUC, **not** the invariant lock |
| **C2** | CRITICAL | L0–L3 envelope guarantees `pin_ip` recall = 1.000; strongest naive baseline beats SICA on F1 on both workloads | No numbers wrong; the interpretation and framing must change |
| **H1** | HIGH | Masquerade level derived from pre-churn address, so L2/L3/L4 can be mislabelled | Yes — per-level results and the whole E4a grid |
| **H2** | HIGH | `_bump_version` cannot bump AptHTTP versions; M2/M3 agent churn is a measured no-op on W2 (ε(V1)=0.00000) | Yes — all W2 operating-point numbers and the false-alarm breakdown |
| **H3** | HIGH | PR AUC has no tie correction while ROC AUC does; risk is heavily tied | Yes — all PR-AUC values only |
| **H4** | HIGH | "No feature-based detector can separate the classes" contradicted by own E5 (0.732 AUC on W2) | No — wording and validator tolerance |
| **H5** | HIGH | ROC AUC tabulated for binary pinning rules, where it is balanced accuracy | No — one column relabelled/withdrawn |

## E. Recommended fixes

**Tier 1 — correctness, must be fixed before any reported run.**
1. **C1** — implement the budget as declared (smallest τ with in-sample alarm rate ≤ α);
   assert it in `validate.py`; add the tied-sample test.
2. **H1** — derive attacker bindings from the victim's live binding at the theft point.
3. **H2** — make the churn model's version bump consistent with the fingerprint parser.
4. **H3** — tie-correct `pr_auc`.
5. **M1** — deterministic session identifiers.
6. **M2** — respect the theft-position window; count and report exclusions.

**Tier 2 — reporting validity, must be fixed before the paper.**
7. **C2** — reframe the baseline comparison around FPR and ranking; state the
   constructional recall fact; add an L4-inclusive secondary mixture.
8. **H5** — balanced accuracy for binary rules; withdraw their AUC.
9. **H4** — replace the absolute leakage claim with the measured one; tighten the validator.
10. **M3** — document the selection rule that was actually applied, with the dev table and
    the W2 tie.

**Tier 3 — hygiene, before release.**
11. **M4**, **M6**, **M7** test repairs; **M5** resume support; **L1–L5**; **I1** (AUDIT.md
    R4), **I2** (`RESEARCH_RECORD.md`), **I4** (git, `CITATION.cff`, cache cleanup).

**Explicitly not recommended:** changing `DEFAULT_INVARIANTS`; matching donors on
distinct-path count to suppress H4's shortcut; any change whose justification is that a
number improves.

## F. Files that must change

| File | Findings |
|---|---|
| `sica/calibrate.py` | C1 |
| `sica/inject.py` | H1, H4 (docstring), L3, L4 |
| `sica/churn.py` | H2 |
| `sica/metrics.py` | H3, L1 |
| `sica/sessionize.py` | M1, L2, L5 |
| `sica/harness.py` | H1 (live-binding plumbing), H5 |
| `pipeline/validate.py` | C1, C2, H4, H5 assertions |
| `pipeline/exp02_main.py`, `pipeline/make_tables.py` | H5, C2 reporting |
| `tests/test_sica.py` | C1, H1, H2, H3, M4, M6, M7 |
| `run_all.sh` | M5 |
| `AUDIT.md` | I1 |
| `RESEARCH_RECORD.md` | I2 (create) |
| `paper/paper.tex` | C2, H4, H5, M3, I3 — **after** results exist, not before |

## G. Files that should NOT change

* `sica/invariants.py` — `DEFAULT_INVARIANTS` is locked. The audit found **no correctness
  problem** in the three retained invariants or in their selection; M3 is a documentation
  defect, not a selection defect. The selection criterion was threshold-free, so C1 does not
  reach it.
* `sica/fingerprint.py` — correct as written; the binding key deliberately carries the full
  address, and the core/version split is what makes V1's grading meaningful. (H2 *reads*
  its version-key table; it does not change it.)
* `sica/monitor.py` — the hot path, the O(1) claims, reference migration and the bounded
  state are all correct and were previously repaired. Do not touch.
* `sica/baselines.py` — the rules themselves are fair; `_ua_core` already guarantees the
  baseline sees exactly what V1 sees. Only how their AUC is *reported* changes (H5).
* `data/raw/*` — inputs, never modified.
* `CHECKPOINT.md` §§1–7 — the lock. Changing it requires the §9 change-control procedure.
* Everything under `results/` from the incomplete run — preserved as evidence, superseded
  only by a complete run.

## H. What is already correct

* The threat model, the unit of analysis, and the separation of takeover from concurrent.
* The monitor's state machine: O(1) time and space, bounded ring and path window with an
  incremental membership index, ablation switch reaching the hot path, reference migration
  charging a monotone move exactly once.
* The benign-rarity weighting — I recomputed the published weights from the published ε and
  they match `w ∝ log(1/(ε+0.01))` exactly on both workloads.
* The applicability gate — V6 is correctly gated off on W2 (applicability 0.000, referrer
  coverage 0.00025) rather than being awarded maximum weight for never firing, which is
  precisely the failure mode it exists to prevent.
* Label-free calibration, verified adversarially: relabelling the entire calibration
  partition changes neither weights nor threshold.
* Calibration and evaluation use the *same* evidence pipeline (the two-pass design) — the
  defect that invalidated the earlier version is genuinely fixed.
* Attack construction from real donor traffic with exact length matching — no request-count
  or content artifact of the kind that ruined the old Dataset A. Verified by the structural
  checks and by `n_requests` marginal AUC ≈ 0.52.
* Benign churn exists at all three address granularities including intra-/24, so pinning
  baselines do pay a realistic false-alarm cost (`pin_ip` FPR 14.7% / 15.0%).
* Dev/reporting seed disjointness, asserted mechanically.
* Split insensitivity: temporal, client-disjoint and random all give ROC AUC within 0.005.
* The 26 structural leakage checks, all passing.
* `run_all.sh`'s fail-fast design with `PIPESTATUS` and single-marker semantics, and
  `validate.py`'s breadth (including the LaTeX column-count check).
* Documentation depth: `DATASET.md`, `EXPERIMENTS.md`, `REPRODUCIBILITY.md` and
  `CHECKPOINT.md` are genuinely self-contained and honest about limitations.

## I. What must be frozen before experiments

Frozen now, not to be reopened without the `CHECKPOINT.md` §9 procedure:

1. **The invariant set** — `(V1_agent_mutation, V2_scope_discontinuity, V3_binding_fork)`.
2. **Invariant severities** — `InvariantParams` as declared.
3. **The calibration protocol** — applicability gate at 1%, `w ∝ log(1/(ε+0.01))`, peak-risk
   evidence, threshold at budget α = 0.01. *The budget's **implementation** is repaired under
   C1; its **definition** is frozen.*
4. **Reference migration on**; evidence = peak.
5. **Corpora, sessionisation** (1800 s idle, ≥7 requests), and the `(address, UA)` ground-truth
   grouping.
6. **Attack construction semantics** — real donor content, exact length matching, levels
   L0–L4 with their stated definitions, takeover/concurrent modes. *H1 and M2 repair the
   implementation to match these definitions; the definitions themselves are frozen.*
7. **Benign churn model and rates** — 0.15 monotone / 0.05 flapping, host 0.50 / subnet 0.30 /
   scope 0.20. *H2 repairs the agent-bump implementation; the rates are frozen.*
8. **Seeds** — reporting 0–29 and 0–19; development 100–119; bootstrap seed 0, 10,000 resamples.
9. **The experiment suite** — E0–E7 and no more. No experiment may be added to improve a
   number.
10. **The baseline set.**

Freeze **after** Tier-1 fixes land and the tests pass, and not before: fixing C1, H1, H2, H3,
M1 and M2 changes generated numbers, so any run before them is throwaway.

## J. Exact next step for PART 2

**Part 2 = Tier-1 correctness repair and verification. No experiments, no paper.**

In this order:

1. Run `pytest -q` once and record the result — this settles **U3** and establishes the
   baseline the repairs must not break. (Seconds; not an experiment.)
2. Write the *failing* tests first, one per Tier-1 finding: tied-sample budget (C1), live-binding
   masquerade levels (H1), version-bump/parser consistency (H2), permutation-invariant PR AUC
   (H3), cross-process identifier determinism (M1/M7), theft-position window (M2). Confirm each
   fails against the current code. This is what prevents the "mixed correct and unverified
   changes" failure mode.
3. Apply the six Tier-1 fixes, one finding per commit, running the suite after each. No fix
   may be bundled with another, and no fix may touch `sica/invariants.py`,
   `sica/monitor.py` or `sica/fingerprint.py`.
4. Settle **U1** and **U2** with two short read-only diagnostics (per-scenario marginal audit
   of `duration_s`; a count of window-violating takeover injections). If U1 shows takeover
   duration inflation, raise a new finding and stop for a decision rather than fixing blind.
5. Run `./run_all.sh --quick` **once** as a smoke test only — explicitly *not* a reporting
   run, and its outputs are not to be quoted.
6. Re-run `dev_invariants.py` on **development seeds only** to settle **U4**, and record the
   result in the audit. Do not change the lock on the basis of it unless it exposes a
   correctness problem.
7. Report back: which fixes landed, which tests now pass, what U1/U2/U4 showed, and a
   proposed freeze declaration.

Only after that freeze is accepted does Part 3 (the full reporting run) begin, and only after
Part 3 validates does Part 4 (the paper) begin.

**STOP. Do not proceed to Part 2 without explicit instruction.**
