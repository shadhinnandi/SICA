# Experiments

Every experiment writes CSVs to `results/tables/` and JSON to
`results/metadata/`. Nothing is reported that is not in one of those files, and
`pipeline/make_tables.py` generates the manuscript's tables and inline numbers
directly from them, so no number in the paper is typed by hand.

Run everything with `./run_all.sh`. Individual commands are given below.

**Shared configuration.** The executable source of truth is `pipeline/common.py`
(with `sica/invariants.py`, `sica/monitor.py`, `sica/inject.py`, `sica/churn.py`
and `sica/calibrate.py` for component defaults). `config.yaml` is a **descriptive
mirror that no code loads**; if the two disagree, the code is correct.
Methodological authority rests with `docs/EXPERIMENT_CONTRACT.md`.

Budget `α = 0.01`; 1800 s idle timeout; sessions of ≥7 requests; 20% of
evaluation sessions targeted; `attack_fraction = 0.40` (concurrent mode only);
benign monotone mobility 0.15 and flapping 0.05; temporal calibration/evaluation
split at 50%; retained invariants `v1, v2, v3`.

**Workloads.** W1 (primary) `data/raw/apache_sample_1.log` — Apache combined log,
human web browsing. W2 (secondary) `data/raw/nginx_real.log` — **Elastic Nginx
demo/sample corpus**, not production traffic and not a real package mirror: three
placeholder URL paths, 65.8% 404s, ~0% referrer coverage. It is retained because
it is adversarial to the method. Both are public sample logs from the Elastic
Examples repository (Apache-2.0), verified byte-identical to upstream.

**Seeds.** Reporting: 0–29 (E1 main, E2 baselines); **0–14 (E1b budget sweep,
implemented as `SEEDS[:15]`)**; 0–19 (E3, E4, E5). E6 uses no seed — it is a
deterministic replay. Development: 100–119. The reporting and development blocks
are disjoint, and `pipeline/validate.py` asserts it.

**Two limitations bind every experiment below.** (i) The source logs carry a
degenerate minute field, so no sessionised session exceeds 59 seconds and all
inter-arrival times are generator artefacts: **no claim about realistic temporal
behaviour may be made, and detection latency in *seconds* is not reportable.**
Latency in attacker *requests* is unaffected, as is the computational latency of
E6. The retained invariants read no timestamp, gap or duration, so the detector
itself is unaffected. (ii) W2 is demo data (above). See
`docs/DATASET_VERIFICATION.md` §6.

---

## Metric definitions

All metrics are **session-level** unless stated otherwise: an operator responds
to a session, not to an individual request.

| Metric | Definition |
|---|---|
| Recall (TPR) | TP / (TP + FN) — share of hijacked sessions alerted |
| FAR (FPR) | FP / (FP + TN) — share of benign sessions alerted |
| Precision | TP / (TP + FP), **at the benchmark's prevalence** |
| F₁ | harmonic mean of precision and recall |
| Specificity | TN / (TN + FP) |
| Balanced accuracy | (recall + specificity) / 2 |
| ROC AUC | rank statistic over session peak risk, ties handled by mid-rank |
| PR AUC | average precision over session peak risk, **tie groups collapsed to one operating point** |
| Attack-request detection rate | share of *injected requests* whose own risk crosses τ |
| Detection latency | number of attacker **requests** observed before the first alert |
| Calibration alarm rate | share of *calibration* sessions that would alert at τ |

**Ranking metrics apply only to continuous scores.** A pinning baseline is a
parameter-free binary rule: it has one operating point and no ranking curve, and
its ROC AUC collapses identically to `(TPR + TNR)/2` — balanced accuracy. Ranking
metrics are therefore **withheld (`NaN`) for every pinning rule**, which carry
recall, FPR, precision, F₁ and balanced accuracy instead. No continuous score is
invented for them. Each baseline row records `score_resolution ∈ {binary,
continuous}` so the distinction survives into every generated table, and
`validate.py` asserts both halves.

**Detection latency is a request count, never a clock reading.**
`latency_seconds_median` is still computed but is **not reportable** on this
corpus (degenerate timestamps), and is marked as such in `sica/metrics.py`. It
must never be presented alongside, or confused with, the *computational* latency
measured in E6 — those are different quantities in different units.

Accuracy is never reported: at 20% prevalence, and far more so at deployment
prevalence, it is dominated by the negative class.

**Uncertainty.** The detector is deterministic given a request stream, so
reported variance comes from the benchmark draw and the calibration split, not
from model initialisation. Intervals are percentile bootstrap (10,000 resamples,
seed 0) over the per-seed values. Paired comparisons use the Wilcoxon
signed-rank test over paired draws with Holm correction within each family.

---

## E0 — Corpus audit

**Purpose.** Establish what the source logs actually contain and justify the
sessionisation parameters.

```bash
python3 pipeline/exp01_corpus.py
```

| Output | Contents |
|---|---|
| `e0_corpus.csv` | per workload: requests, addresses, `/16`s, agents, agent cores, referrer coverage, span, sessions, session-length distribution |
| `e0_sessionisation_sensitivity.csv` | session yield across idle ∈ {900, 1800, 3600} s × min length ∈ {5, 7, 10, 15} |
| `e0_agent_mix.csv` | agent-family composition per workload |

Detector-independent; nothing here depends on SICA.

---

## E1 — Main evaluation and budget sweep

**Purpose.** Detection at the frozen, label-free operating point, and the
recall/false-alarm trade-off as the operator's budget is varied.

```bash
python3 pipeline/exp02_main.py
```

**Protocol per seed.** Split → benign churn (both partitions) → inject attacks
(evaluation only) → calibrate on the calibration partition alone → freeze weights
and τ → replay evaluation → read labels.

| Output | Contents |
|---|---|
| `e1_main_runs.csv` | one row per (workload, seed): all metrics, τ, partition sizes, realised prevalence |
| `e1_main_summary.csv` | mean, SD and bootstrap 95% CI per workload |
| `e1_per_scenario.csv` | recall etc. broken out by injected scenario |
| `e1_false_alarms_by_benign_class.csv` | every false alarm attributed to the benign phenomenon that caused it |
| `e1_calibration_runs.csv`, `e1_calibration_summary.csv` | per-invariant benign firing rate ε, applicability π, derived weights, τ, calibration alarm rate |
| `e1_alpha_sweep.csv`, `e1_alpha_sweep_runs.csv` | α ∈ {0.001 … 0.10}, 15 seeds |

---

## E2 — Baseline comparison

**Purpose.** Answer the project's central comparative question: *does SICA
provide useful detection beyond pinning a session to an IP address?*

```bash
python3 pipeline/exp02_main.py     # E2 runs in the same script as E1
```

Baselines run on **identical sessions from identical draws**, with the same
sessionisation and the same information.

*Pinning rules* (parameter-free, so reported at whatever false-alarm rate the
traffic produces — this is the operational point of the comparison, not an
unfairness): `pin_ip`, `pin_prefix24`, `pin_scope16`, `pin_useragent`,
`pin_useragent_core`, `pin_ip_or_useragent`, `pin_ip_and_useragent`.

*Scored rules* (calibrated to the **same** budget by the **same** quantile
procedure on the **same** attack-free calibration partition):
`score_distinct_bindings`, `score_max_request_rate`, `score_burstiness`.

`pin_useragent_core` uses exactly the agent core that `v1` uses, so the
comparison measures the rule and not the parser.

| Output | Contents |
|---|---|
| `e2_baseline_runs.csv` | per (workload, seed, detector) |
| `e2_baselines.csv` | aggregated with CIs |

Per-adversary baseline results are in E4 (`e4_scenario_baselines.csv`), which is
where the comparison becomes informative: it shows *which adversary defeats which
defence*, rather than only which defence has the larger average.

---

## E3 — Ablation and restoration

**Purpose.** Establish that each retained invariant earns its place, and keep the
rejection of the two discarded invariants auditable.

```bash
python3 pipeline/exp03_ablation.py
```

Each ablation is **separately and fully calibrated**, so the comparison is
between two independently configured detectors rather than a detector and a
de-tuned copy of itself.

| Family | Variants |
|---|---|
| `reference` | the full retained method |
| `leave_one_out` | each of `v1, v2, v3` removed |
| `restored` | `+v4`, `+v5`, `+v6` added back one at a time, and all three together |
| `single` | each invariant alone |
| `weighting` | uniform weights instead of benign-rarity |
| `design` | reference migration off; decayed evidence accumulator instead of peak |

| Output | Contents |
|---|---|
| `e3_ablation_runs.csv`, `e3_ablation.csv` | per variant, with weights |

---

## E4 — Robustness

**Purpose.** Determine where the method works and where it fails, and remove the
dependence of the headline on unverifiable assumptions.

```bash
python3 pipeline/exp04_robustness.py     # the longest stage, ~43 min measured
```

**E4a — adversary grid.** Every cell of masquerade level **`L0`–`L5`** ×
{takeover, concurrent}, evaluated in isolation, for SICA *and* every baseline —
24 cells (6 levels × 2 modes × 2 workloads).

`L0`–`L3` are the *address-visible* levels: the attacker's address differs from
the victim's, so any rule that alerts on an address change detects all of them by
construction. `L4` and `L5` are *co-located*: the attacker presents the victim's
own address. `L4` also clones the agent and is therefore invisible to every
binding-based signal — the acknowledged blind spot, reported rather than
excluded. `L5` is the co-located attacker on a different client program: no
address signal at all, but agent continuity breaks.

Both co-located levels are part of the reported envelope, not an appendix.
Restricting the envelope to `L0`–`L3` would give address pinning perfect recall
by construction and reduce the benchmark to address-change detection.

**E4b — assumption sweeps.** Each swept factor is an assumption the benchmark
makes, not a measurement:

| Factor | Values |
|---|---|
| `flapping_rate` | 0, 0.01, 0.02, 0.05, 0.10, 0.20 |
| `monotone_rate` | 0, 0.05, 0.15, 0.30, 0.50 |
| `attack_fraction` | 0.05, 0.10, 0.20, 0.40, 0.60 |
| `attack_rate` (prevalence) | 0.02, 0.05, 0.10, 0.20, 0.35 |
| `theft_position` | 0.10–0.20, 0.25–0.50, 0.50–0.70, 0.70–0.85 |
| `theft_delay_s` | 0, 1, 60, 600 — **inert; see below** |
| `min_requests` (session length) | 7, 10, 15, 20 |

**`theft_delay_s` is an inert condition on this corpus and is reported as such.**
No session exceeds 59 seconds, so a 60 s or 600 s delay is not expressible. In
concurrent mode the delay is clamped inside the victim's remaining window so the
scenario stays concurrent; in takeover mode the victim is already silent and no
retained invariant reads a timestamp. The measured result is identical across all
four levels on W1 and differs only in the fourth decimal on W2 (timestamp
tie-ordering at exactly zero delay). It is retained so that its inertness is
itself a generated, checkable result, and it must **not** be presented as evidence
of robustness to attacker timing.

**E4c — address-churn crossover.** SICA and every baseline as benign monotone
mobility grows from 0 to 0.35. This locates the mobility rate at which address
pinning stops being preferable, which is the quantity an operator needs in order
to choose between them.

| Output | Contents |
|---|---|
| `e4_scenario_grid.csv`, `e4_scenario_grid_runs.csv` | SICA per adversary cell |
| `e4_scenario_baselines.csv`, `e4_scenario_baselines_runs.csv` | every detector per cell |
| `e4_sweeps.csv`, `e4_sweep_runs.csv` | the assumption sweeps |
| `e4_crossover.csv`, `e4_crossover_runs.csv` | the crossover analysis |

---

## E5 — Leakage audit

**Purpose.** Demonstrate that the constructed benchmark does not contain the
shortcut it was designed to avoid.

```bash
python3 pipeline/exp05_leakage.py
```

**E5a — marginal-feature audit.** ROC AUC of each per-session summary feature
alone against the injected label: request count, duration, total and mean bytes,
distinct paths, median and minimum inter-arrival gap, error rate. Chance is 0.5.

**E5b — content-reference detector.** A deterministic Mahalanobis one-class score
over all eight of those features, fitted on the attack-free calibration split and
thresholded at the same budget. Reported **for context only**; it is not part of
SICA, which uses no learned component. It shows what a feature-based detector
obtains on this benchmark.

**E5c — split sensitivity.** The same experiment under temporal, client-disjoint
and random splits. Agreement shows that neither client identity nor time ordering
carries the result.

**E5d — structural checks.** Mechanical assertions with an explicit verdict each:
session-id uniqueness, calibration/evaluation disjointness, attack-freeness of the
calibration partition, length matching of injected sessions, client isolation
under the client-disjoint split, development/reporting seed disjointness, and
that the retained invariant set reads no timing or volume feature.

| Output | Contents |
|---|---|
| `e5_marginal_audit.csv` | per-feature AUC with CIs |
| `e5_content_reference.csv` | the reference detector's metrics |
| `e5_split_sensitivity.csv` | the three splits |
| `results/metadata/leakage_report.json` | machine-readable, pass/fail per check |

---

## E6 — Efficiency

**Purpose.** Measure the "lightweight" claim instead of asserting it.

```bash
python3 pipeline/exp06_efficiency.py
```

What is timed is `ContinuityMonitor.observe` on an already-parsed request
stream — the work a server does in the request path. Log parsing and
sessionisation are offline benchmark preparation and are timed **separately** in
`e6_preparation_cost.csv`, neither folded in nor omitted.

* **Throughput** from an *uninstrumented* loop: a `perf_counter` pair around
  every call costs a measurable fraction of a ~14 µs operation and would be
  charged to the detector.
* **Latency percentiles** from a separate instrumented pass, whose absolute
  values therefore include the timer overhead they measure. Both are reported.
* **Scaling**: the same measurement at 5%, 10%, 25%, 50% and 100% of the
  workload's sessions. Flat per-request cost across that range is the observable
  consequence of the O(1) design — and is the check the previous version of this
  project failed, having reported a "benchmark" whose total time did not grow
  with input size at all.
* **Memory**: recursive resident size of the per-session state, alongside the
  analytic design bound.

2 warm-up runs, 7 timed repetitions, median aggregation, GC disabled inside timed
loops. Environment (Python version, implementation, platform, library versions)
is captured in `results/metadata/e6_environment.json`.

| Output | Contents |
|---|---|
| `e6_efficiency.csv` | throughput, latency percentiles, state size per workload |
| `e6_scaling.csv` | the same across live-session counts |
| `e6_preparation_cost.csv` | offline parse and sessionisation cost |

---

## E7 — Statistics and base rates

**Purpose.** Establish that reported differences are stable across draws, and
translate benchmark precision into deployment terms.

```bash
python3 pipeline/exp07_stats.py
```

Paired Wilcoxon signed-rank tests of SICA against every baseline and of the full
method against every ablation, Holm-corrected within each family, reported with
the median paired difference as effect size — because a p-value over 30 paired
draws says a difference is stable, not that it matters.

Base-rate analysis recomputes precision and alert volume from the measured TPR
and FPR across prevalences 10⁻⁵ … 0.2.

| Output | Contents |
|---|---|
| `e7_baseline_tests.csv` | SICA vs each baseline |
| `e7_ablation_tests_*.csv` | full vs each ablation family |
| `e7_base_rate.csv` | precision and alerts per million sessions |

---

## Figures and tables

```bash
python3 pipeline/make_tables.py     # paper/tables/*.tex, including numbers.tex
python3 pipeline/exp08_figures.py   # results/figures/*.pdf and *.png
```

| Figure | Content |
|---|---|
| `fig1_architecture` | processing path and the calibration path |
| `fig2_mechanism` | monotone mobility vs interleaved fork |
| `fig3_envelope` | recall by adversary capability |
| `fig4_operating` | SICA's budget curve against the baseline points |
| `fig5_crossover` | when address pinning stops being viable |
| `fig6_ablation` | ΔF₁ per removed invariant |

---

## Development studies (not part of the reported results)

These fixed the design choices, on the **disjoint** seed block 100–119. They are
included so the choices are auditable.

```bash
python3 pipeline/dev_design.py       # evidence rule, reference migration, budget
python3 pipeline/dev_invariants.py   # which invariants are retained
```

| Output | Decision it settled |
|---|---|
| `dev_design.csv` | peak evidence over a decayed accumulator; reference migration on |
| `dev_invariants.csv` | retain `v1, v2, v3`; drop `v4`, `v5`, `v6` (criterion: development-seed ROC AUC, agreeing on both workloads) |

---

## Validation

```bash
python3 pipeline/validate.py
```

Asserts that every expected artefact exists, that the leakage report contains no
failed check, that no module under `sica/` imports a machine-learning library,
that the reporting seeds are 0–29, that the ablation covers both the retained and
the rejected invariants, and that the headline numbers are in plausible ranges.
It additionally asserts that the adversary grid covers **all 24 cells including
the co-located levels**, that `pin_ip` recall is **not** 1.0 (i.e. the envelope is
not trivially separable by an address rule), that **no binary baseline carries a
ranking AUC** while all carry their operating-point metrics, that **every run met
its declared false-alarm budget on calibration**, and that every generated macro
the manuscript references is defined. Exits non-zero on any failure, so
`run_all.sh` cannot mark a broken run complete.

**Current status: 70 checks passed, 0 failed** (`results/logs/validate.log`).

### Current output inventory

| Location | Contents |
|---|---|
| `results/tables/` | **39 CSVs** — the 27 contracted tables plus 12 per-run (`*_runs.csv`) tables |
| `results/metadata/` | 3 JSON, including `leakage_report.json` (26 checks passed, 0 failed) |
| `results/figures/` | 6 figures as PDF **and** PNG (12 files) |
| `paper/tables/` | 12 `.tex`, including `numbers.tex` (94 generated macros) |
| `results/logs/` | one log per stage, plus `RUN_ALL.log` at the top level |
| `results/RUN_STATUS.md` | why there is no `PIPELINE_DONE` marker despite a valid run |

The test suite gate inside `run_all.sh` is **50 tests** (24 in
`tests/test_sica.py`, 26 in `tests/test_regressions.py`).
