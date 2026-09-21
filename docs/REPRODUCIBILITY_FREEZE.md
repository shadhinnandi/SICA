# Reproducibility and Reporting Freeze

**Date.** 2026-09-12. Closes the four issues left open by `docs/ARCHITECTURE_FREEZE.md` §15.10
(M1/M7, M2, M6, H5). Companion to that document, which remains authoritative for the
detector architecture and the invariant lock.

**Test status at freeze: 45 passed, 0 failed** (`pytest -q`). Collected:
`tests/test_sica.py` 24, `tests/test_regressions.py` 21. Progression across the work:
23 (pre-Tier-1) → 36 (Tier-1) → **45** (this pass).

Each of the four issues followed the same discipline: inspect → write the regression test
first → demonstrate the old behaviour → smallest correction → targeted test → full suite.
No experiment was run. The numbers marked *diagnostic* below come from single-seed runs used
only to verify a fix end to end; they are **not** reported results.

---

## 1. Deterministic randomness and hash behaviour

**Identifiers.** Session identifiers are `"{address}|{agent_digest}|{index}"`, where
`agent_digest` is `blake2s(ua, digest_size=6).hexdigest()` — 48 bits, standard library,
deterministic, dependent on nothing outside its input.

**What it replaced.** `hash(ua) & 0xffffff`. CPython salts `str` hashing per process unless
`PYTHONHASHSEED` is pinned, so identifiers differed between runs and between machines. The
old behaviour was demonstrated before the fix: the same session was
`83.149.9.216|8710409|1` under one seed and `83.149.9.216|2298458|1` under another.

**Why it mattered beyond tidiness.** Two sessions colliding onto one identifier would have
their state *merged* inside the monitor and corrupt each other. The 24-bit truncation gave a
birthday collision probability of roughly 1-in-3 across the ~3,100 sessions of W2 — uniqueness
was a property of luck, re-rolled every run. At 48 bits it is below 1e-10 and is now also
asserted directly on both corpora.

**Randomness elsewhere is unchanged and was already deterministic:** every stochastic choice
flows from `numpy.random.default_rng(seed)` — the calibration/evaluation partition, which
sessions churn and how, which sessions are targeted, donor selection, theft point, displaced
requests, and bootstrap resampling. Seeds are unchanged: reporting 0–29 (E1/E2) and 0–19
(E3/E4/E5), development 100–119, bootstrap seed 0 with 10,000 resamples.

**Guarded by:** `test_session_ids_are_deterministic_across_processes` (spawns two
interpreters with `PYTHONHASHSEED=0` and `=12345` and requires byte-identical identifiers),
`test_session_ids_are_unique_on_both_corpora`.

**Residual caveat, unchanged:** bit-identical *per-seed* reproduction still requires the same
NumPy version, because `Generator` stream values are version-dependent for some
distributions. Aggregates across seeds are stable; `results/metadata/e6_environment.json`
records the versions used.

## 2. Experiment condition handling

**Principle now enforced: the theft point is an experimental condition and is never moved.**
It is drawn from `[earliest_takeover, latest_takeover]` and nothing downstream may relocate
it. A requested condition that cannot be realised for a given victim is **refused and
counted**, never silently replaced.

**What it replaced.** In takeover mode the attacker's share was
`k = min(n - cut - 1, donor.n, max_attacker_requests)` followed by `cut = n - k - 1`. When
the 40-request cap bound — every session longer than ~80 requests — the theft point was
re-derived from the cap. Demonstrated before the fix: a requested window of **[0.20, 0.30]**
produced sessions stolen at **0.600**. E4's theft-position sweep was therefore inert for
precisely the sessions it existed to probe.

**The cap is now explicit and mode-scoped.** `max_attacker_requests` bounds the
**concurrent** share only, where the share is a free parameter set by `attack_fraction`. In a
**takeover** the victim falls silent, so the share is *determined* by the theft point
(`k = n - cut - 1`); an independent cap there is a contradiction, and the theft point wins.
The only remaining constraint is real: a donor must be long enough to supply the tail, since
attacker content is never fabricated.

**The effective condition is reported.** `inject_session` accepts a `reasons` dict;
`inject_mixture` and `inject_corpus` return `refusal_reasons`, `refused_per_scenario` and the
`theft_window` actually requested, so a workload whose session lengths cannot supply a window
shows up in the record instead of quietly becoming a different experiment.

Refusal reasons: `session_too_short_for_theft_window`,
`theft_window_leaves_too_little_tail`, `no_admissible_donor`,
`donor_too_short_for_takeover_tail`, `no_attacker_request_survived`.

*Diagnostic — what the correction costs (seed 0, both workloads):*

| | targeted | injected | refusals |
|---|---|---|---|
| W1_web | 20 | 18 | 2 × `theft_window_leaves_too_little_tail` |
| W2_apt | 330 | 322 | 8 × `theft_window_leaves_too_little_tail` |

**Zero** `donor_too_short_for_takeover_tail` refusals: lifting the cap for takeover did not
create a donor-availability problem in practice. All refusals are short sessions, which the
old code also refused.

**Guarded by:** `test_takeover_respects_its_theft_window`, parameterised over three windows
chosen so the required attacker share falls **below** the old cap (0.70–0.80 → ~19–30
requests), **spanning** it (0.58–0.62 → ~37–42), and **above** it (0.20–0.30 → ~69–80). Each
asserts every produced session's realised theft fraction lies inside the requested window,
within a one-request tolerance for the ceil/floor rounding of the window bounds. Plus
`test_takeover_reports_rejections_rather_than_relocating_the_theft`.

## 3. Fixture isolation

`tests/test_sica.py::test_churn_is_applied_only_to_benign_sessions` mutated the
module-scoped `sessions` fixture in place (`marked[0].label = 1`) and restored it on its last
line. Any failure before that line left every subsequent test running against a corrupted
corpus, so results depended on execution order and on whether an unrelated test had already
failed.

**Demonstrated** in an isolated scratch reproduction — a mutate-then-fail test followed by an
integrity check — where the failure propagated and caused a *second, unrelated* test to fail.

**Correction:** the test now deep-copies before mutating, and additionally asserts the copy
retained its label. A new `test_the_session_fixture_is_not_mutated_by_any_test` asserts
fixture integrity — no labels, scenarios or injected flags written through — and is placed
after the mutation-prone tests. Order-independence verified by running the integrity check
*before* the churn test as well as after.

## 4. Metric definitions

| Metric | Definition | Applies to |
|---|---|---|
| recall, FPR, precision, F1, specificity, balanced accuracy | session-level counts under the frozen threshold | every detector and baseline |
| **ROC AUC** | rank-based, **mid-rank tie correction**, over a continuous session score | SICA and the scored baselines only |
| **Average precision (PR AUC)** | tie groups collapsed to one operating point (corrected in Tier-1 H3) | SICA and the scored baselines only |
| attacker-request detection rate, detection latency | request-level, secondary | SICA |

**Binary baselines carry no ranking metric.** A pinning rule emits a decision, not a score:
one operating point, no ranking. Its ROC curve has a single interior point and the area under
it collapses *identically* to `(TPR + TNR)/2` — balanced accuracy. This is asserted, not
argued: `test_binary_rule_auc_is_exactly_balanced_accuracy` checks the equality over 20
random label/prediction pairs.

Treatment chosen: **withhold** ranking metrics for binary rules (`roc_auc` and `pr_auc` are
`NaN`) and let their operating-point metrics carry the comparison. **No continuous score was
invented** — none exists for a parameter-free rule. Every baseline row now carries
`score_resolution ∈ {binary, continuous}` so the distinction survives into every generated
table and cannot be lost by a downstream join.

**Guarded by:** `test_pinning_baselines_report_no_ranking_metrics`, plus two
`pipeline/validate.py` assertions (pinning rows carry no ranking AUC; pinning rows carry
balanced accuracy).

**Downstream.** The LaTeX baselines table already emitted only recall, FPR, precision and F1,
so it was never affected. `pipeline/make_tables.py` did emit `\PinIpAuc*`, `\PinCoreAuc*` and
`\PinTwentyFourAuc*` macros from the pinning rows; those are replaced by `…BalAcc…` macros
under their true name.

## 5. Exact test count and result

```
$ pytest -q
.............................................                            [100%]
45 passed
```

`tests/test_sica.py` 24 · `tests/test_regressions.py` 21. Regression tests added in this
pass (9):

| Test | Guards |
|---|---|
| `test_session_ids_are_deterministic_across_processes` | M1/M7 |
| `test_session_ids_are_unique_on_both_corpora` | M1/M7 |
| `test_takeover_respects_its_theft_window[0.70–0.80]` | M2 — below the old cap |
| `test_takeover_respects_its_theft_window[0.58–0.62]` | M2 — spanning the old cap |
| `test_takeover_respects_its_theft_window[0.20–0.30]` | M2 — above the old cap |
| `test_takeover_reports_rejections_rather_than_relocating_the_theft` | M2 — refusal recorded |
| `test_the_session_fixture_is_not_mutated_by_any_test` | M6 |
| `test_binary_rule_auc_is_exactly_balanced_accuracy` | H5 — the justification |
| `test_pinning_baselines_report_no_ranking_metrics` | H5 — the treatment |

## 6. Known remaining issues

**Blocking the next full run — one item.**

1. **`paper/paper.tex` references `\PinIpAucApt`, which is no longer generated.**
   `validate.py`'s macro check will fail until the paper is updated, **by design** — the
   failure is the mechanism that forces the edit rather than letting a stale claim survive.
   The sentence at `paper.tex:708–711` currently reads: *"in ROC terms address pinning is not
   uniformly dominated: its AUC is `\PinIpAucApt` against SICA's `\aucApt` on W2, essentially
   a tie."* That is exactly the comparison H5 identifies as invalid — a binary rule's
   balanced accuracy set against a ranking AUC and called a tie. It must be rewritten during
   the paper pass, which is out of scope here; `paper/` was not modified.

**Open, non-blocking.**

2. Audit **UNKNOWNs U1, U2, U4, U5** remain open. U2 (how often the theft window was
   overridden) is now moot — the override cannot occur and refusals are counted instead.
   U1 (per-scenario duration inflation in takeover mode, whose attacker timeline is still
   uncompressed), U4 (whether the corrected threshold changes `v3`'s cost/benefit — to be
   settled on **development seeds only**), and U5 (bibliography re-verification) stand.
3. The W2 content shortcut (`distinct_paths`, ≈0.73 marginal AUC) is documented, not
   suppressed. Suppressing it would be a benchmark change made to improve a number.
4. Measured per-session state exceeds the analytic design bound by 1.7–2.4×; both are
   reported.
5. Every pre-fix result remains void. `results/` still holds the artifacts of the abandoned
   run and was deliberately left untouched as evidence.

---

## Read-only audit

Performed after all four corrections; no file was modified during it.

| Check | Result |
|---|---|
| No ML libraries | **PASS** — the only match for `sklearn\|torch\|tensorflow\|keras\|xgboost\|lightgbm\|catboost` across `sica/`, `pipeline/`, `tests/` is the banned-token literal inside `validate.py`'s own check |
| No hidden label use in detector or calibration | **PASS** — `sica/calibrate.py` and `sica/monitor.py` contain no reference to `.label` or `injected`; asserted adversarially by `test_calibration_ignores_labels_entirely` (relabelling the whole calibration partition moves neither weights nor threshold) and by `test_calibration_partition_contains_no_attacks` |
| No reporting/test-seed tuning | **PASS** — `SEEDS = tuple(range(30))` and `DEV_SEEDS = tuple(range(100, 120))` unchanged; no fix consulted a reporting-seed result; α unchanged at 0.01 |
| No hard-coded result numbers | **PASS** — no numeric literal in `sica/` or `pipeline/` encodes a result; every paper number is a generated macro. Numbers quoted in documentation are cited to their source CSV |
| V1/V2/V3 unchanged | **PASS** — `DEFAULT_INVARIANTS == ("V1_agent_mutation", "V2_scope_discontinuity", "V3_binding_fork")`; the three invariant functions and `InvariantParams` are byte-identical to their pre-audit form |
| No accidental modification of results | **PASS** — zero files under `results/` newer than 2026-09-06 |
| No paper modification | **PASS** — zero files under `paper/` newer than 2026-09-06 |
| No deleted historical work | **PASS** — `data/raw/` intact; `results/tables/dev_*.csv` and all 24 experiment CSVs from the abandoned run intact; `AUDIT.md` round-1/round-2 history preserved and corrected in place, never truncated |

**Files modified in this pass:** `sica/sessionize.py`, `sica/inject.py`, `sica/harness.py`,
`pipeline/make_tables.py`, `pipeline/validate.py`, `tests/test_sica.py`,
`tests/test_regressions.py`, and this document. Nothing else.

---

**STOP.** No experiments were run. E4c, exp07, table generation, figure generation and paper
compilation were not run and must not begin without explicit instruction.
