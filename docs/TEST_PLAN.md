# Test Plan — Tier-1 Correction

Converts every CRITICAL and HIGH finding in `docs/ARCHITECTURE_AUDIT.md` into an explicit
regression test wherever a test can express it. Each row states the property to be asserted,
not the implementation, so the test survives a different correction than the one anticipated.

**Baseline.** `pytest -q` on the pre-fix code: **23 passed, 0 failed** (2026-09-12).
This settles audit item **U3**: the suite does pass on the final pre-fix code; the
`lastfailed` entry in `.pytest_cache` predated the last edit to `tests/test_sica.py` and was
stale. Every fix below must leave this suite green and add to it.

**Discipline.** For each finding: write the test → run it → *confirm it fails against the old
behaviour* → apply the minimal fix → run that test → run the whole suite → record. One
finding per step. No unrelated code touched.

---

## Tier-1 regression tests

| # | Finding | Test name | Property asserted | Expected pre-fix |
|---|---|---|---|---|
| 1 | **C1** | `test_threshold_meets_the_budget_under_heavy_ties` | For a coarse, heavily tied peak population and α ∈ {0.001, 0.005, 0.01, 0.02, 0.05}, the alert rule `peak >= τ` yields an in-sample alarm rate ≤ α | **FAIL** (0.03 at α=0.01) |
| 1b | **C1** | `test_threshold_is_the_smallest_meeting_the_budget` | No smaller observed value also meets the budget — τ is minimal, so the budget is not met by over-shooting | FAIL |
| 1c | **C1** | `test_threshold_is_unattainable_when_the_sample_is_too_coarse` | When even the largest observed value alarms on > α of the sample, τ alerts nothing rather than silently exceeding the budget | FAIL |
| 1d | **C1** | `test_calibration_achieves_its_declared_budget_end_to_end` | On real calibration traffic, `info["calibration_alarm_rate"] <= alpha` | **FAIL** (0.0215 vs 0.01) |
| 2 | **C2** | `test_pin_ip_is_not_perfect_by_construction` | Over the *reported* scenario envelope there exists at least one attack scenario in which the attacker's address equals the victim's live address, so `pin_ip` cannot reach recall 1.0 by definition | **FAIL** (L4 excluded; recall 1.000) |
| 2b | **C2** | `test_every_masquerade_level_has_its_declared_address_relation` | L0/L1 differ in /16; L2 shares /16, differs in /24; L3 shares /24, differs in host; L4 shares the full address | FAIL (see H1) |
| 3 | **H1** | `test_masquerade_level_uses_the_post_churn_victim_binding` | With a forced cross-scope churn *before* the theft point, the L2/L3/L4 attacker address bears the declared relation to the victim's binding **at the theft point**, not to its original one | **FAIL** |
| 4 | **H2** | `test_version_bump_is_observable_for_every_parsed_family` | For every agent family the fingerprinter extracts a version from, `_bump_version` produces a binding whose `version` differs | **FAIL** (AptHTTP, Wget, Curl) |
| 4b | **H2** | `test_agent_churn_is_observable_on_the_apt_workload` | On W2-like traffic, M2-churned sessions produce a non-zero V1 firing rate | **FAIL** (ε=0.00000) |
| 5 | **H3** | `test_pr_auc_is_invariant_to_input_order_under_ties` | PR AUC is unchanged by permuting equally-scored samples | **FAIL** |
| 5b | **H3** | `test_pr_auc_matches_known_values` | Closed-form cases: all-tied → prevalence; perfectly separable → 1.0 | FAIL (tied case) |
| 5c | **H3** | `test_roc_auc_matches_known_values` | ROC AUC tie handling re-verified alongside (regression guard, expected to pass) | pass |
| 6 | **H4/H5** | — | Documentation-only; no test. Verified by inspection against `e5_marginal_audit.csv` and `dev_invariants.csv`. | n/a |

**Outcome.** All rows above were written first, confirmed failing against the old behaviour,
and now pass. Suite: **23 → 36 passed, 0 failed.** The 13 new tests live in
`tests/test_regressions.py`; `tests/test_sica.py` was not modified.

## NOT DONE — deferred MEDIUM findings

These were scoped into an earlier draft of this plan but are **not** part of the Tier-1
order the work actually followed, and were **not** implemented. They remain open, and the
freeze records them as open:

| # | Finding | Intended test | Status |
|---|---|---|---|
| 7 | **M1/M7** | `test_session_ids_are_deterministic_across_processes` | **NOT DONE** — session ids still embed the salted `hash()` |
| 8 | **M2** | `test_takeover_respects_its_theft_window` | **NOT DONE** — the theft window is still overridden when the 40-request cap binds |
| 9 | **M6** | fixture-mutation repair in `tests/test_sica.py` | **NOT DONE** |
| 10 | audit **H5** (ROC AUC reported for binary pinning rules) | `validate.py` assertion | **NOT DONE** — reporting-layer change, deferred with the paper work |

Scope discipline: the instruction was a specific six-fix Tier-1 order. Expanding it silently
is the failure mode this process exists to prevent, so these are listed rather than absorbed.

## Out of scope for Tier 1

* Changing `DEFAULT_INVARIANTS` — locked.
* Suppressing the W2 `distinct_paths` shortcut by donor matching (**H4**) — a benchmark
  change, deliberately *not* made; documented instead.
* Any change justified by a number improving.
* E4c, E7, `make_tables`, figures, or any full-pipeline run.

## Recording

Each fix appends a row to the change log in `docs/ARCHITECTURE_FREEZE.md`, with the test
that now guards it and the full-suite count after it landed.
