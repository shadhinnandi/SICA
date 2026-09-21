# Architecture Freeze

**Date.** 2026-09-12. **Supersedes** the informal state recorded in `CHECKPOINT.md` for
every item listed in §16; `CHECKPOINT.md` remains the change-control document.

This records the architecture as frozen after the Tier-1 corrections of
`docs/ARCHITECTURE_AUDIT.md`. Nothing in §16 may change without the `CHECKPOINT.md` §9
procedure. No experiment was run to produce this document: the numbers quoted as
*diagnostics* come from single-seed runs used to verify that each fix works end to end, and
are explicitly **not** reported results.

**Test status at freeze: 36 passed, 0 failed** (`pytest -q`, 2026-09-12), up from 23 before
the corrections. 13 new regression tests, one per CRITICAL/HIGH finding that a test can
express, all confirmed failing against the old behaviour before the corresponding fix.

---

## 1. Final architecture

A stateful, non-learning, per-request session-continuity monitor. Each request is reduced to
a *binding* — the client characteristics a server can attribute to whoever presented the
session identifier. Three invariants score the binding against bounded per-session state,
each returning a graded violation in [0,1]. Their weighted sum is the request's risk; the
session's evidence is its peak risk; a session alerts when that peak reaches a threshold
frozen at calibration time. A *reference migration* policy re-pins the binding after a
monotone transition but never after a revisit, which is what turns "the binding changed"
into "the bindings are interleaved". Work is O(1) per request in time and space. No machine
learning of any kind, enforced mechanically by `pipeline/validate.py`.

## 2. Final invariant definitions

**LOCKED — unchanged by this work.**

```python
DEFAULT_INVARIANTS = ("V1_agent_mutation", "V2_scope_discontinuity", "V3_binding_fork")
```

| | Security property | Benign cause | Grading |
|---|---|---|---|
| `v1` agent mutation | client software identity cannot change mid-session | major-version upgrade | 1.0 core change, 0.35 version-only |
| `v2` scope discontinuity | a bearer token presented from a different network than obtained it | DHCP renewal, NAT rotation, roaming | 1.0 new /16, 0.45 new /24, 0.15 new host |
| `v3` binding fork | two bindings interleaved — no single-client explanation | dual-homed client flapping | 1.0 on revisit |

Severities are the declared constants in `InvariantParams`; none is fitted.

**Rejected and kept implemented and auditable:** `v4` transition velocity, `v5` rate
discontinuity, `v6` navigation break. E3 restores each and reports the effect.

**Selection, stated exactly** (corrected under FIX 6). Chosen on development seeds 100–119,
disjoint from every reporting seed, on threshold-free ROC AUC required to agree across both
workloads. This set is the outright maximum on W1 (0.9613 vs 0.9521 for `V1,V2`). On W2 it
is **statistically tied, not first**: `V1,V2,V3,V4,V6` scores 0.9608 vs 0.9589, a 0.0019 gap
with overlapping CIs, while being clearly worse on W1 (0.9409). The rule applied was "best
on one workload, tied on the other, nothing dominating on both" — not a per-workload argmax.
Dropping `v3` gives a **higher** F1 on both workloads (0.705 vs 0.649 on W1; 0.694 vs 0.539
on W2) at lower AUC; `v3` is retained because the criterion was pre-declared and
threshold-free, not because it wins everywhere.

## 3. Per-request processing flow

```
observe(session_id, ip, ua, ts, path, referrer)
  binding_of(ip, ua)  →  (address, /24, /16, browser, version, os, device)
  first sight?  → pin reference, record path, return zero record (established)
  otherwise:
    dt, changed_binding = key != last_key, is_revisit = changed_binding and key in ring
    evaluate ONLY the enabled invariants          (the ablation switch reaches the hot path)
    risk = Σ wᵢ · vᵢ                               (evidence = peak risk)
    bounded state update:
      ring ← key (bounded, evicting oldest)
      reference migrates iff migrate_reference and NOT is_revisit
      ewma_gap, last_ts, n_seen, path window + membership index
    peak_risk, alerted_at (first crossing of τ)
  return per-invariant degrees, applicability flags, risk, explanation
```

## 4. State maintained

Per live session (`SessionState`, `slots=True`): pinned `Binding`, `last_key`, `last_ts`,
`n_seen`, `ewma_gap`, bounded binding `ring` (4), bounded `paths` deque (32) with a parallel
`path_set` membership index, `accumulator`, `peak_risk`, `evidence_peak`, `alerted_at`.
Analytic design bound 2,000 B/session; **measured** resident cost 4,767 B (W1) / 3,366 B
(W2). Both are reported; they are not a bound and its confirmation — the design bound counts
payload, the measurement counts Python object overhead.

## 5. Calibration definition

Attack-free calibration traffic only; no label is read anywhere in `sica/calibrate.py`.

1. **Applicability gate** — an invariant whose precondition holds on <1% of calibration
   requests is disabled and its weight redistributed. (This is what correctly switches `v6`
   off on W2, where referrer coverage is 0.00025 and applicability measures 0.000, rather
   than awarding it maximum weight for never firing.)
2. **Benign-rarity weights** — `wᵢ ∝ log(1/(εᵢ + ε₀))`, `ε₀ = 0.01`, over the applicable set.
   Verified against the published ε: the recorded weights reproduce this formula exactly on
   both workloads.
3. **Threshold** — §6.
4. Labels are read only to compute metrics, after every decision exists.

Two passes and no more: pass 1 probes **all six** invariants with unit weights to obtain ε
and applicability (so a rejected invariant's statistics stay observable); pass 2 replays with
the deployed weights through the **same** evidence pipeline evaluation uses, and the
threshold is taken over that statistic.

## 6. Threshold definition

**CORRECTED — FIX 1 (audit C1).** τ is the **smallest observed session peak risk whose
realised in-sample alarm rate satisfies the budget** under the deployed alert inequality.

* **Calibration population** — session peak risk of every session in the attack-free
  calibration partition, through the evaluation evidence pipeline. No evaluation session and
  no label contributes.
* **Alert inequality** — `peak >= τ`. The threshold is chosen against that exact inequality.
* **Tie handling** — the risk statistic is coarse (a weighted sum of three invariants with
  fixed severities), so the population is heavily tied. A `(1−α)` quantile lands on a plateau
  and `>=` admits the whole plateau. Only an observed value can change the alarm set, so the
  admissible thresholds are exactly the distinct observed values; the smallest one meeting
  the budget is returned.
* **Guarantee** — `mean(peaks >= τ) ≤ α`, and no smaller observed value satisfies it
  (minimality matters: the budget is otherwise met trivially by detecting nothing).
* **Finite-sample behaviour** — achievable rates are multiples of `1/N`. A budget below
  `1/N` is attainable only by alerting on nothing; when no observed value qualifies, τ is
  placed just above the maximum and the run alerts on nothing rather than overshooting.
* **Achieved rate** — recorded per run as `calibration_alarm_rate` and asserted by
  `validate.py` across every run.

α = 0.01, unchanged. **α was not altered in response to any observed result.**

*Before:* `np.quantile(values, 1−α, method="higher")`, measured calibration alarm rate
**2.15% (W1) / 1.85% (W2)** against a 1.0% budget, and 3.94% on one seed — the budget was
missed on the very sample the quantile was computed from.
*After (diagnostic):* ≤ 0.79% on every seed checked, on both workloads.

## 7. Threat model

Unchanged. The adversary has obtained a valid, already-authenticated session identifier by a
means outside the model and replays it against the same server. The defender sees only what
a web server logs: address, User-Agent, timestamp, path, referrer, status, bytes. No TLS
fingerprint, no client-side JavaScript, no token binding. Out of scope: session fixation,
credential theft, replay of a completed transaction. The unit of analysis is the request,
evaluated statefully; the unit of decision and reporting is the session.

## 8. Attack construction

Attacker requests are **real requests taken verbatim from a different real client of the same
server**; only the binding is substituted. Sessions are **length-matched** exactly.

**CORRECTED — FIX 3 (audit H1):** the masquerade level is defined against the victim's
binding **at the theft point**, not against `Session.client`. Benign churn is applied before
injection, so a victim may legitimately have moved network or updated its agent before the
theft; deriving levels from the original binding placed the attacker further from the victim
than the level declared, making the hardest cells artificially detectable. Donor
admissibility for L0/L1 likewise excludes every scope the victim presents anywhere in the
session, not merely its first.

**EXTENDED — FIX 2 (audit C2):** the reported envelope now spans six levels.

| Level | Attacker address | Attacker agent | Address signal |
|---|---|---|---|
| L0 | donor's own (different /16) | donor's own | present |
| L1 | donor's own (different /16) | victim's (cloned) | present |
| L2 | synthetic, victim's /16, different /24 | donor's own | present |
| L3 | synthetic, victim's /24, different host | victim's (cloned) | present |
| **L4** | **the victim's own** | victim's (cloned) | **none** |
| **L5** | **the victim's own** | donor's own | **none** |

Modes: `takeover` (victim silent after theft) and `concurrent` (victim keeps browsing; the
final request is never displaced, and the donor's gap pattern is compressed where necessary
so the interleaving is real).

**Why the envelope changed.** L0–L3 all give the attacker a different address, so "alert on
any address change" detected every one of them *by construction* — `pin_ip` measured recall
exactly **1.0000** on both workloads. Evaluating on those alone reduces the benchmark to
address-change detection and makes the recall axis of the baseline comparison carry no
information. L4 (co-located, cloned agent) is invisible to *every* binding-based signal and
is the acknowledged blind spot of the whole approach; L5 (co-located, different client
program) carries no address signal at all but does break agent continuity, and is the case
that separates hijack detection from address-change detection most directly. **No scenario
was removed.** L4 was previously defined but excluded from the reported mixture; it is now
included and L5 is new.

**Detecting address change ≠ detecting session hijacking.** The benchmark now makes the
distinction measurable in both directions: hijacks with no address change (L4, L5) that an
address rule cannot see, and benign sessions with address changes (the churn model) on which
an address rule false-alarms. Neither the presence nor the absence of an address change
determines the label. *Diagnostic:* `pin_ip` recall falls from 1.0000 to 0.44–0.75.

## 9. Legitimate churn model

Benign mobility injected into the negative class, applied to **both** partitions at the same
declared rates (an operator's calibration traffic is itself subject to mobility):
`M1_handover` (address change, monotone), `M2_agent_update` (client version upgrade,
monotone), `M3_combined`, `M4_flapping` (alternating addresses — the one benign phenomenon
that mimics a live hijack, included deliberately so `v3`'s cost is measured rather than
assumed). Rates: monotone 0.15, flapping 0.05; address granularity host 0.50 / subnet 0.30 /
scope 0.20. These are **declared assumptions, not measurements**, and are swept in E4.

**CORRECTED — FIX 4 (audit H2):** the agent update now moves the version the fingerprinter
actually reads. Previously `_bump_version` matched a hard-coded list of browser tokens and
appended `" Build/2"` to anything else; on W2, which is 91.96% `Debian APT-HTTP/1.3 (…)`,
that suffix changed the raw string while leaving every parsed field identical, so the benign
agent-update class existed in name only — 1,898 sessions labelled `M2_agent_update`
produced **zero** V1 firings and the measured benign firing rate was exactly **ε(V1) =
0.00000**. Three changes:

1. `sica/fingerprint.VERSION_KEYS` is now the single source of truth for where each family
   advertises its version; the fingerprint reads with it and the churn model writes with it,
   so the two cannot drift.
2. For `AptHTTP` the **parenthesised package version** is read rather than the protocol
   version. `Debian APT-HTTP/1.3 (0.9.7.9)` advertises protocol 1.3 — identical for every apt
   client ever observed in these corpora — and the client's own version in parentheses, which
   is what genuinely varies (`0.8.16~exp12ubuntu10.16`, `0.9.7.9`, `1.0.1ubuntu2` all occur).
3. An agent update prefers a **real agent string observed elsewhere in the same corpus** with
   the same agent core and a different major version, falling back to a synthetic increment
   only when the corpus offers none. No unrealistic agent is fabricated. A client that
   advertises no version at all cannot undergo an observable upgrade, so that session is
   skipped and the skip is counted (`skipped_agent_update`) rather than mislabelled.

*Diagnostic:* ε(V1) on W2 moves from 0.00000 to ≈0.0027–0.0029. **Direction of effect:**
this both restores a benign cost that V1 was previously never charged *and* gives V1 signal
on W2 attack cells where donor and victim run different apt versions. It is a correctness
fix with effects in both directions; it must not be presented as a neutral one.

## 10. Baselines

Unchanged. Pinning (parameter-free): `pin_ip`, `pin_prefix24`, `pin_scope16`,
`pin_useragent`, `pin_useragent_core`, `pin_ip_or_useragent`, `pin_ip_and_useragent`. Scored
(calibrated to the same budget, by the same procedure, on the same partition):
`score_distinct_bindings`, `score_max_request_rate`, `score_burstiness`.
`pin_useragent_core` reads exactly the agent core `v1` reads, through a shared helper.

**Open, deferred:** ROC AUC is still computed for binary pinning rules, where it reduces to
balanced accuracy and is not a ranking measure, yet is tabulated in the same column as
SICA's AUC (audit H5, my numbering). This is a reporting-layer defect; it is **not fixed**
and must be addressed before the baseline table is published.

## 11. Evaluation scenarios

Per seed: split (temporal 50/50 reported; client-disjoint and random as leakage controls) →
benign churn on both partitions → attack injection into the evaluation partition only →
calibrate on calibration only → replay evaluation under the frozen threshold → metrics.
Scenario grid: 6 levels × 2 modes = 12 cells per workload. Reporting seeds 0–29 (E1/E2) and
0–19 (E3/E4/E5); development seeds 100–119, disjoint and asserted. Attack rate 0.20 of
evaluation sessions targeted; realised prevalence reported rather than assumed.

## 12. Leakage controls

* Calibration partition is attack-free by construction; calibration/evaluation session
  disjointness asserted.
* Calibration reads no label — asserted adversarially by relabelling the entire calibration
  partition and requiring weights and threshold to be unchanged.
* Sessions are length-matched, so request count cannot predict the label (marginal ROC AUC
  ≈0.52).
* Development and reporting seed blocks are disjoint, asserted.
* Split sensitivity: temporal, client-disjoint and random agree to within 0.005 ROC AUC.
* 26 structural checks in `results/metadata/leakage_report.json`, all passing.

**CORRECTED — FIX 6 (audit H4):** the claim that "no classifier of per-request features can
separate the classes" was **false** and is removed. Measured: `distinct_paths` reaches
marginal ROC AUC **0.732** on W2 and an ML-free Mahalanobis content detector reaches
**0.731**, because a donor package-manager client fetches a different set of package paths
than the victim. The defensible claim, which is what the design relies on, is narrower: the
retained invariants read **no path, timing, volume or byte-count feature** — a structural
property checked mechanically — so the residual shortcut cannot reach the detector, and the
detector's ranking quality is far above what the shortcut yields. The shortcut itself is
**not** suppressed by donor matching: that would be a benchmark change made to improve a
number, and it is documented instead.

## 13. Complexity

O(1) time and O(1) space per request; O(S) for S concurrently live sessions. Bounded binding
ring (4) and path window (32) with an incremental membership index; no scan over session
history; disabled invariants are not evaluated. Measured: ~67–72k req/s uninstrumented,
median instrumented latency 12.3 µs (W1) / 13.0 µs (W2), p99 ≈ 42 µs.

## 14. Tests

**36 passing.** `tests/test_sica.py` (23, unmodified) covers fingerprinting, invariant
grading, reference migration, fork-vs-move discrimination, state boundedness, rarity
weighting, applicability gating, label-free calibration, length-matched injection, real
takeover, genuine concurrent interleaving, determinism, churn scoping and AUC edge cases.
`tests/test_regressions.py` (13, new) guards every Tier-1 finding:

| Test | Guards |
|---|---|
| `test_threshold_meets_the_budget_under_heavy_ties` | C1 — budget holds on tied populations |
| `test_threshold_is_the_smallest_meeting_the_budget` | C1 — minimality |
| `test_threshold_is_unattainable_when_the_sample_is_too_coarse` | C1 — conservative fallback |
| `test_calibration_achieves_its_declared_budget_end_to_end` | C1 — on real traffic |
| `test_reported_envelope_contains_colocated_attackers` | C2 — envelope includes L4/L5 |
| `test_every_masquerade_level_has_its_declared_address_relation` | C2 — level semantics |
| `test_pin_ip_is_not_perfect_by_construction` | C2 — recall < 1.0 |
| `test_masquerade_level_uses_the_post_churn_victim_binding` | H1 |
| `test_version_bump_is_observable_for_every_parsed_family` | H2 |
| `test_agent_churn_is_observable_on_the_apt_workload` | H2 — on W2 specifically |
| `test_pr_auc_is_invariant_to_input_order_under_ties` | H3 |
| `test_pr_auc_matches_known_values` | H3 — closed forms |
| `test_roc_auc_matches_known_values` | H3 — regression guard |

Every one was written first and confirmed failing against the old behaviour.

## 15. Known limitations

1. **L4 is undetectable in principle.** A co-located attacker cloning the victim's agent
   presents an identical binding; no server-side binding signal can separate it. It is in the
   reported envelope precisely so this is visible rather than hidden.
2. **A silent takeover is information-theoretically identical to a legitimate device change**
   at the binding level.
3. **W1 is small** (254 sessions); its intervals are wide and it should not carry a claim
   alone.
4. **The benign mobility model's shape is ours.** Rates are swept; shape is not. The corrected
   agent-update draws real strings from the corpus, but which sessions churn, and at what
   rate, remain declared assumptions.
5. **Both logs are unauthenticated public traffic from 2015**, so session identity is
   reconstructed rather than observed.
6. **The attacker's timing is a real client's timing**, so this benchmark cannot credit `v5`
   with signal it might carry against a scripted adversary.
7. **`v3`'s aggregate contribution is small** and costs F1 at the operating point; it is
   retained on a pre-declared threshold-free criterion. Whether the C1 correction changes that
   trade-off is **UNKNOWN** and must be settled on development seeds only (audit U4).
8. **A content shortcut remains on W2** (`distinct_paths`, ≈0.73 AUC). It cannot reach the
   retained invariants, and is documented rather than suppressed.
9. **Measured per-session state exceeds the analytic design bound** by 1.7–2.4×.
10. **Open MEDIUM findings, not fixed:** M1/M7 (session ids embed the salted `hash()`, so ids
    are not reproducible across processes and uniqueness is probabilistic), M2 (the takeover
    theft window is overridden when the 40-request cap binds, making part of E4's
    theft-position sweep inert), M6 (a test mutates a shared fixture), and audit H5 (ROC AUC
    reported for binary rules). Audit UNKNOWNs U1, U2, U4, U5 remain open.

## 16. Explicit frozen decisions

Frozen as of this document; any change requires `CHECKPOINT.md` §9.

1. **Invariant set** — `(V1_agent_mutation, V2_scope_discontinuity, V3_binding_fork)`.
2. **Invariant severities** — `InvariantParams` as declared.
3. **Calibration protocol** — applicability gate at 1%; `w ∝ log(1/(ε+0.01))`; peak-risk
   evidence; two-pass structure. *Definition frozen; the threshold **implementation** was
   corrected under FIX 1 to satisfy it.*
4. **Budget** — α = 0.01, with the guarantee and finite-sample behaviour of §6.
5. **Reference migration on**; evidence = peak.
6. **Corpora and sessionisation** — 1800 s idle, ≥7 requests, `(address, UA)` ground-truth
   grouping (detector sees only the session id).
7. **Attack construction** — real donor content, exact length matching, levels **L0–L5** with
   the definitions of §8, modes takeover/concurrent, level defined against the victim's
   binding at the theft point.
8. **Churn model** — kinds and rates of §9; agent updates drawn from real corpus strings.
9. **Seeds** — reporting 0–29 and 0–19; development 100–119; bootstrap seed 0, 10,000
   resamples.
10. **Experiment suite** — E0–E7 and no more. No experiment may be added to improve a number.
11. **Baselines** — the ten rules of §10.
12. **Metrics** — session-level primary; ROC AUC and average precision both tie-corrected.

**Not frozen:** manuscript prose, figure styling, deployment-side response policy, and the
four open MEDIUM findings in §15.10.

---

## Change log — OLD → NEW

| File | OLD | NEW | Finding |
|---|---|---|---|
| `sica/calibrate.py` | `threshold_for_budget` returned `np.quantile(v, 1−α, method="higher")`; docstring claimed a budget guarantee it did not provide | scans distinct observed values and returns the smallest whose realised alarm rate ≤ α, with conservative fallback above the maximum; docstring states population, inequality, tie handling, guarantee, finite-sample behaviour | **C1** |
| `sica/inject.py` | `LEVELS = ("L0".."L3")`, `LEVELS_ALL` adding L4; L4 excluded from the reported mixture | `LEVELS_ADDRESS_VISIBLE` (L0–L3), `LEVELS_COLOCATED` (L4, **L5 new**), `LEVELS_ALL` = all six = the reported envelope; L5 implemented with a donor-agent constraint | **C2** |
| `sica/inject.py` | attacker binding derived from `victim.client`; donor scope check against the victim's first scope only | derived from `victim.requests[cut]` (the theft-point binding); donor excluded if it matches **any** scope the victim presents | **H1** |
| `sica/inject.py` | docstring: "no classifier of per-request features can separate the classes" | claim removed as false; replaced with the measured statement (0.732 / 0.731 on W2) and the narrower property the design actually relies on | **H4** |
| `sica/harness.py` | `ExperimentConfig.levels = LEVELS` (L0–L3) | `= LEVELS_ALL` (L0–L5), with the rationale inline | **C2** |
| `sica/fingerprint.py` | version-key table inline in `_major_version`; `AptHTTP` read the protocol version after `apt-http/` | `VERSION_KEYS` module constant as single source of truth; `AptHTTP` reads the parenthesised client package version first | **H2** |
| `sica/churn.py` | `_bump_version` regex over 6 browser tokens, appending `" Build/2"` otherwise | `bump_agent_version` (keyed on `VERSION_KEYS`, returns `None` when no version is advertised), `build_agent_pool`, `agent_update` preferring a real corpus agent with the same core and a different major version; unobservable updates skipped and counted | **H2** |
| `sica/metrics.py` | `pr_auc` walked the sorted list sample by sample, so ties were ordered by input position; `_auc_inputs` helper | average precision with tie groups collapsed to one operating point; dead `_auc_inputs` removed | **H3** |
| `sica/invariants.py` | selection described as ROC AUC "consistent across both workloads" | adds exactly what that resolved to, including the W2 statistical tie (0.9608 vs 0.9589, overlapping CIs) and `v3`'s F1 cost. **`DEFAULT_INVARIANTS` unchanged.** | **H5** |
| `pipeline/validate.py` | adversary grid hard-coded to 20 cells | grid size computed from `LEVELS_ALL × MODES × workloads`; asserts the envelope includes the co-located levels, that `pin_ip` recall < 1.0, and that every run meets its budget on calibration | **C1, C2** |
| `CHECKPOINT.md` | §2 stated the criterion without its outcome | records the W1 maximum, the W2 tie, and `v3`'s F1 cost | **H5** |
| `AUDIT.md` | §R4 "Two invariants were harmful and were removed" | "Three invariants were rejected, in two rounds", with `v6`'s round-2 rejection and the stale text acknowledged | audit **I1** |
| `tests/test_regressions.py` | *(did not exist)* | 13 regression tests, one per Tier-1 finding | all |
| `docs/TEST_PLAN.md` | *(did not exist)* | the plan, its outcome, and an explicit NOT-DONE list | — |
| `docs/ARCHITECTURE_FREEZE.md` | *(did not exist)* | this document | — |

`tests/test_sica.py`, `sica/monitor.py`, `sica/baselines.py`, `sica/sessionize.py`,
`pipeline/*` (other than `validate.py`), `paper/*`, `data/*` and everything under `results/`
were **not modified**. No previous result artifact was deleted or overwritten.

## Effect of the corrections — diagnostic only, NOT reported results

Single-seed runs used solely to verify the fixes work end to end.

| | before | after |
|---|---|---|
| calibration alarm rate vs α=0.01 | 0.0215 (W1) / 0.0185 (W2); 0.0394 worst seed | ≤ 0.0079 every seed, both workloads |
| `pin_ip` recall | **1.0000** (both workloads) | 0.44–0.75 |
| ε(V1) on W2 | **0.00000** | ≈0.0027–0.0029 |
| PR AUC, fully tied sample | 0.833 | 0.500 (= prevalence) |
| SICA ROC AUC | ≈0.96 | ≈0.83–0.92 |

The last row is the honest cost of the first two: the envelope now contains attacks that are
undetectable by any binding-based signal (L4) or by any address-based signal (L5), and the
operating point is where it was declared to be rather than 2–4× past it. **Every reported
number in the project must be regenerated; none of the pre-fix results may be quoted.**

---

**STOP.** No experiments were run and none may begin without explicit instruction. The
next step, when authorised, is Part 3: a full reporting run from a clean `results/` tree,
ending in `validate.py` and `results/PIPELINE_DONE`.
