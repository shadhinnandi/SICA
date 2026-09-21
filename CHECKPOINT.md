# Checkpoint — final locked research state

This file records what is **frozen**. Nothing listed under "locked" may be
changed without invalidating the reported results; anything changed under it
requires a full re-run of `./run_all.sh` and a re-derivation of every table,
figure and number in the manuscript.

Status is filled in by the final validated run; see the header of
`RESEARCH_RECORD.md` for the run's numbers and `results/PIPELINE_DONE` for its
timestamp.

---

## 1. Locked: research design

* **Problem.** Intra-session HTTP session hijacking: replay of a valid,
  already-authenticated session identifier by a party other than the one that
  authenticated. Not session fixation, not credential theft, not replay of a
  completed transaction.
* **Constraint.** The detector contains **no machine learning** — no neural
  network, no classifier, no clustering, no one-class SVM, no learned embedding,
  no supervised use of attack labels. Enforced mechanically by
  `pipeline/validate.py`.
* **Unit of analysis.** The request within a session, evaluated statefully.
* **Explainability.** Every alert names the invariants it violated and their
  violation degrees.

## 2. Locked: invariant set

```
DEFAULT_INVARIANTS = (V1_agent_mutation, V2_scope_discontinuity, V3_binding_fork)
```

Selected on the **development seed block 100–119**, disjoint from every seed used
for a reported result, by `pipeline/dev_invariants.py`, under a criterion
declared before selection: **threshold-free ROC AUC, required to agree across
both workloads.**

What that criterion resolved to, exactly: this set is the outright maximum on W1
(0.9613 vs 0.9521 for `V1,V2`), but on W2 it is **statistically tied**, not first —
`V1,V2,V3,V4,V6` scores 0.9608 against 0.9589, a 0.0019 gap with overlapping CIs,
while being clearly worse on W1 (0.9409). The applied rule was "best on one
workload, tied on the other, with nothing dominating on both". Dropping `v3`
would give a *higher* F1 on both workloads (0.705 vs 0.649 on W1; 0.694 vs 0.539
on W2) at lower AUC; `v3` is retained because the criterion was threshold-free and
pre-declared, not because it wins everywhere. See `docs/ARCHITECTURE_AUDIT.md` M3.

| | Security property | Benign cause | Grading |
|---|---|---|---|
| `v1` agent mutation | client software identity cannot change mid-session | browser major-version upgrade | 1.0 core change, 0.35 version-only |
| `v2` scope discontinuity | a bearer token presented from a different network than obtained it | DHCP renewal, NAT rotation, roaming | 1.0 new `/16`, 0.45 new `/24`, 0.15 new address |
| `v3` binding fork | two bindings interleaved — no single-client explanation | dual-homed client flapping | 1.0 on revisit |

**Rejected, and kept implemented and auditable:** `v4` transition velocity,
`v5` rate discontinuity, `v6` navigation break. E3 restores each one to the
retained set and reports the effect.

**Design switches, also fixed on development seeds:** reference migration **on**
(re-pin after a monotone transition, never after a revisit); session evidence =
**peak** per-request risk (not the decayed accumulator).

## 3. Locked: calibration protocol

1. Applicability gate — an invariant whose precondition holds on <1% of
   calibration requests is disabled and its weight redistributed.
2. Benign-rarity weights — `wᵢ ∝ log(1/(εᵢ + ε₀))`, `ε₀ = 0.01`, over the
   applicable set, from attack-free calibration traffic only.
3. Threshold — `τ` = the `(1−α)` quantile of session peak risk over the
   calibration partition, computed through the **same** evidence pipeline that
   evaluation uses, and frozen before any evaluation session is scored.
4. Labels are read only to compute metrics, after every decision exists.

`α = 0.01`. Asserted by
`tests/test_sica.py::test_calibration_ignores_labels_entirely`.

## 4. Locked: dataset and benchmark construction

* **Corpora.** `data/raw/apache_sample_1.log` (W1, Apache sample log, human web
  browsing) and `data/raw/nginx_real.log` (W2, Nginx sample/demo log, APT-style
  clients). Both are **public sample logs from the Elastic Examples repository**
  (Apache-2.0), unmodified, verified byte-identical to upstream by SHA-256, and
  included in the repository. They are sample logs, **not production traffic**.
  Two verified limitations bind their use — degenerate timestamps (no session
  exceeds 59 s; no temporal claim, no latency in seconds) and W2's placeholder
  URL universe. See `docs/DATASET_FREEZE.md`.
* **Sessionisation.** Group by `(address, User-Agent)`; 1800 s idle timeout;
  discard sessions under 7 requests. The grouping key is **ground truth only**;
  the detector sees a session identifier.
* **Attack injection.** Attacker requests are real requests taken verbatim from
  a different real client of the same server; only the binding is substituted.
  Length-matched. Masquerade levels `L0`–`L5` form the reported envelope:
  `L0`–`L3` address-visible, `L4` and `L5` co-located (the attacker presents the
  victim's own address). `L4` is outside any binding-based envelope and is
  reported as such. Modes: takeover
  (victim silent after theft) and concurrent (victim keeps browsing; the final
  request is never displaced).
* **Benign churn.** Monotone mobility 0.15 (host 0.50 / subnet 0.30 / scope
  0.20), flapping 0.05, applied to both partitions. **Assumptions, not
  measurements**; each swept in E4.
* **Splits.** Temporal 50/50 reported; client-disjoint and random as leakage
  controls. Attacks injected only into the evaluation partition.

## 5. Locked: seeds

| Purpose | Seeds |
|---|---|
| Reported results | 0–29 (E1, E2); 0–19 (E3, E4, E5) |
| Development decisions | 100–119 |
| Bootstrap | 0, 10,000 resamples |

Disjointness asserted by `pipeline/validate.py`.

## 6. Locked: experiment suite

E0 corpus · E1 main + budget sweep · E2 baselines · E3 ablation and restoration ·
E4 adversary grid, assumption sweeps, address-churn crossover · E5 leakage audit
· E6 efficiency · E7 statistics and base rates · figures and tables.

No further experiments are to be added. Per `EXPERIMENTS.md`, an additional
experiment is warranted only to establish correctness or answer a major reviewer
concern, not to improve a number.

## 7. Locked: baselines

Pinning (parameter-free): `pin_ip`, `pin_prefix24`, `pin_scope16`,
`pin_useragent`, `pin_useragent_core`, `pin_ip_or_useragent`,
`pin_ip_and_useragent`. Scored (calibrated to the same budget by the same
procedure on the same calibration partition): `score_distinct_bindings`,
`score_max_request_rate`, `score_burstiness`.

`pin_useragent_core` reads exactly the agent core that `v1` reads.

## 8. What is NOT locked

* The manuscript's prose.
* Figure styling.
* Deployment-side response policy (out of scope for this repository).

## 9. Change control

Any change to §§1–7 invalidates the reported results. The procedure is:

1. State the change and the reason in `AUDIT.md`.
2. If it is a design choice, decide it on the **development** seeds only.
3. Re-run `./run_all.sh` in full.
4. Confirm `pipeline/validate.py` passes and `results/PIPELINE_DONE` is written.
5. Regenerate tables and figures; the manuscript follows automatically because
   every number in it is a generated macro.

## 10. Known open weaknesses (documented, not fixed)

1. **W1 is small** (254 sessions); its intervals are wide.
2. **The realised false-alarm rate exceeds the nominal budget** (≈1.8% at
   α = 0.01), because the risk score is coarse-valued and the calibration
   quantile lands on a plateau. The budget transfers well from calibration to
   evaluation; it is not exactly met. Reported as measured.
3. **The benign mobility model's shape is ours.** Rates are swept; shape is not.
   It assigns zero probability to a mid-session agent-*core* change, so the 0%
   false-alarm rate measured for `pin_useragent_core` is an upper bound on that
   baseline, not a measurement.
4. **`L4` is outside any binding-based envelope**, and a silent takeover is
   information-theoretically identical to a legitimate device change.
5. **Both logs are unauthenticated public traffic from 2015**, so session
   identity is reconstructed rather than observed.
6. **The attacker's timing is a real client's timing**, which denies the
   evaluation any rate-based signal; `v5` cannot be credited here with signal it
   might carry against a scripted adversary.
7. **`v3`'s aggregate contribution is small.** It improves ranking on both
   workloads, which is why the pre-declared criterion retained it, but at the
   α = 0.01 operating point removing it raises F₁. Reported in E3 rather than
   presented as the decisive component.
