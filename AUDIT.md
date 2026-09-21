# Audit trail

What was wrong with the earlier versions of this project, what was changed, and
what the change did to the numbers. Nothing here is retrospective
rationalisation: each finding is stated with the artefact that demonstrates it,
and the superseded work is preserved under `archive/v1/` rather than deleted.

There were **two** rounds of correction. Round 1 rebuilt the research direction.
Round 2 audited the rebuild itself and found four further defects — including two
in the benchmark construction that had been *inflating* the reported detection
rate.

---

## Round 1 — the original project

The original work was a six-context per-user anomaly detector ("does this session
look like this user's history?") evaluated on a mixture of synthetic and log-derived
data.

### O1. The 54% false-positive rate was a bug, not a finding

`src/data_generator.py` gave each user a fixed `base` tuple and then emitted all
50 history sessions as `LEGITIMATE_NORMAL` **without perturbing it**. Every
user's entire history was therefore one repeated point: identical network,
device, browser, latitude/longitude, transaction amount, type, beneficiary and
hour. Compounding it, `build_profiles` fitted the profile on all history and
`evaluate` then scored that same history to calibrate the threshold — so
historical novelty was zero by construction, the standard deviation collapsed,
and `τ = mean + 2σ` landed near zero. Any legitimate change in evaluation (a new
device scores 1/6 ≈ 0.167) exceeded `τ + δ` and was terminated.

That is the reported FPR of 0.5409, and it is why the "minus behaviour" ablation
row reported FPR exactly 1.0000.

### O2. The headline "real-data" result was a trivial artefact — and was ML

All 803 attack labels in Dataset A came from one synthetic file,
`web_sessions.csv`, in which

| | `requests_count` | `duration_seconds` |
|---|---|---|
| legitimate | 1 – 30 | 60 – 3600 |
| attack | 50 – 500 | 1 – 60 |

The ranges are **disjoint**. A single hand-picked threshold on one feature
separates the classes perfectly, which is the entire content of the reported ROC
AUC 0.9999 and recall 1.0000. The real Apache and Nginx rows carried *no* attack
labels, so no real traffic was ever tested. Separately, the strongest reported
number belonged to a One-Class SVM — a learned detector, excluded by the
project's own non-ML constraint.

### O3. Almost none of the "attacks" were session hijacking

Of the 803 Dataset A attacks: 169 `session_hijack`, 163 brute force, 152 XSS,
143 SQL injection. Dataset B's other 1,185 were network port-scan flows. **169
rows in the entire project were the phenomenon the paper was about.**

### O4. Dataset B was incoherent, and double-counted its inputs

It merged 15,000 network flows with web sessions and scored them with session
features; its reported ROC AUC of 0.2016 is *below chance*, which is a symptom of
broken construction rather than an identity-quality insight. Independently,
`apache_sample_2.log` and `nginx_real.log` were verified byte-for-byte identical
in content — the same 51,462 log records in two formats — and were counted as two
separate "source families" of 7,308 records each.

### O5. The runtime benchmark was not timing the detector

`runtime_benchmark.csv` reported 0.0037 s for 100 sessions and 0.0049 s for
10,000 — flat in *n*. The in-loop figure reported elsewhere was 0.40 ms/session,
roughly 1000× larger. The "lightweight" claim was unmeasured.

### O6. The unit of analysis was wrong

Scoring whole sessions against a per-user historical profile is anomalous-login /
account-takeover detection. Session hijacking is an **intra-session** event: a
stolen identifier replayed inside a live session. The correct unit is the request
within a session, not the session against a user history.

### Response

The direction was rebuilt around stateful per-request session-continuity
monitoring, evaluated on real access logs with hijacks injected from other real
clients. The v1 tree is preserved under `archive/v1/`.

---

## Round 2 — auditing the rebuild

The rebuild was then audited against its own claims. Four defects were found;
two of them were inflating the reported detection rate, and both are now covered
by regression tests.

### R1. "Takeover" was silently a partially concurrent hijack — **inflated recall**

`inject_session` drew the theft point `cut` and the attacker's request count `k`
independently, then kept `benign[: n - k]` for takeover mode. Since `k ≈ 0.4n`
and `cut ∈ [0.25n, 0.5n]`, the retained victim traffic ran to index `n - k ≈
0.6n`, past the theft point — while attacker timestamps were anchored at
`cut`. The victim therefore kept issuing requests *after* the theft, so the fork
invariant could fire on a scenario that by definition contains no fork.

**Fix.** For takeover, `k := n − cut − 1`: the attacker replaces the whole
remaining tail and the victim falls silent at the theft point. The attacker's
share is then fixed by the theft position, which is swept in E4.
`tests/test_sica.py::test_takeover_is_a_real_takeover` asserts that no victim
request follows the first injected one.

**Effect on results** (W1, 10 seeds): aggregate recall fell 0.576 → 0.519;
`L1_takeover` fell 0.555 → 0.093. The corrected figures are the reported ones.

### R2. "Concurrent" produced no interleaving in 40% of cases — **inflated recall**

Two independent causes. First, `k` was allowed to consume the *entire* post-theft
tail, so all remaining victim requests could be displaced, leaving an attacker
block at the end — a takeover wearing a concurrent label. Second, attacker
timestamps used the donor's raw inter-arrival gaps, which frequently ran past the
victim's last request.

**Fix.** The final request of a session is never displaced (`k ≤ n − cut − 2`),
and the donor's gap *pattern* is compressed where necessary to fit inside the
victim's remaining window. Only compression is applied.
`test_concurrent_hijack_actually_interleaves` asserts that >80% of concurrent
injections contain a victim request after the theft; measured, it is 100%.

This alters inter-arrival magnitudes, which is admissible precisely because no
retained invariant reads a timestamp difference — see R4 and `DATASET.md §5`.

### R3. Three defects in the request path

* **`v6` could never match.** Request paths were stored with their query strings
  while `Referer` values were normalised without them, so an in-site referrer
  could not match the page it pointed at. Paths are now normalised identically.
* **Disabled invariants were still evaluated.** The ablation switch reached only
  the weight vector, so the efficiency benchmark charged the deployed detector
  with work it does not do. The switch now reaches the hot path.
* **`set(st.paths)` was rebuilt on every request**, a 32-element allocation
  inside an `O(1)` claim. A parallel set is now maintained alongside the bounded
  deque.

### R4. Three invariants were rejected, in two rounds

**Round 1 — `v4` and `v5`.** `v4` (transition velocity) and `v5` (rate
discontinuity) each *reduced* detection quality on **both** workloads. The reasons
are specific rather than incidental: in a log without geographic coordinates `v4`
fires on the same event `v2` already reports, double-counting one piece of
evidence; `v5` fires on 12–19% of benign requests.

**Correction (Part 3.5).** This section previously attributed `v5`'s firing rate
to ordinary page loads being bursty. That explanation was wrong. Independent
dataset verification established that both source logs carry a degenerate minute
field — always `05` in W1, `05`/`06` in W2 — so every sessionised session spans at
most 59 seconds and every inter-arrival gap is an artefact of the upstream
generator rather than an observation of client behaviour. `v5` is measuring
generator noise on this corpus, and `v4` cannot be assessed at all here because
its 300 s settle time exceeds the longest session by a factor of five. Both
rejections stand; the reasons are now stated correctly. See
`docs/DATASET_VERIFICATION.md` §6 and `docs/DATASET_FREEZE.md` §9.

**Round 2 — `v6`.** A later ablation anomaly prompted a re-selection over a
broader candidate set, and `v6` (navigation break) was dropped as well. It is
*inapplicable* on W2 — referrer coverage there is 0.00025, so the applicability
gate correctly disables it and its measured applicability is 0.000 — and on W1,
the one workload where it can fire at all, it fires on 34% of benign requests and
reduced ranking quality. Dropping it also removed the only corpus-level parameter
(the first-party host set) from the deployed configuration.

The final retained set is therefore **three** invariants, `v1`, `v2`, `v3`, and
three were rejected. An earlier revision of this section described only the first
round and said "two invariants were removed"; that was stale and is corrected
here.

Both rounds were decided on the **development seed block (100–119)**, disjoint
from the reporting seeds, by `pipeline/dev_invariants.py`, on threshold-free ROC
AUC. The criterion did not separate the candidates cleanly on W2, where the
retained set is statistically tied rather than first; see `CHECKPOINT.md` §2 and
`docs/ARCHITECTURE_AUDIT.md` M3 for the exact figures.

All three rejected invariants remain implemented, and E3 reports **restoration**
experiments that add each back to the retained set, so the rejections stay
auditable rather than asserted.
A deployment with genuine geolocation (for `v4`) or a scripted adversary (for
`v5`) may recover their value; this evaluation cannot credit them with it.

### R5. Two fairness defects in the benchmark, found by a baseline beating the method

Address pinning initially outranked SICA in ROC terms. Investigating rather than
accepting it revealed that the benchmark was unfair **to the baseline's
disadvantage in one respect and to its advantage in another**:

* **Benign intra-`/24` address churn did not exist.** The benign mobility model
  only ever changed the `/24` or the `/16`, so the most common real benign
  address change — a DHCP lease renewal or NAT pool rotation inside one `/24` —
  never occurred, and address pinning never paid for it. The model now draws
  granularity as 50% host / 30% subnet / 20% scope.
* **SICA could not see host-level changes at all.** Its binding key used the
  `/24` prefix, so an attacker in the victim's `/24` was invisible to it while
  address pinning caught them. The binding key now carries the full address and
  `v2` grades over three levels (0.15 / 0.45 / 1.0).

After both corrections SICA's ROC AUC rose above address pinning's on both
workloads, and — more importantly — the comparison became a real trade-off with a
measurable crossover point, which E4c now reports.

Separately, `pin_useragent_core` was reading `(browser, OS)` while `v1` reads
`(browser, OS, device class)`. The baseline now uses exactly the same derived
quantity, so the comparison measures the rule and not the parser.

---

## What remains a known weakness rather than a fixed defect

* **W1 is small** (254 sessions); its intervals are wide.
* **The benign mobility model's shape is ours.** Its rates are swept; its shape
  is not. It assigns zero probability to a mid-session agent-*core* change, so
  the 0% false-alarm rate measured for agent-core pinning is an **upper bound on
  that baseline**, not a measurement — stated as such wherever that baseline is
  reported.
* **The realised false-alarm rate exceeds the nominal budget.** At α = 0.01 the
  measured rate is ≈1.6–1.8%, because the risk score is coarse-valued and the
  calibration quantile lands on a plateau. The budget *transfers* well from
  calibration to evaluation; it is not exactly met. Reported as measured.
* **`L4` is outside any binding-based envelope**, and a silent takeover is
  information-theoretically identical to a legitimate device change.

---

## Provenance of the numbers in this file

The v1 figures are quoted from the artefacts in `archive/v1/results/` and from
`archive/v1/MASTER_RESEARCH_RECORD.md`. The disjointness of the
`web_sessions.csv` feature ranges and the byte-identity of `apache_sample_2.log`
and `nginx_real.log` were verified directly against those files during the audit.
The round-2 before/after figures were produced by running the corrected and
uncorrected code paths on the same seeds. All current figures come from
`results/tables/`, regenerated by `./run_all.sh`.
