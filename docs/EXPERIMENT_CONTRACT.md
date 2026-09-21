# Experiment Contract

**Date.** 2026-09-12. **Status.** Pre-registered. Written **before** any reporting run.
**Binding on.** Everything executed from Part 4B onward.

This document fixes what will be run and how it will be judged, in enough detail that another
researcher could reproduce the study without making a single methodological choice that is not
written here. Where the implementation already fixes a decision, this contract **documents it
as implemented** rather than redesigning it; every such statement was read out of the code, not
recalled.

Companion frozen documents, with which this contract must not conflict (§23):
`docs/ARCHITECTURE_FREEZE.md`, `docs/REPRODUCIBILITY_FREEZE.md`, `docs/DATASET_FREEZE.md`,
`docs/DATASET_VERIFICATION.md`, `CHECKPOINT.md`.

**Nothing in this step was run.** No experiment, no table, no figure.

---

## 1. Primary research question

> **Can SICA detect intra-session session hijacking by identifying violations of session
> continuity/binding invariants, when attacker requests are injected into otherwise legitimate
> sessions?**

The question is scoped to **session hijacking** and is not broadened. This study does **not**
ask, and its results may not be used to answer, whether the method performs generic anomaly
detection, network intrusion detection, account-takeover detection, login-anomaly detection, or
malicious-payload detection. A result that would be interesting for one of those problems is
out of scope here.

Two sub-questions are measurable and both are reported:

* **Ranking quality** — ROC AUC and average precision of session peak risk.
* **Operating cost** — realised session-level false-alarm rate against the declared budget, and
  the recall obtained at it.

## 2. Threat model (frozen)

**Victim.** Holds a legitimate, already-authenticated session and has established a binding —
the observable client characteristics (network address, /24, /16, browser family, major
version, OS family, device class) that the server can attribute to whoever presents the session
identifier.

**Attacker.** Has obtained the victim's session credential by a means **outside this model**
(XSS, network capture, log leakage, malware) and replays it against the same server. The
attacker can issue requests under that session. The attacker does **not** necessarily control
the victim's original client, and in the concurrent regime the victim keeps using the session.

**Defender.** Sees only what a web server logs: address, User-Agent, timestamp, path, referrer,
status, byte count. No TLS fingerprint, no client-side JavaScript, no token binding, no
cooperation from the client.

**Detection goal.** Detect the continuity/binding inconsistency that the replay produces
*within the live session*. Unit of analysis: the request, evaluated statefully. Unit of decision
and reporting: the session.

**Explicitly distinguished — only the first is this study's problem:**

| Phenomenon | In scope? | Why it differs |
|---|---|---|
| **Stolen-session replay (intra-session hijacking)** | **YES — the problem** | A second party uses a *live, already-authenticated* identifier; continuity within one session is broken |
| Account takeover | No | Concerns credential compromise and subsequent *new* authenticated sessions, not continuity inside one |
| Login anomaly | No | Evaluated at authentication time, on identity and history; this detector never sees an authentication event |
| Malicious payload detection | No | Concerns request *content*; this detector reads no payload and no body |
| Session fixation | No | The attacker supplies the identifier before authentication |
| Replay of a completed transaction | No | No live session to be continuous with |

## 3. Dataset (frozen — see `docs/DATASET_FREEZE.md`)

Only the frozen corpus is used. The excluded v1 synthetic datasets (`web_sessions.csv`,
`network_flows.csv`, `apache_sample_2.log`) are **not** reintroduced and none exists in the
repository.

| Role | ID | File | SHA-256 (abbrev.) | Raw requests | Sessions (≥7 req) | Requests in corpus |
|---|---|---|---|---|---|---|
| **PRIMARY** | W1 | `data/raw/apache_sample_1.log` | `f15c31e9…0364ef` | 10,000 | **254** | 3,874 |
| **SECONDARY** | W2 | `data/raw/nginx_real.log` | `52683243…6937df` | 51,462 | **3,126** | 43,307 |

These counts were recomputed from the files in Part 3.5 and agree with `DATASET_FREEZE.md` §8.

**Statements that must accompany every description of this benchmark:**

* Both files are **public sample logs** from the Elastic Examples repository (Apache-2.0),
  verified byte-identical to upstream. They are **not production traffic**.
* The **traffic substrate is real observed traffic**; every request's path, status, byte count
  and referrer is genuine.
* The **attack condition is controlled injection**. Attacks here are **not claimed to be
  naturally occurring attacks**, and no prevalence claim about real deployments follows.
* **W2 is a demo/sample corpus**: three placeholder URL paths, 65.8% 404s, 0.025% referrer
  coverage. It is retained because it is *adversarial to the method*, not because it is
  representative.
* **Timestamp limitations are frozen** (§12): the minute field is degenerate, so no session
  exceeds 59 s and all inter-arrival times are generator artifacts.

## 4. Detector (frozen — no architecture change)

SICA as implemented, with the locked invariant set:

```python
DEFAULT_INVARIANTS = ("V1_agent_mutation", "V2_scope_discontinuity", "V3_binding_fork")
```

| | Name | Fires on | Grading (from `InvariantParams`) | Benign cause |
|---|---|---|---|---|
| **V1** | `agent_mutation` | client software identity differs from the pinned binding | **1.0** core change (browser family, OS family, device class); **0.35** major-version-only change | browser/client upgrade |
| **V2** | `scope_discontinuity` | network location differs from the pinned binding | **1.0** different /16; **0.45** different /24, same /16; **0.15** different address, same /24 | DHCP renewal, NAT rotation, roaming |
| **V3** | `binding_fork` | the incoming binding key is a **revisit** — it differs from the last binding and is already in the session's bounded ring | **1.0** | dual-homed client flapping |

Fixed constants: `version_severity=0.35`, `host_severity=0.15`, `subnet_severity=0.45`,
`ring_size=4`, `path_window=32`. None is fitted.

**Per-request flow.** Build binding → on first sight, pin the reference and emit a zero record
→ otherwise evaluate **only the enabled** invariants → `risk = Σ wᵢ·vᵢ` → session evidence is
the **peak** per-request risk → alert when the peak reaches τ. **Reference migration** is
**on**: the reference re-pins after a *monotone* binding change and never after a revisit. O(1)
time and space per request.

The primary experiment **must** use this frozen implementation. `V4`, `V5`, `V6` remain
implemented and appear **only** in the pre-defined ablation (§14) as rejected-invariant
analysis; they are not primary methods and may not become primary as a result of any outcome
seen here.

## 5. Calibration (frozen)

* **Benign-only.** Attacks are injected into the evaluation partition only, so the calibration
  partition is attack-free **by construction**. Asserted by
  `test_calibration_partition_contains_no_attacks`.
* **No label influence.** `sica/calibrate.py` reads no label. Asserted adversarially by
  `test_calibration_ignores_labels_entirely`: relabelling the entire calibration partition as
  attacks changes neither the weights nor the threshold.
* **No reporting-data influence.** No evaluation observation enters calibration.
* **α = 0.01**, unchanged and not to be changed after seeing any result.

**Procedure (two passes, and no more).**

1. **Probe pass** — replay calibration traffic with unit weights over **all six** invariants to
   obtain each one's benign firing mass εᵢ and applicability (so a rejected invariant's
   statistics stay observable).
2. **Applicability gate** — an invariant whose precondition holds on <1% of calibration
   requests is disabled and its weight redistributed. This is what correctly switches `V6` off
   on W2 (applicability 0.000).
3. **Weights** — `wᵢ ∝ log(1/(εᵢ + ε₀))`, `ε₀ = 0.01`, over the applicable set.
4. **Threshold pass** — replay with the deployed weights through the **same** evidence pipeline
   evaluation uses, and select τ over that statistic.

**Threshold rule, including tie handling (the corrected Part-2 procedure).** The alert rule is
`peak ≥ τ`. The risk statistic is coarse — a weighted sum of three invariants with fixed
severities — so the calibration population is **heavily tied**, and a `(1−α)` quantile lands on
a plateau that `≥` then admits in full. Only an observed value can change the alarm set, so:

> τ is the **smallest observed calibration session peak risk** for which
> `mean(peaks ≥ τ) ≤ α`. If no observed value qualifies — including when more than `α·N`
> sessions are tied at the maximum — τ is placed just above the maximum and the run alerts on
> nothing.

**Finite-sample behaviour.** Achievable alarm rates are multiples of `1/N`. W1 calibrates on
N = 127 sessions, so the only achievable non-zero rate at α = 0.01 is 1/127 ≈ 0.0079; a budget
below `1/N` is attainable only by alerting on nothing.

**The realised rate is reported, never assumed.** Every run records
`calibration_alarm_rate`, and `pipeline/validate.py` asserts `≤ α` across all runs. The
evaluation-side FPR is a separate measured quantity and is **not** guaranteed to equal α: the
guarantee is in-sample on calibration, and transfer is an empirical result to be reported as
measured.

## 6. Seed policy (frozen)

| Purpose | Seeds |
|---|---|
| **Development** — debugging, sanity checks, every design decision already made | **100–119** |
| **Reporting** — E1 main, E2 baselines | **0–29** |
| **Reporting** — E1b false-alarm-budget sweep | **0–14** |
| **Reporting** — E3/E4/E5 | **0–19** |
| Bootstrap resampling | seed 0, 10,000 resamples |
| **E6 efficiency** | none — deterministic replay, no injection draw |

*The E1b row was added during the Part-4B preflight.* The α-sweep is implemented as
`SEEDS[:15]` in `pipeline/exp02_main.py` and therefore runs on seeds 0–14, not the 30 used by
E1 proper. This was undocumented before preflight. It is a **prefix of the reporting block**,
so no development seed is involved and no seed is cherry-picked; the only consequence is a
wider confidence interval on the sweep than on the main result, and `n_runs` makes that
visible in the output. The experiment definition was **not** changed to match the document —
the document was corrected to match the implementation, because the contract's purpose is to
record what will actually run.

Disjointness is asserted mechanically (`pipeline/validate.py`, and the leakage report).

**Rules.** Reporting seeds are strictly held out from tuning. No seed may be changed after
reporting results are seen. No favourable subset may be selected. **All** reporting seeds are
reported, including unfavourable ones. Development seeds may be used freely for debugging and
for any further sanity check, and any such use must be labelled a diagnostic, not a result.

## 7. Data splits — documented exactly as implemented

`sica/harness.split_sessions`. The reported split is **temporal 50/50**: sessions are sorted by
first-request timestamp and cut at `calibration_share = 0.5`; the earliest half calibrates, the
latest half is evaluated.

| | W1_web | W2_apt |
|---|---|---|
| Calibration sessions | 127 | 1,563 |
| Evaluation sessions | 127 | 1,563 |

**A property that must be stated, because it changes how the intervals are read.** Under
`split='temporal'` the partition uses **no randomness**: it is a deterministic sort and cut.
Verified — the calibration and evaluation session sets are byte-identical across seeds 0, 1, 29,
100 and 119. The seed therefore varies **only** the churn draws, which sessions are targeted,
which donor supplies each attacker's content, the theft point, and which victim requests are
displaced. Consequently:

* Reported variance across the 30 reporting seeds is **injection and churn variance, not split
  variance**.
* Sensitivity to the split choice is a **separate** measurement (E5c, §16), which reports
  temporal, client-disjoint and random splits.
* **There is no separate development data partition.** Development is a *seed block*, not a
  held-out corpus: development seeds draw different injections over the *same* benign sessions
  that reporting seeds use. See §22 for the limitation this implies.

**Contamination controls, all verified in Part 3.5 at seed 0 on both workloads:** 0 shared
session identifiers between partitions; 0 attack-labelled sessions in calibration; 0 injected
requests in calibration; 0 shared benign requests `(ip, ua, ts, path)` across partitions.

**Donor/victim relationship — a documented, deliberate coupling.** The donor pool is built from
the evaluation partition, so a session may be both a victim and a source of content for another
victim (18 of 127 on W1; 322 of 1,563 on W2 at seed 0). This leaks no label — only request
content is copied and the donor's own label is unaffected — and it is exactly what makes
attacker content statistically inseparable from benign content. It is reported, not removed.

## 8. Attack injection (frozen)

For every injected attack, the construction fixes:

| Element | Rule |
|---|---|
| **Victim session** | drawn from the evaluation partition; each session targeted independently with probability `attack_rate = 0.20` |
| **Theft point** | `cut` drawn uniformly from `[earliest_takeover·n, latest_takeover·n]` = `[0.25n, 0.50n]`, and **never moved thereafter** |
| **Donor** | a *different* real client of the same server, satisfying the level's constraints and long enough to supply the required run |
| **Attacker content** | real requests taken **verbatim** from the donor — path, status, bytes, referrer unchanged. Nothing is fabricated |
| **Attacker binding** | per masquerade level (§9), defined relative to the victim's binding **at the theft point** |
| **Request ordering** | merged by timestamp, stable sort |
| **Injection location** | *takeover*: the attacker replaces the entire remaining tail. *concurrent*: `k` post-theft victim requests are displaced, and the **final** request is never displaced |
| **Length matching** | exact — an injected session keeps the victim's original request count |
| **Scenario label** | `"{level}_{mode}"`, e.g. `L3_concurrent` |
| **Evaluation label** | `Session.label = 1`; `Request.injected = 1` on each attacker request |

**The detector receives none of:** attack label, scenario label, donor identity, injection
marker, or any future information. `ContinuityMonitor.observe` accepts exactly
`(session_id, ip, user_agent, ts, path, referrer)`. Labels are read at one point only — metric
computation, after every decision exists.

**Unrealisable conditions are refused and counted**, never silently substituted. Reasons:
`session_too_short_for_theft_window`, `theft_window_leaves_too_little_tail`,
`no_admissible_donor`, `donor_too_short_for_takeover_tail`, `no_attacker_request_survived`.
`inject_mixture` returns `refusal_reasons`, `refused_per_scenario` and the requested
`theft_window`, so the **effective** experimental condition is always reportable. At seed 0:
18/20 injected on W1, 322/330 on W2, all refusals being short sessions.

**Part-3.5 correction concerning theft delay — stated explicitly as required.** The attacker's
first request is anchored at `victim.requests[cut].ts + delay`. In *concurrent* mode the delay
is now **clamped to 5% of the victim's remaining window** whenever that window is positive,
independently of the gap-span compression that was already applied. Before this correction, a
delay larger than the victim's remaining window placed the attacker's first request after the
victim's session had already ended, so every surviving victim request preceded the attacker's
and the session was a **takeover carrying a `concurrent` label**. Because no session in this
corpus exceeds 59 s while E4 sweeps the delay to 60 s and 600 s, this was not hypothetical:
only **34.2%** of "concurrent" injections still interleaved at those levels. After the fix,
100% interleave at every swept delay, guarded by
`test_concurrent_interleaves_at_every_swept_theft_delay`.

**No temporal realism is claimed.** Attacker inter-arrival gaps are the donor's own gaps,
compressed to fit the victim's window — and the donor's gaps are themselves artifacts of the
degenerate upstream timestamps (§12). The injection's *timing* is therefore not offered as
realistic; only its *content* and its *binding structure* are.

## 9. Scenarios — frozen L0–L5, as implemented

The taxonomy is **not redesigned**. Levels vary how much of the victim's binding the attacker
reproduces; modes vary whether the victim keeps using the session.

| Level | Attacker address | Attacker agent | Address relation to victim | Agent relation | Expected invariant visibility |
|---|---|---|---|---|---|
| **L0** | donor's own | donor's own | different /16 | different | V2 at 1.0; V1 usually fires; V3 in concurrent |
| **L1** | donor's own | **victim's (cloned)** | different /16 | identical | V2 at 1.0; **V1 silent**; V3 in concurrent |
| **L2** | synthetic, victim's /16, different /24 | donor's own | same /16, different /24 | different | V2 at 0.45; V1 usually fires; V3 in concurrent |
| **L3** | synthetic, victim's /24, different host | **victim's (cloned)** | same /24, different host | identical | **V2 at only 0.15**; V1 silent; V3 in concurrent — the hardest address-visible cell |
| **L4** | **the victim's own** | **victim's (cloned)** | identical | identical | **No binding signal exists at all** |
| **L5** | **the victim's own** | donor's own | identical | different | **No address signal**; V1 is the only evidence |

Modes: **takeover** (victim silent after the theft) and **concurrent** (victim keeps browsing;
the final request is never displaced). Reported envelope = 6 levels × 2 modes = **12 cells per
workload**.

**Why the taxonomy is scientifically useful.** L0→L3 is a monotone ladder of attacker capability
against address evidence, so the detectability envelope can be read off directly. L1 vs L0
isolates the value of agent evidence at constant address evidence. **L1_concurrent vs
L1_takeover** is the cleanest single contrast in the study: identical attacker capability, the
only difference being whether the victim keeps browsing — so any performance gap is attributable
to the monotone/interleaved asymmetry that V3 and reference migration exist to exploit.

**L4 and L5 must remain, and this is the reason.** Every one of L0–L3 gives the attacker a
*different address*, so a rule that alerts on any address change detects all of them **by
construction** — `pin_ip` measured recall of exactly **1.0000** before these cells were included.
Restricting the envelope to L0–L3 reduces the benchmark to address-change detection and makes
the recall axis of the baseline comparison carry no information. **L4** is the co-located
attacker with a cloned agent: invisible to *every* binding-based signal, and reported as the
acknowledged blind spot rather than quietly excluded. **L5** is the co-located attacker on a
different client program: no address signal whatsoever, but agent continuity breaks — the case
that most directly separates *hijack detection* from *address-change detection*. Together with
the benign churn model (which supplies benign sessions that **do** change address), neither the
presence nor the absence of an address change determines the label.

## 10. Primary metrics

All are session-level. For each, report **mean, standard deviation, 95% confidence interval,
and the number of reporting seeds**.

| Metric | Definition | Applies to |
|---|---|---|
| **ROC AUC** | rank-based with **mid-rank tie correction**, over session peak risk | SICA and scored baselines only |
| **PR AUC** (average precision) | tie groups collapsed to a single operating point | SICA and scored baselines only |
| **Recall** | TP / (TP + FN), sessions | all detectors |
| **FPR** | FP / (FP + TN), sessions | all detectors |
| **Precision** | TP / (TP + FP) | all detectors |
| **F1** | harmonic mean of precision and recall | all detectors |
| Specificity, balanced accuracy | reported alongside | all detectors |

**ROC AUC is not the headline metric on its own.** This is a security-detection problem, so
**FPR and recall are jointly decisive**: a detector that ranks well but cannot be operated at a
tolerable alarm rate is not deployable, and a detector with high recall at 15% FPR is not
either. Every comparison must present recall **and** the FPR at which it was obtained. Where a
single summary is needed, ROC AUC is used because it is the only metric here not determined by
the operating point — and that choice is stated, not implied.

Secondary, reported but not headline: attacker-request detection rate; per-scenario breakdown;
false alarms attributed to each benign churn class.

## 11. Detection latency

**Wall-clock detection latency in seconds is NOT reported.** The frozen dataset cannot support
it: the minute field of both source logs is degenerate, so all inter-arrival times are generator
artifacts (§12). `latency_seconds_median` is still computed by the implementation and is marked
in `sica/metrics.py` as not reportable; it must not appear in any table, figure or claim.

**Request-based detection delay is reported**, and is defined precisely as implemented in
`sica/metrics.evaluate_sessions`:

> For an attack session that is detected, let `first` be the index of the first injected
> request and `fired` the index of the first request at or after `first` whose evidence reaches
> τ. The detection delay is the **number of attacker requests in `[first, fired]`**, floored at
> 1. Sessions never detected contribute no value.

Reported as `latency_requests_median`, `_mean`, `_p90`. This is a **count**, not a clock
reading, and is unaffected by the timestamp degeneracy.

**Never to be conflated:** *detection delay* (how many attacker requests elapse before the
alert — a detection-quality property) and *detector computation time* (§17 — how long the
detector takes to process a request, a performance property). They are measured in different
experiments, carry different units, and may not be presented in the same column.

## 12. Timestamp limitation (binding constraint on every experiment)

Verified in Part 3.5: the minute field is `05` in **all 10,000** W1 records and `05`/`06` in W2.
Consequently no sessionised session exceeds **59 seconds**, none crosses a day boundary, and the
1800 s idle timeout, cross-day handling and maximum-duration logic are all **unexercised**.

Binding consequences: no claim about realistic temporal behaviour; timestamp distributions may
not be cited as evidence of realistic user behaviour; no latency-in-seconds result; `V5` may not
be a primary invariant; `V4` cannot be assessed here at all. **The detector is unaffected** —
V1, V2 and V3 consume no timestamp, gap or duration, verified mechanically.

## 13. Baselines

All are non-ML deterministic rules, evaluated on **identical evaluation sessions with identical
labels** in the same run as SICA.

**Pinning rules — binary, parameter-free** (`score_resolution = "binary"`): `pin_ip`,
`pin_prefix24`, `pin_scope16`, `pin_useragent`, `pin_useragent_core`, `pin_ip_or_useragent`,
`pin_ip_and_useragent`. Each alerts iff the pinned quantity changes anywhere in the session.

**Scored rules — continuous** (`score_resolution = "continuous"`), calibrated to the **same**
budget by the **same** procedure on the **same** calibration partition:
`score_distinct_bindings`, `score_max_request_rate`, `score_burstiness`.

**Reporting treatment of binary baselines (frozen).** A parameter-free rule emits a decision,
not a score: one operating point, no ranking. Its ROC AUC collapses *identically* to
`(TPR + TNR)/2` — asserted by `test_binary_rule_auc_is_exactly_balanced_accuracy`. Therefore:

* **No continuous score is fabricated for them.** None exists.
* **ROC AUC and PR AUC are withheld (`NaN`)** for every pinning rule and must render as N/A,
  never as a number.
* Their comparison is carried by **recall, FPR, precision, F1 and balanced accuracy**.
* `validate.py` asserts both halves of this.

**Documented unavoidable differences.** (i) Pinning rules cannot be calibrated to a budget —
their FPR is whatever the traffic makes it. That is the operational complaint against them and
is reported, not corrected. (ii) Pinning rules are evaluated retrospectively over the whole
session, whereas SICA decides online per request; both yield a session-level decision, so the
session-level comparison is like-for-like, but the *online* property is SICA's alone and is not
credited to it in any metric. (iii) `pin_useragent_core` reads exactly the agent core `V1`
reads, through a shared helper, so that comparison measures the rule and not the parser.

## 14. Ablation (frozen — `pipeline/exp03_ablation.py`, seeds 0–19)

Every variant is independently re-weighted and re-thresholded by the same calibration
procedure, so each comparison is between two fully calibrated detectors, not between a detector
and a de-tuned copy of itself.

The seven combinations required by the contract are **all covered** by the implemented families:

| Required combination | Implemented as | Family |
|---|---|---|
| V1 alone | `only_V1_agent_mutation` | `single` |
| V2 alone | `only_V2_scope_discontinuity` | `single` |
| V3 alone | `only_V3_binding_fork` | `single` |
| V1+V2 | `minus_V3_binding_fork` | `leave_one_out` |
| V1+V3 | `minus_V2_scope_discontinuity` | `leave_one_out` |
| V2+V3 | `minus_V1_agent_mutation` | `leave_one_out` |
| V1+V2+V3 | `full` | `reference` |

Additional pre-registered families, reported as **secondary / rejected-invariant analysis** and
explicitly **not** candidate primary methods:

* `restored`: `plus_V4`, `plus_V5`, `plus_V6`, and `plus_all_rejected` — each rejected invariant
  added back to the retained set, so the rejection is auditable rather than asserted.
  `single` also covers `only_V4`, `only_V5`, `only_V6` where applicable.
* `weighting`: benign-rarity surprisal vs the uniform control.
* `design`: reference migration off; evidence = accumulator instead of peak.

**No invariant may be selected or reinstated on the basis of reporting-seed performance.** The
set was fixed on development seeds 100–119 under a pre-declared threshold-free criterion, and
`docs/ARCHITECTURE_FREEZE.md` §2 records exactly what that criterion resolved to, including the
W2 statistical tie and the F1 cost of retaining V3.

## 15. Robustness (frozen — `pipeline/exp04_robustness.py`, seeds 0–19)

| Dimension | Independent variable | Levels | Seeds | Hypothesis | Metrics |
|---|---|---|---|---|---|
| **Masquerade × concurrency** | scenario cell | 6 levels × 2 modes | 0–19 | Detection degrades monotonically L0→L3; L4 is undetectable; L5 detectable by V1 alone; concurrent > takeover at matched level | recall, precision, F1, FPR, ROC AUC, attacker-request detection rate, request latency |
| **Benign roaming (monotone)** | `monotone_rate` | 0.0, 0.05, 0.15, 0.30, 0.50 | 0–19 | FPR rises slowly; SICA degrades more gracefully than address pinning | FPR, recall, F1, ROC AUC |
| **Benign flapping** | `flapping_rate` | 0.0, 0.01, 0.02, 0.05, 0.10, 0.20 | 0–19 | FPR rises fastest here, because flapping is the one benign phenomenon that mimics a live hijack (it triggers V3) | FPR, recall, F1, ROC AUC |
| **Attacker volume** | `attack_fraction` | 0.05, 0.10, 0.20, 0.40, 0.60 | 0–19 | Recall rises with attacker share; small shares are the hard case | recall, F1, ROC AUC |
| **Attack prevalence** | `attack_rate` | 0.02, 0.05, 0.10, 0.20, 0.35 | 0–19 | Ranking metrics stable; precision falls as prevalence falls | precision, recall, ROC AUC, PR AUC |
| **Takeover timing (position)** | `theft_position` | (0.10,0.20), (0.25,0.50), (0.50,0.70), (0.70,0.85) | 0–19 | Later theft leaves less attacker traffic, lowering recall | recall, F1, request latency |
| **Session-length floor** | `min_requests` | 7, 10, 15, 20 | 0–19 | Longer sessions are easier; guards against the floor driving the result | recall, FPR, ROC AUC |
| **Address-churn crossover** | benign churn vs `pin_ip` | see E4c | 0–19 | Identifies the churn level beyond which address pinning is unusable while SICA remains operable | FPR, F1 |
| **Takeover timing (delay)** | `theft_delay_s` | 0, 1, 60, 600 s | 0–19 | **See classification below** | — |

### `theft_delay_s` classification: **INERT / UNREPORTABLE**

Determined from the actual implementation against the frozen dataset, not assumed.

*Evidence.* No session in either corpus exceeds 59 s (§12), so a 60 s or 600 s delay is not
expressible in this data. In concurrent mode the Part-3.5 correction clamps the delay inside the
victim's remaining window so the scenario stays concurrent; in takeover mode the victim is
already silent, and no retained invariant reads a timestamp. Measured after the correction on
W1, seeds 0–2: recall, ROC AUC and FPR are **identical to six decimal places at all four
levels**.

*Classification.* **INERT / UNREPORTABLE.** The parameter cannot vary anything observable on
this corpus.

*What it measured before the correction.* Not delay, but the silent degeneration of concurrent
hijacks into takeovers — 34.2% interleaving at 60 s and 600 s. The apparent effect was an
artifact of a construction bug, which is exactly why it must not be reported as a robustness
result.

*Disposition.* **Not deleted.** It is retained in the sweep so that its inertness is itself a
generated, checkable result, and it will be reported as inert with this explanation. It must
**not** be presented as evidence of robustness to attacker timing, and no tuning may be done
around it. A decision to drop it from E4 entirely is deferred to review (§22).

## 16. Leakage controls (frozen — `pipeline/exp05_leakage.py`, seeds 0–19)

Purpose: determine whether the benchmark contains a **shortcut easier than session continuity**.
These are diagnostics of the *benchmark*, not detector features, and none is added to the
detector under any outcome.

* **E5a — marginal single-feature audit.** Session-level ROC AUC of each of: `n_requests`,
  `duration_s`, `total_bytes`, `mean_bytes`, `distinct_paths`, `median_gap_s`, `min_gap_s`,
  `error_rate`. A feature far from chance indicates a shortcut.
* **E5b — content-reference detector.** An ML-free Mahalanobis detector over those content
  features, answering "what could a purely feature-based detector achieve here?"
* **E5c — split sensitivity.** Temporal vs client-disjoint vs random splits; disagreement would
  indicate split-induced leakage.
* **E5d — structural checks** (26, machine-readable to `results/metadata/leakage_report.json`):
  session-id uniqueness, calibration/evaluation disjointness, calibration attack-freeness,
  injected-session length matching, client-disjoint isolation, dev/reporting seed disjointness,
  and the check that **the final invariant set consumes no timing or volume feature**.

**Already-known shortcuts, pre-registered so they cannot be presented as discoveries later:**
`distinct_paths` reaches ROC AUC ≈ **0.733** on W2 and the content-reference detector ≈ **0.731**
— both artifacts of W2's three-path universe; `median_gap_s` reaches ≈ **0.322** on W1, an
artifact of gap compression over degenerate timestamps. Neither is removed (a feature is not
deleted for making the detector look good), and neither is legitimate hijacking signal, so
neither is added. What matters, and what is asserted structurally, is that **neither can reach
the detector**: V1, V2 and V3 read no path count, gap, byte count, request count or duration.

Additional identity controls, expected to be non-separable and reported as such: source/workload
identity (workloads are never mixed), missing-value pattern, status-code pattern, session
identifier (a deterministic digest), donor identity and scenario identity (never exposed).

## 17. Efficiency (frozen — `pipeline/exp06_efficiency.py`)

Measures **detector computation only**, on this machine. The old placeholder runtime benchmark
is not reused; the current implementation separates the two things that benchmark conflated.

| Quantity | Method |
|---|---|
| Requests processed | count of the replayed event stream |
| Total runtime / throughput (req/s) | **uninstrumented** loop-level timing, median of repeated runs, min and max also recorded |
| Per-request runtime (µs) | derived from the uninstrumented total |
| **p50 / p95 / p99 / max latency** | **instrumented** per-call timing — reported separately because the timer's own overhead is charged to it |
| State growth | measured resident bytes per live session, reported beside the analytic design bound |
| Scaling | per-request cost across 5%→100% of live sessions, to test the O(1) claim empirically |
| Preparation cost | log parsing and sessionisation timed **separately**, so they are not charged to the detector |
| Environment | Python version/implementation, platform, numpy/pandas versions captured to `results/metadata/e6_environment.json` |

**No wall-clock network, server or real-world detection-delay claim** may be derived from this
experiment. Absolute microsecond figures are hardware-dependent; the reproducible claim is the
*shape* — flat per-request cost as live sessions grow.

## 18. Statistics (pre-registered, before any result is seen)

* **Aggregation.** Each seed is one independent draw of the benchmark construction. Report
  **mean ± SD** over seeds, and `n_runs`.
* **95% confidence interval.** Percentile **bootstrap** over the per-seed values, **10,000
  resamples, seed 0** (`sica.metrics.bootstrap_ci`). Non-finite values are dropped before
  resampling; an empty set yields NaN rather than a fabricated interval.
* **Paired comparisons.** Every detector sees identical sessions within a seed, so comparisons
  are **paired by seed**. Test: **Wilcoxon signed-rank** (per-draw differences are not assumed
  normal). Family-wise correction across the comparisons against the proposed method:
  **Holm step-down**. Effect size reported as the **median paired difference**, because a
  p-value on 20–30 paired draws says a difference is stable, not that it matters.
* **Significance threshold.** α_stat = **0.05** on Holm-adjusted p-values. Fixed now.
* **The test is chosen now and does not change.** No alternative test may be substituted after
  seeing which one yields significance.
* **Ties.** ROC AUC uses mid-rank tie correction; average precision collapses tie groups to a
  single operating point. Wilcoxon zero-differences are handled by SciPy's default
  (`zero_method='wilcox'`).
* **NaN / inapplicable.** Metrics that do not exist for a detector (ranking metrics for binary
  rules, §13) stay **NaN** and render as N/A. They are never imputed, zero-filled or silently
  dropped from a mean. `summarise` drops non-finite values before aggregating and reports
  `n_runs`, so a partially-NaN column is visible as a reduced count rather than a distorted
  mean.
* **Base rates.** Because 20% prevalence does not transfer to deployment, precision and daily
  alert volume are recomputed from measured TPR/FPR across prevalences
  10⁻⁵, 10⁻⁴, 10⁻³, 10⁻², 5×10⁻², 2×10⁻¹.

## 19. Result reporting rules (frozen)

1. Report **all** reporting seeds.
2. **Never** remove an unfavourable seed.
3. **Never** tune after seeing reporting results.
4. **Never** manually edit a CSV result file.
5. **Never** type an experimental number into a table by hand.
6. Every reported number must trace to a generated result file.
7. Every figure must trace to generated data.
8. Binary baselines remain binary — no fabricated scores, no ranking metrics.
9. Missing or inapplicable metrics remain **NaN** or explicitly **N/A**.
10. Unexpected results are **investigated**, not hidden.
11. Scientifically valid negative results **are reported**.
12. **No post-hoc architecture change** after seeing results.

Rules 5–7 are enforced mechanically: `pipeline/make_tables.py` writes every table body and every
inline value as a LaTeX macro from the result CSVs, and `pipeline/validate.py` checks that every
macro the manuscript references is generated and that table bodies match their column counts.

## 20. Execution order

The repository's own numbering is authoritative; the contract's logical stages map onto it as
follows. Order is the dependency order enforced by `run_all.sh`.

| # | Stage (repo) | Script | Produces | Depends on |
|---|---|---|---|---|
| 0 | preflight | `run_all.sh` | Python ≥3.10, modules, input logs present | — |
| 1 | tests | `pytest -q` | must pass before any result is generated | — |
| 2 | **E0 corpus** | `exp01_corpus.py` | corpus audit, sessionisation sensitivity, agent mix | logs |
| 3 | **E1 main + E2 baselines** | `exp02_main.py` | primary benchmark, budget sweep, baseline comparison | E0 |
| 4 | **E3 ablation** | `exp03_ablation.py` | §14 | — |
| 5 | **E5 leakage** | `exp05_leakage.py` | §16 + `leakage_report.json` | — |
| 6 | **E6 efficiency** | `exp06_efficiency.py` | §17 | — |
| 7 | **E4 robustness** | `exp04_robustness.py` | §15 (longest stage) | — |
| 8 | **E7 statistics** | `exp07_stats.py` | §18, base rates | E2, E3 per-run CSVs |
| 9 | tables | `make_tables.py` | `paper/tables/*.tex` | E0–E7 |
| 10 | figures | `exp08_figures.py` | `results/figures/*` | E1, E3, E4 |
| 11 | **validation** | `validate.py` | consistency assertions; gate on `PIPELINE_DONE` | all |

`results/PIPELINE_DONE` is written only if every stage succeeds; `results/PIPELINE_ERR` names
the failed stage otherwise. Development studies (`dev_design.py`, `dev_invariants.py`) are
**not** part of a reporting run and execute only under `--dev`.

## 21. Reproducibility

| Item | Value |
|---|---|
| Python | **3.11.15** (contract requires ≥3.10) |
| Platform | `Linux-6.18.44-fc-v24-x86_64-with-glibc2.39` |
| numpy | **2.4.4** |
| pandas | **3.0.2** |
| scipy | **1.17.1** (E7 only) |
| matplotlib | **3.10.9** (figures only) |
| Declared minimums | `requirements.txt` |
| Configuration | `config.yaml`; frozen constants in `pipeline/common.py` |
| Dataset hashes | `f15c31e9…0364ef` (W1), `52683243…6937df` (W2) — §3 |
| Source version | **No git repository exists**; there is no commit to record. Recorded as UNKNOWN rather than invented |
| Environment capture | `results/metadata/e6_environment.json`, written automatically by E6 |

**Exact commands.**

```bash
python3 -m pytest -q                 # must pass first
./run_all.sh                         # full reporting run (~45 min, 1 core)
./run_all.sh --quick                 # smoke test; skips E4; NOT a reporting run
python3 pipeline/validate.py         # re-runnable at any time
```

**Determinism.** Every stochastic choice derives from `numpy.random.default_rng(seed)`. Session
identifiers use BLAKE2s and are byte-identical across processes. Bit-identical *per-seed*
reproduction additionally requires the same NumPy version, because `Generator` streams are
version-dependent for some distributions; aggregates across seeds are stable. Timing figures are
hardware-dependent by nature.

No git commit is created by this contract.

## 22. Pre-registered claims

### Claims this experiment is designed to test

1. A stateful, non-learning continuity monitor over three declared invariants can rank hijacked
   sessions above benign ones on real public web-log traffic with controlled injection.
2. It can be operated at a **declared** session-level false-alarm budget derived from attack-free
   traffic alone, with the realised in-sample rate reported rather than assumed.
3. Its detection is graded by attacker capability in the way the threat model predicts — the
   L0→L3 envelope — and it fails, as predicted, where no binding signal exists (L4).
4. The monotone/interleaved asymmetry is the operative mechanism: L1_concurrent vs L1_takeover
   isolates it at constant attacker capability.
5. Each retained invariant contributes, and each rejected invariant does not (§14).
6. It offers a materially different **false-alarm/recall trade-off** from deployed pinning
   rules at matched evaluation.
7. Per-request cost is O(1) in time and bounded in space, empirically.
8. The benchmark's residual shortcuts cannot reach the detector (§16).

### Claims this experiment **cannot** establish

1. **Production deployment validation.** Nothing here was deployed, or run against a live
   application, or evaluated by an operator.
2. **Real-world naturally occurring attack prevalence.** Every attack is constructed. The 20%
   benchmark prevalence is an experimental parameter and says nothing about how often session
   hijacking occurs in deployment.
3. **Realistic temporal latency.** Ruled out by the frozen dataset (§12). No wall-clock
   detection-delay claim may be made.
4. **Superiority against all session-hijacking detectors.** Only non-ML deterministic rules
   implementable on these logs are compared. No comparison is made against ML detectors,
   commercial products, token-binding schemes, or methods needing client cooperation or signals
   these logs do not carry.
5. **Generalisation to arbitrary web applications.** Two public sample logs, one of them a demo
   corpus with three URL paths, from 2015, both without authentication state. Session identity
   is *reconstructed*, not observed.
6. **That the attacks are representative of real attacker behaviour.** Attacker content is a
   different real client's traffic, which is a deliberate choice to defeat content shortcuts —
   not a model of adversary intent, tooling or targeting.
7. **Anything about encrypted, authenticated or modern-protocol traffic.**
8. **That W2 represents package-mirror traffic.** It is sample/demo data.

## 23. Contract consistency check

Checked against `docs/DATASET_FREEZE.md`, `docs/DATASET_VERIFICATION.md`,
`docs/ARCHITECTURE_FREEZE.md`, `docs/REPRODUCIBILITY_FREEZE.md` and `CHECKPOINT.md`.

**No contradictions found.** Points verified rather than assumed:

* Invariant set, severities, calibration protocol, seeds and α match `ARCHITECTURE_FREEZE.md`
  §§2–5 and `CHECKPOINT.md` §§2–5.
* Threshold rule, tie handling and the finite-sample note match `ARCHITECTURE_FREEZE.md` §6 and
  `REPRODUCIBILITY_FREEZE.md` §4.
* Level set L0–L5, modes, refusal semantics and the theft-delay clamp match
  `ARCHITECTURE_FREEZE.md` §8, `REPRODUCIBILITY_FREEZE.md` §2 and `DATASET_VERIFICATION.md` §13.
* Corpus counts, licensing, privacy status, the timestamp limitation and the frozen terminology
  match `DATASET_FREEZE.md` §§1–11.
* Binary-baseline reporting matches `REPRODUCIBILITY_FREEZE.md` §4.
* Metric definitions (tie-corrected ROC AUC and average precision) match
  `REPRODUCIBILITY_FREEZE.md` §4.

Two items are **clarified here for the first time** and are additions rather than conflicts,
because no prior document stated them:

1. **The temporal split is not reseeded** (§7) — the calibration/evaluation partition is
   identical across all seeds, so reported variance is injection and churn variance only.
2. **Development is a seed block, not a data partition** (§7) — development seeds draw
   different injections over the *same* benign sessions that reporting seeds use.

Both are recorded as limitations in §24 rather than resolved by changing anything frozen.

## 24. Decisions requiring review before Part 4B

1. **`theft_delay_s` is inert** (§15). Retained and to be reported as inert. A decision to drop
   it from E4 is deferred to review.
2. **Seed separation does not separate the benign corpus** (§7). Development and reporting seeds
   share the same benign sessions and the same temporal split; only the injection and churn
   draws differ. Design decisions made on development seeds therefore saw the same underlying
   benign population that reporting seeds use. This is a real limitation, is not fixable without
   changing the frozen split, and must be stated in the manuscript's limitations rather than
   glossed. Mitigations already in place: the invariant set was chosen on a threshold-free
   criterion, and E5c reports split sensitivity.
3. **`paper/paper.tex` still carries the superseded `v5` rationale** (line ~304) and has not
   adopted the frozen terminology (`DATASET_FREEZE.md` §10) or the timing restrictions (§11).
   Blocks publication, not experimentation.
4. **No git repository exists**, so no source-code commit can be recorded against this run
   (§21). If provenance of the code version matters for the record, a repository must be
   initialised before the reporting run; this contract does not create one.

5. ~~**`results/` holds 34 stale CSVs from the abandoned pre-fix run.**~~ **RESOLVED
   2026-09-12.** All 46 files of the abandoned 2026-09-05 run were archived intact to
   `results_archive/2026-09-05_prefix_abandoned/` with a pre-move SHA-256 manifest
   (`MANIFEST.sha256.txt`, all 46 re-verified after the move) and a provenance note
   (`PROVENANCE.md`) recording why the results are void, which audit findings were measured
   from them, and the rule that no pipeline stage may read them. `results/` now contains four
   empty directories and no files, so the reporting run starts from a clean output tree.
   Nothing was deleted.

   The underlying weakness remains and is recorded for a future decision: `run_all.sh` clears
   only the two marker files, and `validate.py` checks artifact *existence*, not freshness. A
   partial run over a non-empty `results/` could still produce a silent mixture. Making
   `run_all.sh` refuse to start unless `results/tables` is empty would close this
   structurally; it is a code change and has not been made.
