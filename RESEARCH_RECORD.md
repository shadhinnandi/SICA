# Research Record — SICA

A single-page provenance record: what this project is, what state it is in, and
where the evidence for every claim lives. Written 2026-09-13.

Every number below is transcribed from a generated artifact, with the artifact
named. Nothing here is typed from memory or estimated.

---

## 1. Project

**SICA — Session-continuity Invariant Analysis.** A lightweight, explainable,
**non-machine-learning** detector for **intra-session web session hijacking**,
evaluated on real public web-log traffic with controlled hijacking injection.

**Research question.** Can intra-session hijacking be detected server-side, at
constant cost per request, by checking a small set of declared continuity
invariants against bounded per-session state — without any machine learning and
without any attack-labelled training data?

The question is scoped to session hijacking. It is **not** generic anomaly
detection, intrusion detection, account takeover, login-anomaly detection, or
malicious-payload detection.

## 2. Threat model

An adversary has obtained a valid, already-authenticated session identifier by a
means outside the model (XSS, network capture, log leakage, malware) and replays
it against the same server. The victim may fall silent (**takeover**) or keep
browsing (**concurrent**). The defender sees only what a web server logs —
address, User-Agent, timestamp, path, referrer, status, bytes. No TLS
fingerprint, no client-side JavaScript, no token binding, no client cooperation.

Detection target: the continuity/binding inconsistency the replay produces
*inside a live session*. Unit of analysis: the request, evaluated statefully.
Unit of decision and reporting: the session.

Full statement: `docs/EXPERIMENT_CONTRACT.md` §2.

## 3. Detector — status: **FROZEN**

```
DEFAULT_INVARIANTS = ("V1_agent_mutation", "V2_scope_discontinuity", "V3_binding_fork")
```

| | Fires on | Grading |
|---|---|---|
| **V1** agent mutation | client software identity differs from the pinned binding | 1.0 core change; 0.35 version-only |
| **V2** scope discontinuity | network location differs from the pinned binding | 1.0 new /16; 0.45 new /24; 0.15 new host |
| **V3** binding fork | binding *revisit* — interleaving, not a monotone move | 1.0 |

Reference migration is **on**: the reference re-pins after a monotone binding
change and never after a revisit. Session evidence is the **peak** per-request
risk. Work is O(1) per request in time and space. `V4`, `V5`, `V6` remain
implemented and appear only in the E3 ablation as rejected-invariant analysis.

The set was selected on development seeds 100–119 under a pre-declared
threshold-free criterion (ROC AUC, required to agree across both workloads).
Locked state: `docs/ARCHITECTURE_FREEZE.md` §2.

## 4. Frozen datasets

| ID | Role | Path | SHA-256 | Raw requests | Sessions (≥7 req) | Retained requests |
|---|---|---|---|---|---|---|
| W1 | primary | `data/raw/apache_sample_1.log` | `f15c31e9…0364ef` | 10,000 | 254 | 3,874 |
| W2 | secondary | `data/raw/nginx_real.log` | `52683243…6937df` | 51,462 | 3,126 | 43,307 |

Temporal 50/50 split → W1 **127 + 127** sessions, W2 **1,563 + 1,563**.

Both are public sample logs from the **Elastic Examples** repository
(Apache-2.0), verified byte-identical to upstream; only the file names differ.
**W2 is demo/sample data, not production traffic** — three placeholder URL paths,
65.8% 404s. Provenance and licence: `docs/DATASET_FREEZE.md`,
`CITATION_OF_INPUTS.txt`.

## 5. Experiment configuration

| | |
|---|---|
| α (session-level false-alarm budget) | **0.01** |
| Threshold rule | smallest observed calibration peak risk whose in-sample alarm rate ≤ α (not a quantile) |
| Sessionisation | group by (address, User-Agent); 1800 s idle; ≥7 requests |
| Attack rate | 0.20 of evaluation sessions |
| Attack fraction | 0.40 (concurrent mode only) |
| Theft window | 0.25–0.50 of session length, never moved once drawn |
| Masquerade levels | **L0–L5** (L0–L3 address-visible; **L4, L5 co-located**) |
| Modes | takeover, concurrent — 24 grid cells |
| Benign churn | monotone 0.15, flapping 0.05 |
| Splits | temporal (reported); client-disjoint and random as leakage controls |

Executable source of truth: `pipeline/common.py` and the component defaults in
`sica/`. `config.yaml` is a descriptive mirror that **no code loads**.

## 6. Seed blocks

| Purpose | Seeds |
|---|---|
| E1 main, E2 baselines | 0–29 |
| E1b budget sweep | 0–14 (`SEEDS[:15]`) |
| E3, E4, E5 | 0–19 |
| E6 efficiency | none — deterministic replay |
| Development decisions | 100–119 |
| Bootstrap | seed 0, 10,000 resamples |

Reporting and development blocks are disjoint; `validate.py` asserts it. Under
the reported temporal split the partition is deterministic and **not reseeded**,
so reported variance is injection/churn variance, not split variance.

## 7. Current final results

**Location: `results/`.** Read from `results/tables/e1_main_summary.csv`:

| Workload | seeds | ROC AUC [95% CI] | Recall | FPR | Precision | F₁ | PR AUC |
|---|---|---|---|---|---|---|---|
| W1_web | 30 | **0.8836** [0.8665, 0.8995] | 0.3579 | **0.0085** | 0.9064 | 0.4968 | 0.7419 |
| W2_apt | 30 | **0.8510** [0.8475, 0.8547] | 0.2291 | **0.0056** | 0.9201 | 0.3623 | 0.6666 |

Supporting facts, each from its artifact:

* Worst calibration alarm rate across all 60 runs: **0.0096** ≤ α
  (`e1_calibration_runs.csv`).
* `pin_ip` recall **0.7107 / 0.6955** at FPR **0.1526 / 0.1505** — no longer
  perfect by construction (`e2_baselines.csv`). Binary baselines carry no ranking
  metric.
* Leakage audit: **26 structural checks passed, 0 failed**
  (`results/metadata/leakage_report.json`).
* Efficiency: **58,808 / 52,007** requests/s, median per-request latency
  **15.9 / 17.1 µs**, p99 **48.2 / 52.1 µs** (`e6_efficiency.csv`) — this is
  *computational* cost, not detection delay.

Inventory: 39 result CSVs, 3 metadata JSONs, 6 figures (PDF + PNG), 12 generated
LaTeX tables with 94 macros.

## 8. Validation status

**`pipeline/validate.py`: 70 passed, 0 failed** (`results/logs/validate.log`).
**Test suite: 50 passed, 0 failed** (24 + 26).

There is **no `results/PIPELINE_DONE` marker**, and that is deliberate: the final
three stages were run individually after a reporting-layer fix, so the marker's
precondition — one uninterrupted `run_all.sh` invocation — was not met. Creating
it by hand would have made the repository assert something untrue.
`results/RUN_STATUS.md` records exactly what happened.

## 9. Known limitations

1. **Degenerate source timestamps.** The minute field is always `05` in W1 and
   `05`/`06` in W2, so no session exceeds 59 s and all inter-arrival times are
   generator artefacts. No temporal-behaviour claim; **no detection latency in
   seconds**. The retained invariants read no clock, which is why the study
   survives this. The E4 `theft_delay_s` sweep is consequently **inert**.
2. **W2 is demo data**, not production traffic.
3. **Session identity is reconstructed, not observed** — the logs carry no
   authentication state.
4. **Attacks are constructed.** The traffic substrate is real; the hijacking is
   controlled injection. No real-world prevalence claim follows.
5. **L4 is undetectable in principle** — a co-located attacker cloning the agent
   presents an identical binding. It is inside the reported envelope so this is
   visible rather than hidden.
6. **W1 is small** (254 sessions); its intervals are wide and it should not carry
   a claim alone.
7. **Two residual marginal shortcuts** are documented, not removed:
   `distinct_paths` on W2 (≈0.73 AUC) and `median_gap_s` on W1 (≈0.32). Neither
   can reach the detector.
8. **Development is a seed block, not a held-out corpus** — development seeds draw
   different injections over the same benign sessions.
9. **No git repository**, so no code commit is recorded against these results.
10. **`results/tables/e0_corpus.csv` carries a superseded W2 description string.**
    The label in `pipeline/common.py` was corrected 2026-09-13; the CSV was not
    regenerated for a cosmetic change and nothing downstream reads that column.

## 10. Archived, invalid results

**`results_archive/2026-09-05_prefix_abandoned/`** — the superseded pre-fix run
(48 files, SHA-256 manifest, provenance note). **Every number in it is void**: it
predates the threshold correction, the L4/L5 envelope, the masquerade-reference
fix, the agent-churn fix and the PR-AUC tie correction.

It is retained because the audit findings were *measured from it* — it is the
evidence base for the corrections, and `docs/ARCHITECTURE_FREEZE.md` quotes it as
the "before" column. **Do not delete, do not quote, no pipeline stage may read
it.**

## 11. Environment of record

From `results/metadata/e6_environment.json`: CPython **3.11.15**,
`Linux-6.18.44-fc-v24-x86_64-with-glibc2.39`, numpy **2.4.4**, pandas **3.0.2**.
Per-seed bit-identical reproduction requires the same NumPy version; aggregates
are stable across versions.

## 12. Current status

**Experiments complete and validated. Manuscript not finished.**

| Area | State |
|---|---|
| Detector | frozen; 50 tests green |
| Datasets | frozen; hashes verified against upstream |
| Experiments | complete; validated 70/70 |
| Results | final; archived predecessor kept as evidence |
| Documentation | current as of 2026-09-13 |
| Manuscript | draft; not finalised; literature review not yet done |
| Repository | not yet a git repository; structure not yet reorganised |
