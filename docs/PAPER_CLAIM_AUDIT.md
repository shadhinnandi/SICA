# Paper claim audit — SICA manuscript

**Date:** 2026-09-13 · **Scope:** `paper/paper.tex` only · **Experiments re-run:** none

Every claim in the manuscript was traced to current repository evidence. Nothing in
the detector, datasets, result CSVs, generated tables or generated figures was
changed. `paper/paper.tex` is the only file modified.

**Classification.** A = directly supported by frozen evidence · B = supported but
required qualification · C = unsupported or stale, removed or corrected ·
D = needs external literature verification.

**Totals: 39 issues found — 36 corrected, 2 deliberately deferred, 1 flagged for a
documentation step. A further 4 claims were checked and found already correct.**

---

## 1. Sources consulted

`docs/EXPERIMENT_CONTRACT.md`, `docs/DATASET_FREEZE.md`,
`docs/DATASET_VERIFICATION.md`, `docs/ARCHITECTURE_FREEZE.md`,
`docs/REPRODUCIBILITY_FREEZE.md`, `RESEARCH_RECORD.md`,
`docs/L5_REPORTING_FIX.md`, all 27 CSVs under `results/tables/`, the 3 metadata
JSONs, the 12 generated tables, the 6 figures, and the frozen implementation.

Two named sources do not exist and were not used:
`docs/DATASET_FORENSIC_AUDIT.md` (absent) and `docs/RESEARCH_RECORD.md` (the file
is at the repository root, not under `docs/`). The timestamp findings attributed to
the forensic audit are present in `docs/DATASET_FREEZE.md` §9.1 and were taken from
there, and independently re-verified against the raw logs for this audit.

---

## 2. Corrections, by paper location

### Masquerade levels and the envelope

| # | Location | Claim as written | Evidence | Class | Action |
|---|---|---|---|---|---|
| 1 | Contributions, item 4 | "a **five-level** masquerade ladder" | Contract §9: 6 levels; `e4_scenario_grid.csv` has 24 cells over L0–L5 | C | Corrected to six-level, naming the four address-visible and two co-located levels |
| 2 | Threat model, ladder table | Table listed **L0–L4 only** | `sica/inject.py`: `LEVELS_ALL = L0..L5` | C | `L5` row added: victim's own address, a different client program's own agent |
| 3 | Threat model | "`L0`--`L3` form the evaluated envelope" | Contract §9: reported envelope = 6 levels × 2 modes | C | Corrected: all six evaluated; L0–L3 address-visible, L4/L5 co-located, with the reason the ladder is not truncated |
| 4 | Threat model | L4 treated as the single co-located case | Contract §9: L4 = no binding signal; L5 = no address signal, `v1` remains | C | L4 and L5 explicitly distinguished; no claim that they are equivalent |
| 5 | §Evaluation setup | "drawn uniformly from the **eight** `L0`--`L3` × {takeover, concurrent} cells" | `sica/harness.py:48` `levels = LEVELS_ALL`; `inject_mixture` builds `levels × modes` | C | Corrected to twelve `L0`--`L5` × 2 cells, noting this is why aggregate recall is far below the L0 figure |
| 6 | Fig. 3 caption | "vanishes at `L3`; `L4` … is outside the envelope of any binding-based server-side signal" | L4 recall 0.002–0.015; L5 concurrent 0.891 / 0.485 | C | Rewritten: floor at L3 and L4, shaded column is L4 (no binding signal at all), L5 equally co-located but detected — the cell showing the method is not an address-change detector |
| 7 | §Envelope prose | "`L4` is zero by construction", no mention of L5 | `e4_scenario_grid.csv` | C | L4 stated at the floor using `\recLfour…` macros; a new paragraph reports L5 with all four `\recLfive…` macros and states the claim is for the co-located *different-client* case specifically, not co-located attackers in general |
| 8 | §Discussion | "one behind the same NAT is invisible to **any** binding-based signal whatsoever" | L5 is behind the victim's own address and is detected at 0.891 (W1, concurrent) | C | Corrected: shared address **and** cloned agent (L4) is invisible; sharing the address alone is not sufficient |
| 9 | Abstract | Envelope described as falling to zero against a subnet+agent adversary, no L5 | as above | B | Retained and qualified; L5 concurrent result added via macro |

### Threshold, calibration and budget

| # | Location | Claim as written | Evidence | Class | Action |
|---|---|---|---|---|---|
| 10 | Contributions, item 2 | "a **quantile threshold** over attack-free traffic" | `sica/calibrate.py: threshold_for_budget`; `ARCHITECTURE_FREEZE` FIX 1 | C | Corrected to "discrete budgeted threshold" |
| 11 | §Calibration | "τ is the (1−α) **quantile** of session peak risk" | as above | C | Replaced with the frozen rule — smallest observed calibration peak risk whose in-sample alarm rate ≤ α — plus the reason a quantile is wrong here (peak risk is heavily tied; a quantile with `peak ≥ τ` admits a whole tie group and overshoots) |
| 12 | Contributions, item 2 | "Realised false-alarm rates **track the budget to within** 0.85% and 0.56%" | `\fprWeb`/`\fprApt` are the rates themselves, not tolerances | C | Reworded: the realised rates *are* 0.85% and 0.56%, both below a nominal 1% budget |
| 13 | §Main result | "Both realised rates sit **close to** the nominal 1% budget" | 0.85% and 0.56% vs 1% | B | Changed to "below … rather than at it", with an explicit statement that adherence is claimed, not equality to 1% |

### Dataset description and timing

| # | Location | Claim as written | Evidence | Class | Action |
|---|---|---|---|---|---|
| 14 | §Corpora | "**W2**, package-manager clients recorded by an Nginx server" | `DATASET_FREEZE` §10 forbids "any description of W2 as production or package-mirror traffic"; §9.3 W2 is a demo corpus (3 placeholder paths, 65.8% 404s, 0.025% referrers) | C | Rewritten: public sample logs from the Elastic Examples repository, verified byte-identical upstream; W2 explicitly a demonstration corpus; "the substrate is real observed traffic; this is not a real-world attack dataset, and the attacks are constructed" |
| 15 | Table I caption | "**Real** access-log corpora" | as above | C | "Public sample access-log corpora" |
| 16 | Abstract | "two **real** access-log corpora" | as above | C | "two public sample access-log corpora" |
| 17 | §Rejected invariants | "$v_5$ fires on **12–14%** of benign requests because **ordinary page loads are bursty**" | `DATASET_FREEZE` §9.1 names this rationale wrong and requires correction; W1 minute field is `05` throughout, W2 `05`/`06`, verified directly against the raw logs in this audit | C | Replaced: $v_5$ is **unevaluable** on these corpora because every inter-arrival gap is a generator artefact and no session exceeds 59 s. No new empirical timing claim made; no claim in either direction about scripted adversaries. The unsupported 12–14% figure was removed, not restated |
| 18 | §Attack injection | attacker requests copied "verbatim … and **inter-arrival gap**" | as above | B | Retained but qualified: the gap is copied for completeness, no timing property is claimed, and the retained invariants read no clock |
| 19 | §Limitations | "the attacker's timing is **a real client's timing**, which deliberately denies the method any rate-based signal" | degenerate timestamps | C | Replaced with the degeneracy statement, the reason the study survives it (the retained invariants read no clock), and that $v_5$ is unevaluable rather than refuted and the theft-delay sweep inert |
| 20 | §Efficiency | "flat across a **260×** range in the number of concurrently live sessions" | `e6_scaling.csv`: W1 6→127 (21.2×), W2 78→1563 (20.0×). 260× only arises by dividing W2's maximum by W1's minimum — a cross-workload ratio | C | Corrected to ~20× within each workload's own sweep, wider when both are read together; added that these are computational costs, not detection delays |
| 21 | §Efficiency caption | "median of **five** repetitions" | `exp06_efficiency.py`: `REPEATS = 7`, `WARMUP = 2`; `e6_environment.json` confirms | C | "median of seven repetitions after two warm-up runs" |
| 22 | §Limitations | "both logs are **a decade old**" | W1 17–20 May 2015; W2 17 May – 4 Jun 2015, read from the raw logs | A | Kept unchanged — verified |

### Baselines and metrics

| # | Location | Claim as written | Evidence | Class | Action |
|---|---|---|---|---|---|
| 23 | §Baselines | address pinning "**catches every attacker**, since every attacker in `L0`--`L3` changes address" | `e2_baselines.csv`: `pin_ip` recall 0.711 / 0.695 | C | Corrected to the measured recall and FPR on both workloads, with the reason it is not 1.0 (blind to L4 and L5) and the note that an L0–L3-only ladder would have handed it recall 1.0 by construction |
| 24 | §Baselines | balanced accuracy vs ROC AUC for binary rules | frozen H5 decision | A | Unchanged — already correct; no fabricated AUC for any binary baseline anywhere in the paper |
| 25 | §Base rates | pinning "produces roughly **ten times** the alert volume" | at prevalence 1e−3: SICA ≈ 8.8k alerts/M vs pinning ≈ 153k/M ≈ 17× | B | Changed to "well over an order of magnitude", avoiding a newly hand-typed figure |
| 26 | §Leakage | "the largest single-feature AUC is 0.590 … **the remainder sit at chance**" | `e5_marginal_audit.csv`: `median_gap_s` = 0.369 on W1, i.e. further from 0.5 than any feature above it; `distinct_paths` = 0.729 on W2 | C | Corrected: an AUC below 0.5 is an inverted signal, not chance; both residual shortcuts named, with the reason neither can reach the monitor (it reads no gap, byte count or path) |

### Ablation

| # | Location | Claim as written | Evidence | Class | Action |
|---|---|---|---|---|---|
| 27 | §Ablation | "single-$v_2$ configurations reach ROC AUC **within about 0.01** of the full method … and operate at **roughly twice** the full method's false-alarm rate" | `e3_ablation.csv`: `only_V2` AUC 0.811 vs full 0.889 (W1) and 0.791 vs 0.850 (W2) — a gap of 0.06–0.08, not 0.01. `only_V2` FPR = **0.000** and F1 = **0.000** on both workloads — it raises no alerts at all, not twice as many | C | Both figures removed. Replaced with: $v_2$ alone recovers most but not all of the ranking quality, and at α=0.01 a $v_2$-only detector raises no alert at all; the ensemble's contribution is a usable operating point, not ranking |
| 28 | §Ablation | "Removing the explicit fork invariant **raises $F_1$** … on both workloads" | minus_V3 F1 0.578 vs 0.490 (W1, raises) but 0.269 vs 0.369 (W2, **lowers**) | C | Corrected: the $F_1$ effect does not share a sign across workloads; the AUC effect is small and negative on both |
| 29 | §Ablation | disabling reference migration "is the **single most damaging design change** in the table" | `no_migration` ΔF1 −0.073 / −0.150; `accumulator` ΔF1 −0.316 / −0.226 and ΔAUC −0.009 on both — larger on every measure | C | Corrected: the decayed-accumulator variant is the most damaging row; migration remains the larger expression of the asymmetry in $F_1$, and the AUC difference between migration and $v_3$ is too small to separate them |
| 30 | §Ablation | "The **lower block restores each rejected invariant** … each restoration is measurable and **negative**" | The printed lower block is the three *design* variants; restorations are not printed. `plus_V6` on W1 gives AUC 0.902 vs full 0.889 — it **raises** ranking quality | C | Corrected: restorations are in the released ablation, not this table; $v_4$/$v_5$ restorations are negative, $v_6$ is inert on W2 and *positive* on W1; the $v_6$ rejection rests on the development-seed criterion requiring improvement on both workloads, and the reporting-seed ablation does not independently corroborate it — stated rather than glossed |
| 31 | Table VII caption | "Leave-one-out … and **the two** invariants that were implemented and rejected" | The table contains no rejected-invariant rows, and there are **three** rejected invariants | C | Caption corrected to describe the two blocks the table actually contains |

### Terminology, structure and accounting

| # | Location | Claim as written | Evidence | Class | Action |
|---|---|---|---|---|---|
| 32 | §False alarms + Abstract | "across **254** and **3,126** pooled unmodified real sessions" (`\corpusSess…`) | `e1_false_alarms_by_benign_class.csv`: pooled `benign` counts are **2,541** and **30,241**; the macros used are the *corpus* session counts | C | The wrong macros were removed and the sentence reworded to refer to the table rather than introduce a new hand-typed number |
| 33 | §False alarms + Abstract | "**Every** false alarm … comes from a client that leaves its `/16`" | W1 `M4_flapping:subnet` contributes 3 false alarms from flapping *within* a `/16` | C | Corrected to "almost every", with the intra-`/16` flapping exception named as the same interleaving phenomenon one scale down |
| 34 | §Protocol / §Rejected | development seeds described as a disjoint block, independence not characterised | `RESEARCH_RECORD` §6: development seeds draw different injections over the *same* benign sessions | B | Explicit statement added in both places that these are disjoint **seed blocks over the same corpora, not independent datasets**, and that this controls for the benchmark draw but not the corpus |
| 35 | §Protocol | attack-label usage stated only in passing | `harness.py`; contract | B | Explicit sentence added: labels are evaluation-only and enter neither scoring, nor benign weighting, nor the threshold |
| 36 | Whole paper | V1/V2/V3 as the final method; V4/V5/V6 as rejected | `DEFAULT_INVARIANTS` | A | Verified correct throughout — no rejected invariant is presented as part of the detector |
| 37 | Terminology | hijacking vs account takeover / login anomaly / fixation / replay | contract §2 | A | Verified — the Threat Model already distinguishes these explicitly and consistently |

---

## 3. LaTeX and structural defects

| # | Defect | Evidence | Action |
|---|---|---|---|
| 38 | **The manuscript did not compile at all.** Fatal `! Misplaced \noalign` at the first generated table | Reproduced in a minimal document: LaTeX's `\input{f}` expands to `\@@input f \relax`; inside a `tabular` that trailing `\relax` lands at the start of the row after the body's final `\\`, opening a cell, so the following `\bottomrule` is an illegal `\noalign`. Inline bodies compile; every `\input` form fails | Added a preamble helper `\tabbody` (`\@@input` with no trailing token) and used it at the 11 table-body sites. `tables/numbers` is read in the preamble and still uses `\input`. **No generated table was modified** |
| 39 | Overfull `\hbox` 68.3pt (ablation table), 24.1pt (efficiency), 19.4pt→22.0pt (adversary ladder, slightly widened by the new L5 row) | compile log | Ladder given a wrapping `p{}` description column; the two dense 7-column tables given `\tabcolsep` 3.2pt, and the ablation table `\scriptsize`. Worst overfull box is now **3.2pt**. No content hidden, no table truncated |
| 40 | `\label{fig:arch}` and `\label{fig:ablation}` never referenced | cross-reference audit | Both figures now referenced from the text |
| 41 | `IEEEtran.bst` is **not vendored and not installed**, so `bibtex` cannot build the bibliography from a clean checkout | `kpsewhich IEEEtran.bst` → not found; repo vendors only `IEEEtran.cls` | **Not fixed — reported.** Verified separately that this is only a missing style file: with a substitute style, bibtex runs with zero errors and all 21 cited keys resolve |

### Citation audit

* 28 citation uses, **21 distinct keys**; 24 entries in `ref.bib`.
* **Undefined citations: none.** **Duplicate keys: none.** **Dangling `\ref`: none.**
* Unused entries (3): `eckersley2010unique`, `owasp2024session`, `poese2011geolocation`.
  Left in place — harmless, and removing them is a literature decision, not a
  consistency one.
* Venue, year and DOI correctness for all 24 entries is **class D** — it cannot be
  checked from repository evidence alone and is deferred to the literature step.
  Nothing was fabricated and no reference was added.

### Generated-macro audit

* 94 macros defined, **0 undefined macros used**; body usage rose from 51 to **58**.
* Unused macros fell from 43 to **36**: this step put the four `\recLfive…` macros,
  two `\recLfour…` macros and `\PinIpRecallApt` / `\PinIpFprApt` to work.

---

## 4. Deliberately not done (2)

1. **Figure 3 legend collision.** In the W1 panel the `upper right` legend overlaps
   the shaded-band annotation. Pre-existing — it is present in the pre-L5 figure in
   git history — and out of scope by instruction ("do not redesign Figure 3
   aesthetics"). It is a publication blocker and needs one line in
   `pipeline/exp08_figures.py`.
2. **`IEEEtran.bst`.** Vendoring it is a repository change, not a paper-consistency
   change, and it must come from the official IEEE distribution rather than be
   improvised.

---

## 5. Discrepancy noted, not resolved here

`docs/DATASET_FREEZE.md` §9.4 quotes the residual shortcuts as `distinct_paths`
AUC **0.733** (W2) and `median_gap_s` AUC **0.322** (W1). The current
`results/tables/e5_marginal_audit.csv` gives **0.729** and **0.369**. The paper was
made consistent with the **current CSVs**, which are the frozen evidence. The freeze
document appears to quote pre-final numbers and should be reconciled in a
documentation step — no result is affected.

---

## 6. Verification

| Check | Result |
|---|---|
| Files hashed before/after | 170; **169 unchanged**, 1 changed (`paper/paper.tex`) |
| Result CSVs | **0 changed** |
| Generated LaTeX tables | **0 changed** |
| Raw datasets | unchanged, match `DATASET_FREEZE` |
| `sica/`, `pipeline/`, `tests/` | **byte-identical** |
| `results_archive/` | **untouched** |
| `paper/ref.bib` | unchanged |
| Experiments re-run | **none** |
| α / seeds / invariants / levels | 0.01 · 0–29 · V1,V2,V3 · L0–L5 |
| ML imports | none |
| `pytest` | **50 passed** |
| `pipeline/validate.py` | **73 passed, 0 failed** |
| `pdflatex` × 3 | **0 errors**, 0 undefined references, 11 pages |
| Bibliography (substitute style) | 21/21 keys resolve, 0 bibtex errors |
