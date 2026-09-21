# L5 reporting-coverage fix

**Date:** 2026-09-13 · **Scope:** reporting layer only · **Experiments re-run:** none

This records the correction of a reporting-layer defect found during the Step 4
structural audit. No detector code, dataset, experiment parameter or result value
was changed. The underlying run is the same run; only two artifacts that *display*
it were wrong.

---

## 1. The original defect

Two reporting code paths each carried their own hard-coded list of masquerade
levels, and both stopped at `L4`:

| File | Line (before) | Code |
|---|---|---|
| `pipeline/make_tables.py` | 91 | `for level in ["L0", "L1", "L2", "L3", "L4"]:` |
| `pipeline/exp08_figures.py` | 156 | `levels = ["L0", "L1", "L2", "L3", "L4"]` |

The frozen grid is `L0`–`L5`. `sica/inject.py` defines it once and correctly:

```python
LEVELS_ADDRESS_VISIBLE = ("L0", "L1", "L2", "L3")
LEVELS_COLOCATED       = ("L4", "L5")
LEVELS_ALL             = LEVELS_ADDRESS_VISIBLE + LEVELS_COLOCATED
```

`results/tables/e4_scenario_grid.csv` contains all **24** cells
(6 levels × 2 modes × 2 workloads), L5 included. The experiment was complete.
Only the rendered table body and the figure dropped a level on the way out.

The macro layer was **not** affected: `make_tables.py` line 299 already mapped
`"L5": "Lfive"`, so `paper/tables/numbers.tex` already carried
`\recLfiveConcurrentWeb` = `0.891`, `\recLfiveConcurrentApt` = `0.485`,
`\recLfiveTakeoverWeb` = `0.002`, `\recLfiveTakeoverApt` = `0.001`.
The repository therefore held correct L5 numbers and a table and figure that
omitted them at the same time.

## 2. Why it mattered scientifically

L5 is not a minor cell. Per `docs/EXPERIMENT_CONTRACT.md` §9:

| Level | Attacker address | Attacker agent | Evidence available |
|---|---|---|---|
| **L4** | the victim's own | victim's (cloned) | **none — no binding signal exists at all** |
| **L5** | the victim's own | donor's own | **no address signal; `v1` is the only evidence** |

L5 is the *only* cell in the benchmark in which the attacker is fully co-located
— presenting the victim's own address — and is still detected. Its measured
recall is:

| | W1 takeover | W1 concurrent | W2 takeover | W2 concurrent |
|---|---|---|---|---|
| **L5** | 0.002 | **0.891** | 0.001 | **0.485** |

That concurrent column is the empirical demonstration of the paper's central
claim: SICA detects hijacking with **no address evidence whatsoever**, which is
precisely what every address-pinning baseline cannot do by construction. Omitting
L5 removed the strongest single piece of evidence separating SICA from `pin_ip`,
while leaving `L4` — the acknowledged blind spot, recall ≈ 0 — as the last bar on
the chart. The visible story was therefore "detection decays to nothing", when the
measured story is "detection decays to nothing only when the agent is also cloned,
and recovers to 0.891 the moment it is not."

The omission was silent: `pipeline/validate.py` checked that the **source CSV**
covered `LEVELS_ALL` (and it did), but nothing checked the **rendered artifacts**.
All 70 checks passed over an incomplete figure and an incomplete table.

## 3. Files changed

| File | Change |
|---|---|
| `pipeline/make_tables.py` | imports `LEVELS_ALL` from `sica.inject`; `tbl_scenarios()` iterates it instead of a literal |
| `pipeline/exp08_figures.py` | imports `LEVELS_ALL`; `fig_envelope()` iterates it; the shaded band's x-position is now derived via `levels.index("L4")` instead of the hard-coded `3.5, 4.5`, so it cannot drift if the level list changes |
| `pipeline/validate.py` | three new checks (§6) plus a `pdf_level_labels()` helper |

The fix deliberately removes the *duplicate source of truth* rather than extending
it: neither reporting module now states which levels exist. Both ask
`sica/inject.py`, which is the frozen contract's own definition.

### Figure annotation wording

One annotation string changed, and it is recorded here because it is a wording
change rather than a mechanical one. The shaded band over `L4` was labelled
`outside envelope`. With `L4` as the final bar that read as "the reported envelope
stops here". Once `L5` — also co-located, also presenting the victim's own address,
and detected at 0.891 — sits to its right, that label would assert something false.
The band now reads `no binding signal`, which is the contract's own description of
`L4` ("No binding signal exists at all") and agrees with the existing figure
caption in `paper/paper.tex` ("outside the envelope of any binding-based
server-side signal"). The band still covers `L4` alone: `L5` is co-located but
remains detectable through `v1`, so it is inside the detectability envelope.

Nothing else about the figure changed — same size, colours, hatching, error bars,
axes, limits, fonts and legend placement.

## 4. Reporting artifacts regenerated

Exactly three files, produced by calling the two affected functions individually
(`tbl_scenarios()` and `fig_envelope()`) rather than by running `run_all.sh` or
either script's `__main__` block, so no unaffected artifact was rewritten:

- `paper/tables/scenarios.tex`
- `results/figures/fig3_envelope.pdf`
- `results/figures/fig3_envelope.png`

No other table, figure, CSV, JSON or macro file was regenerated.
`paper/tables/numbers.tex` was already correct and was left untouched.

## 5. Experiments were NOT re-run

`E0`–`E7` were not executed. `run_all.sh` was not invoked. No detector was run
over any traffic. Both regenerated artifacts were derived **only** from the
existing frozen `results/tables/e4_scenario_grid.csv`.

Every one of the 24 values now in `scenarios.tex` was verified programmatically
against that CSV, cell by cell; all 24 agree exactly. No number was typed by hand.

## 6. Detector, data and methodology were NOT changed

- Every file under `sica/` is byte-identical to the pre-fix state.
- `V1_agent_mutation`, `V2_scope_discontinuity`, `V3_binding_fork` unchanged
  (`596063c21644ddfc` / `5d2d37e04c0919f9` / `71553e865bab25d9`).
- `DEFAULT_INVARIANTS`, `ALPHA = 0.01`, seeds `0–29` unchanged.
- Both raw corpora unchanged and still match `docs/DATASET_FREEZE.md`.
- `paper/paper.tex` and `paper/ref.bib` byte-identical — not edited in this step.
- All 27 result CSVs and all 3 metadata JSONs byte-identical.
- `results_archive/` untouched.

## 7. Before / after level coverage

| Artifact | Before | After |
|---|---|---|
| `results/tables/e4_scenario_grid.csv` (source) | L0–L5 | L0–L5 (unchanged) |
| `paper/tables/numbers.tex` (macros) | L0–L5 | L0–L5 (unchanged) |
| `paper/tables/scenarios.tex` | **L0–L4** | **L0–L5** |
| `results/figures/fig3_envelope.pdf` / `.png` | **L0–L4** | **L0–L5** |
| `pipeline/validate.py` coverage | source CSV only | source CSV **+ rendered table + rendered figure + reporting source** |

Both workloads (`W1_web`, `W2_apt`) and both modes (`takeover`, `concurrent`)
remain represented at every level: the table is 6 rows × 4 value columns and the
figure is 2 panels × 2 mode series × 6 levels.

## 8. New validation checks

| Check | Fails when |
|---|---|
| `scenarios table body has a row for every masquerade level` | a level in `LEVELS_ALL` has no `\texttt{Lx} &` row in `paper/tables/scenarios.tex` |
| `envelope figure plots every masquerade level` | a level in `LEVELS_ALL` does not appear in the text streams of `fig3_envelope.pdf` (streams are Flate-inflated first; a level never plotted cannot appear) |
| `reporting code derives levels from LEVELS_ALL, not a local literal` | `make_tables.py` or `exp08_figures.py` contains a `["L0", ...]` literal that is not exactly `LEVELS_ALL` |

The first two check the artifacts a reader actually sees; the third removes the
root cause. No existing check was weakened or removed.

**These checks were verified to fail.** The pre-fix `scenarios.tex` and
`fig3_envelope.pdf` were restored from git and the `L0–L4` literal reinstated;
validation then reported `70 passed, 3 failed` and named `L5` in each failure:

```
[FAIL] scenarios table body has a row for every masquerade level: missing rows: ['L5']
[FAIL] envelope figure plots every masquerade level: missing from fig3_envelope.pdf: ['L5']
[FAIL] reporting code derives levels from LEVELS_ALL, not a local literal: make_tables.py: ['L0', 'L1', 'L2', 'L3', 'L4']
```

The corrected artifacts were then restored. The checks are exercised, not vacuous:
they would have caught this defect at the time it was introduced.

## 9. Hash verification

156 tracked artifacts and source files were hashed before and after.
**150 unchanged; 6 changed, all intended:**

```
pipeline/make_tables.py          (fix)
pipeline/exp08_figures.py        (fix)
pipeline/validate.py             (new checks)
paper/tables/scenarios.tex       (regenerated — L5 row added)
results/figures/fig3_envelope.pdf(regenerated — L5 bars added)
results/figures/fig3_envelope.png(regenerated — L5 bars added)
```

Zero result CSVs changed. Datasets, `paper.tex`, `ref.bib`, all of `sica/` and all
of `results_archive/` verified byte-identical.

## 10. Tests and validation

| | Before | After |
|---|---|---|
| `pytest -q` | 50 passed | **50 passed, 0 failed** |
| `pipeline/validate.py` | 70 passed, 0 failed | **73 passed, 0 failed** |

The increase is exactly the three new checks.

## 11. Remaining concerns

1. **`paper/paper.tex` prose does not mention L5 at all.** The table and figure
   now show six levels; the surrounding text discusses L0–L4 and states
   "`L4` is zero by construction" as the end of the ladder. The `\recLfive...`
   macros exist and are unused. The manuscript must be extended to interpret L5 —
   it is the paper's strongest evidence against the pinning baselines and is
   currently displayed but unexplained. **Not fixed here: editing `paper.tex` was
   out of scope for this step by instruction.**
2. **The figure caption in `paper.tex` is now incomplete.** It says `L4`
   "is outside the envelope of any binding-based server-side signal" and does not
   mention `L5`, which is equally co-located but detected. As written it invites
   the reader to generalise from `L4` to all co-located attackers — which the new
   `L5` bar on the same figure contradicts. Same step-scope restriction applies.
3. **Pre-existing figure layout defect (not introduced here).** In the W1 panel the
   `upper right` legend overlaps the shaded-band annotation. This is visible in the
   pre-fix figure in git history as well, so it is not a regression, but the figure
   is not publication-ready until it is resolved (moving the legend or the
   annotation is a one-line change). Left alone because changing legend placement
   is a figure-design change, not part of including L5.
4. **The documented V1/V2/V3 body hashes are not reproducible.**
   `docs/GIT_CHECKPOINT.md` and `docs/RESTRUCTURE_AUDIT.md` record
   `dff8e2d46da31500` / `71739006643fd61d` / `77cdd96d6f4bbb3e`, but no hashing
   routine exists anywhere in the repository and 114 candidate recipes (blake2s/
   blake2b/sha1/sha256/sha512/md5 over raw, dedented, docstring-stripped,
   whitespace-normalised, AST-unparsed and AST-dumped forms) fail to reproduce
   them. The invariant *sources* are demonstrably unchanged — every file under
   `sica/` is byte-identical across Step 4 and Step 5 — so this is a provenance
   defect in the documentation, not evidence of drift. From this document onward
   the recipe is stated explicitly: **blake2s, 8-byte digest, over the function's
   full source text from its `def` line through its last line inclusive**, which
   yields `596063c21644ddfc` / `5d2d37e04c0919f9` / `71553e865bab25d9`. The older
   triple should be treated as unverifiable and retired rather than re-quoted.
5. The `L5` takeover cells are at the false-alarm floor (0.002 / 0.001) while the
   concurrent cells are 0.891 / 0.485. This is a genuine measured result, not a
   defect, but the asymmetry is large and should be explained in the manuscript
   alongside the same effect at `L1`.
