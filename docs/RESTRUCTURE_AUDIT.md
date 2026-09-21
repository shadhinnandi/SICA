# Restructure audit — Step 4

**Date.** 2026-09-13.
**Repository.** `/Users/shadhinnandi/UIU/12/Computer Security/restore/sica`
**Baseline commit.** `cb9771e9e749aa5d119e28db240d3da2d2d0ca9d` (Step 3 checkpoint).

**Headline finding: no file or directory was moved or renamed.** That is the
conclusion of the audit, not an omission. The executable layout is already a
standard research-repository structure, and every candidate move was found to
break either an import path, a safety check, or a reference held inside frozen
evidence. The instruction was explicit — *"if moving a file would break imports
or reproducibility, do not move it merely for appearance"* — and it applies to
every move considered here.

Work done instead: six genuinely stale documentation statements corrected, a
`.gitattributes` added, and three unresolved defects documented.

---

## 1. Pre-restructure state

| Item | Value |
|---|---|
| Commit | `cb9771e9e749aa5d119e28db240d3da2d2d0ca9d`, branch `main`, 1 commit, 0 remotes |
| Working tree | ` M docs/GIT_CHECKPOINT.md` (documented, intentional) |
| Tracked files | 184 |
| Tests | **50 passed, 0 failed** (24 `test_sica.py` + 26 `test_regressions.py`) |
| Validation | **70 passed, 0 failed** |
| `data/raw/apache_sample_1.log` | `f15c31e905f86c7b4b6ab44aee74d0a2086dce89f010187d983edea7ef0364ef` |
| `data/raw/nginx_real.log` | `526832433ab552466dc8623390fd92dc052b4f301b2eec94836a5c42a46937df` |
| `paper/paper.tex` | `fae18ffe3fbfacf0543bcd464390f7a8d66956bff80d8d1c2bc0e503ff303089` |
| `paper/ref.bib` | `75c6a9820683d83e7672f76e050b18bd4697a7481980db34e144650be93dae88` |
| V1 / V2 / V3 bodies | `dff8e2d46da31500` / `71739006643fd61d` / `77cdd96d6f4bbb3e` |
| `ALPHA` | 0.01 · reporting seeds 0–29 · development seeds 100–119 |
| Result artefact baseline | 107 hashed entries under `results/`, `results_archive/`, `paper/tables/` |

## 2. Why nothing was moved

Each constraint below was verified by inspection, not assumed.

| Candidate move | What it would break |
|---|---|
| `sica/` → `src/sica/` | 13 files resolve the repository root as `Path(__file__).resolve().parents[1]`. Worse, `pipeline/validate.py:75` scans `ROOT/"sica"/*.py` to prove **no module imports a machine-learning library**. After the move that glob would match nothing and the check would **pass vacuously** — a safety check silently turning into a no-op is far worse than an untidy layout |
| `pipeline/` → `experiments/` + `reporting/` + `validation/` | Same `parents[1]` anchor in all 13 scripts, plus 12 invocation paths in `run_all.sh`, plus `validate.py`'s expected-artefact list |
| `pipeline/dev_*.py` → `pipeline/development/` | Their `parents[1]` would resolve to `pipeline/`, not the repository root, so `import sica` and every output path would fail |
| `tests/` deeper | `conftest.py`, `test_sica.py:148`, `test_regressions.py:19,433` all use `parents[1]` to locate the root and `data/raw/` |
| `results/` or `paper/` | `paper/paper.tex` hard-codes `../results/figures/…` in 6 `\includegraphics` and `tables/…` in 12 `\input`. Fixing those means editing `paper.tex`, which Step 4 forbids |
| Root docs → `docs/` | `results_archive/…/PROVENANCE.md` — **frozen evidence that must not be modified** — cites `AUDIT.md`. Moving it would either strand a broken reference inside the archive or force an edit to frozen evidence. `AUDIT.md`, `DATASET.md` and `RESEARCH_RECORD.md` are also cited from `tests/test_regressions.py`, `run_all.sh` and `pipeline/common.py` respectively (in comments and messages, not as file reads), and from ~40 places across 17 documents |

The remaining root files — `README.md`, `LICENSE`, `LICENSE-APACHE-2.0.txt`,
`CITATION.cff`, `CITATION_OF_INPUTS.txt`, `requirements.txt`, `.gitignore`,
`pytest.ini`, `config.yaml`, `run_all.sh` — are all at their conventional
location for a research repository.

## 3. Changes made

### Files moved or renamed
**None.**

### Files created

| File | Purpose |
|---|---|
| `.gitattributes` | LF endings; `data/raw/*.log` marked `-text` so the frozen corpora can never be line-ending normalised (which would change their SHA-256); generated artefacts marked `-diff`/`binary`; `linguist-*` so the repository is reported as Python rather than TeX or data |
| `docs/RESTRUCTURE_AUDIT.md` | this document |

### Documentation corrected (6 statements, all verified stale)

| File | Was | Now |
|---|---|---|
| `README.md` | `L0`–`L3` is the evaluated envelope; `L4` reported as such | `L0`–`L5` reported envelope, with the address-visible / co-located distinction and why restricting to `L0`–`L3` would make address pinning perfect by construction. `L5` row added to the level table |
| `README.md` | `pytest -q  # expect: 23 passed` | `# expect: 50 passed` |
| `README.md` | Adversary grid `L0`–`L4` | `L0`–`L5` — 24 cells |
| `README.md` | `27 CSVs`, `4 JSONs`, `results/PIPELINE_DONE` | `39 CSVs`, `3 JSONs`, `results/RUN_STATUS.md` |
| `DATASET.md` | `L0`–`L3` form the evaluated envelope | `L0`–`L5` reported envelope; `L5` row added |
| `CHECKPOINT.md` | Masquerade levels `L0`–`L3` … `L4` reported separately | `L0`–`L5` reported envelope; `L4` outside any binding-based envelope |

No scientific claim was rewritten. Each correction replaces a statement that the
frozen experiment contract and the generated results already contradict.

## 4. Stale references found

### Corrected
The six above.

### Found and deliberately **not** changed — historically accurate

| Location | Content | Why retained |
|---|---|---|
| `docs/ARCHITECTURE_AUDIT.md` | `the previous repository path`, "23 tests", `L0`–`L4`, `pin_ip` AUC 0.926, "bursty page loads" | This is the **pre-fix audit**. Those were the true values at the time it was written; the document is evidence for the corrections that followed. Rewriting it would destroy the record |
| `docs/TEST_PLAN.md` | "23 passed (pre-fix code)" | Explicitly labelled as the pre-fix baseline |
| `AUDIT.md`, `sica/invariants.py` | "bursty page loads" | Both state that this explanation **was wrong** and give the real cause |
| `AUDIT.md` | 54% FPR, One-Class SVM | The historical v1 defect record |
| `CHECKPOINT.md`, `README.md` | "no one-class SVM" | A constraint statement, not a claim of use |
| `RESEARCH_RECORD.md`, `docs/*`, `results/RUN_STATUS.md` | `2026-09-05` | Correct references to the archived superseded run |
| `results_archive/**` | everything | Frozen evidence. Not touched |

### Searched for and **not present**
No reference anywhere to `/session hijacking/project`, no `/Users/` path, no
description of a synthetic dataset as the primary benchmark, no surviving
"package-manager production traffic" wording (only explicit negations), and no
document presenting `V4`/`V5`/`V6` as retained.

## 5. Unresolved issues — documented, not fixed

**These are real defects. They were not fixed because fixing them requires
regenerating frozen artefacts, which Step 4 forbids.**

1. **`pipeline/exp08_figures.py:156` — Figure 3 omits `L5`.**
   `fig_envelope()` hard-codes `levels = ["L0","L1","L2","L3","L4"]`, so the
   detection-envelope figure silently drops the `L5` column.
2. **`pipeline/make_tables.py:91` — the scenarios table omits `L5`.**
   `tbl_scenarios()` iterates the same five-level list, so `paper/tables/scenarios.tex`
   has no `L5` row.

   Both are the same class of defect as the `level_word` bug corrected in the
   reporting pass (which omitted `L5` from the generated macros). `L5` is the
   co-located, different-client-program level — one of the two cells that exist
   precisely to stop the benchmark reducing to address-change detection, and the
   one where the method's own distinctive result appears. Omitting it understates
   the contribution and hides a contracted scenario.

   **`pipeline/validate.py` does not catch this**: it checks that
   `e4_scenario_grid.csv` contains 24 cells, but not that the figure and table
   render every level. That validation gap should be closed at the same time.

   Fixing requires editing two reporting functions and re-running
   `make_tables.py` and `exp08_figures.py` — no experiment re-run, but it does
   regenerate `results/figures/fig3_envelope.*` and `paper/tables/scenarios.tex`.

3. **`paper/paper.tex:304` still carries the superseded `v5` rationale**
   ("ordinary page loads are bursty"). The real cause is the degenerate source
   timestamps. `paper.tex` is out of scope for this step; already recorded in
   `docs/DATASET_FREEZE.md` §12 as blocking publication, not experimentation.

## 6. Post-restructure verification

| Check | Result |
|---|---|
| `python3 -m pytest -q` | **50 passed, 0 failed** |
| `python3 pipeline/validate.py` | **70 passed, 0 failed** |
| Dataset SHA-256 | **unchanged**, both match `docs/DATASET_FREEZE.md` |
| Result artefacts (107 hashed entries) | **unchanged** |
| `paper/paper.tex`, `paper/ref.bib` | **unchanged** (hashes match §1) |
| V1 / V2 / V3 body hashes | **unchanged** |
| `ALPHA`, seeds | **unchanged** — 0.01, 0–29, 100–119 |
| Git remotes | **none** |
| Secrets scan | **clean** |
| Duplicate canonical files | **none** — see note below |
| Documented execution paths | `run_all.sh`, all `pipeline/*.py`, `pytest` — all still resolve |

### Note on byte-identical files across `results/` and `results_archive/`

Five files are byte-identical between the current results and the archived
superseded run:

```
results/tables/e0_corpus.csv                    results/metadata/e0_sessionisation.json
results/tables/e0_agent_mix.csv                 results/metadata/e6_environment.json
results/tables/e0_sessionisation_sensitivity.csv
```

These are **not** duplicated canonical files and neither copy should be removed.
`pipeline/exp01_corpus.py` (E0) takes no seed — it is a pure corpus audit whose
output depends only on the two frozen logs and on `IDLE_SECONDS` / `MIN_REQUESTS`,
none of which changed between the two runs. Two independent executions therefore
produce identical bytes. `e6_environment.json` matches for the same reason: both
runs used the same interpreter and library versions. They are separate files on
disk (different inodes, no symlinks): one is the current result, the other is
evidence of the abandoned run.

Note that `results/tables/e0_corpus.csv` consequently still carries the
superseded W2 description string in its `description` column, exactly as recorded
in `RESEARCH_RECORD.md` — the label was corrected in `pipeline/common.py` but E0
was deliberately not re-run for a cosmetic change.

## 7. Confirmation

No detector logic, invariant, dataset, raw log, experiment parameter, seed,
alpha value, result file, or scientific conclusion was changed in this step. No
experiment was re-run and no result regenerated. No machine-learning component
was introduced. No GitHub remote was added and nothing was pushed. The Step 3
checkpoint commit was not amended. The separate backup folder at
`…/session hijacking/project` was not read, compared against, copied from, or
modified.
