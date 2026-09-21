# Git checkpoint — verified SICA research state

## Purpose

This records the first version-control checkpoint of the SICA project. It was
created **before any physical restructuring of the repository**, so that the
verified scientific state — detector, frozen datasets, final results and the
documentation describing them — is captured under version control and every later
change is reversible and attributable.

Nothing scientific was changed to create this checkpoint. No experiment was run,
no result regenerated, no detector code touched.

---

## Checkpoint facts

| Item | Value |
|---|---|
| Date | **2026-09-13** |
| Repository | initialised in this step; **no prior Git history existed** |
| Branch | `main` |
| Commit | recorded in **§Post-commit record** below — a file cannot contain the hash of the commit that contains it |
| Commit message | `chore: freeze verified SICA research checkpoint` |
| Files committed | **183** |
| Insertions | 104,662 lines |
| Repository size | ~15 MB working tree (`.git` additional) |
| Remote | **none configured** — local only, nothing pushed |
| Committer identity | `the environment's Git identity` (the environment's configured Git identity — **see Risks**) |

## Environment of record

| Item | Value |
|---|---|
| Python | CPython **3.11.15** |
| Platform | `Linux-6.18.44-fc-v24-x86_64-with-glibc2.39` |
| numpy | 2.4.4 |
| pandas | 3.0.2 |
| scipy | 1.17.1 |
| matplotlib | 3.10.9 |
| Git | 2.43.0 |

Source: `results/metadata/e6_environment.json` (captured during the efficiency
stage of the reporting run) and the live interpreter at checkpoint time.

## Verification performed at checkpoint time

| Check | Result |
|---|---|
| Test suite (`pytest -q`) | **50 passed, 0 failed** (24 in `test_sica.py`, 26 in `test_regressions.py`) |
| Pipeline validation (`pipeline/validate.py`) | **70 passed, 0 failed** |
| Raw dataset hashes vs `docs/DATASET_FREEZE.md` | **both MATCH** |
| Result artifact integrity | **131/131 files byte-identical** to the pre-Step-2 snapshot |
| Archive integrity | **unchanged**; 46/46 files still verify against their own `MANIFEST.sha256.txt` |
| `paper/paper.tex`, `paper/ref.bib` | **unchanged** |
| V1/V2/V3 function bodies | **unchanged** — `dff8e2d46da31500`, `71739006643fd61d`, `77cdd96d6f4bbb3e` |
| `ALPHA` | **0.01** |
| Reporting seeds | **0–29** |
| Development seeds | **100–119** |
| Secret scan | **clean** — no keys, tokens, `.env`, certificates or credential assignments |

### Dataset hashes

```
f15c31e905f86c7b4b6ab44aee74d0a2086dce89f010187d983edea7ef0364ef  data/raw/apache_sample_1.log
526832433ab552466dc8623390fd92dc052b4f301b2eec94836a5c42a46937df  data/raw/nginx_real.log
```

Both verified byte-identical to the Elastic Examples originals (Apache-2.0).

## What is under version control

| Area | Files | Why tracked |
|---|---|---|
| Generated results (`results/`) | 67 | The evidence for every number in the manuscript |
| Archived superseded run (`results_archive/`) | 48 | Evidence base for the audit findings — void numbers, deliberately retained |
| Code (`sica/`, `pipeline/`, `tests/`) | 27 | The detector, the experiments, the 50-test gate |
| Root documentation and legal | 16 | README, freezes, licences, `CITATION.cff`, `RESEARCH_RECORD.md` |
| Paper (`paper/`) | 15 | Manuscript source, bibliography, vendored class, 12 generated tables |
| `docs/` | 8 | Frozen records, contract, audits, this file |
| Raw datasets (`data/raw/`) | 2 | 9.0 MB; the study cannot be reproduced without them, and they are redistributable |

Deliberately **not** tracked: Python caches, `.pytest_cache`, `.venv`, editor and
OS junk, and LaTeX build artefacts including the compiled `paper/paper.pdf`.
Figure PDFs live under `results/figures/` and **are** tracked. The rationale is
recorded in `.gitignore` itself.

## Known remaining risks

1. **Commit authorship is the environment's Git identity**
   (`the environment's Git identity`), not the project author. This misattributes
   the work if published as-is. Set a real identity before adding a remote:
   ```bash
   git config user.name  "Your Name"
   git config user.email "you@example.org"
   git commit --amend --reset-author --no-edit
   ```
2. **`CITATION.cff` contains a placeholder author** and no DOI, repository URL or
   version. These were omitted rather than invented and must be completed before
   publication.
3. **No `results/PIPELINE_DONE` marker.** The final three stages of the reporting
   run were executed individually after a reporting-layer fix, so the marker's
   precondition — one uninterrupted `run_all.sh` invocation — was not met. It was
   deliberately not created by hand. See `results/RUN_STATUS.md`.
4. **`run_all.sh` has no freshness guard**: it clears only the marker files, and
   `validate.py` checks artefact *existence*, not freshness. A re-run that fails
   partway over a populated `results/` could mix generations. Archive `results/`
   before any re-run.
5. **`results/tables/e0_corpus.csv` carries a superseded W2 description string.**
   The label in `pipeline/common.py` was corrected on 2026-09-13; the frozen CSV
   was not regenerated for a cosmetic change. Nothing downstream reads that
   column; it resolves on the next full run.
6. **Repository structure is not yet reorganised** — `pipeline/` still mixes
   experiments, reporting and validation. Deferred deliberately so that the
   pre-restructuring state exists in history.
7. **The manuscript is not finished** and the literature review has not been done.
8. The tracked working tree is ~15 MB, dominated by the raw logs (9.0 MB). This is
   a deliberate reproducibility choice, not an oversight.

## Post-commit record

A commit hash cannot appear inside the commit it identifies. The hash below was
therefore written **after** the checkpoint commit was created, and is the one
change in the working tree that the checkpoint commit does not itself contain.

| Item | Value |
|---|---|
| Commit hash | `cb9771e9e749aa5d119e28db240d3da2d2d0ca9d` |
| Short hash | `cb9771e` |
| Files in that commit | **184** (183 project files + this manifest) |
| Verify with | `git rev-parse HEAD` and `git log -1 --oneline` |

## What this checkpoint enables

Any subsequent restructuring — moving `sica/` under `src/`, splitting `pipeline/`
into `experiments/`, `reporting/` and `validation/` — can now be done as a
reviewable diff and reverted if it breaks the path anchors
(`Path(__file__).resolve().parents[1]`), the twelve `sys.path` inserts, or
`validate.py`'s list of expected artefact names.
