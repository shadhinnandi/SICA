# Reproducibility

How to reproduce every number, table and figure in this project from a clean
machine, and — just as importantly — what *kind* of reproduction is actually
guaranteed.

Last verified against the repository on **2026-09-13**.

---

## 0. Three different claims, kept separate

Papers often say "reproducible" without saying which of these they mean. This
project claims the first two strongly and the third only conditionally.

| Claim | Status here |
|---|---|
| **Reproducibility of methodology** — another researcher can see exactly what was done and why, and could re-implement it | **Strong.** Every design decision is frozen and dated in `docs/`; `docs/EXPERIMENT_CONTRACT.md` was written before the reporting run |
| **Reproducibility of results** — re-running this code on this data reproduces the reported findings | **Strong for aggregates.** All 30 reporting seeds are run and reported; conclusions rest on means with bootstrap intervals, not on single seeds |
| **Bit-identical reproduction** — every per-seed number matches to the last digit | **Conditional.** Requires the same NumPy version. See §9 |

---

## 1. Requirements

| Requirement | Value |
|---|---|
| Python | **3.10 or newer** (uses `X \| Y` types and `dataclass(slots=True)`). Verified on **3.11.15** |
| OS | any POSIX system; no OS-specific code, no absolute paths anywhere |
| Cores | 1 — the pipeline is single-threaded |
| RAM | < 1 GB |
| Disk | < 100 MB including all outputs |
| Wall time | **≈ 72 minutes** for the full pipeline on one modern core (measured) |
| Network | **none** — nothing is downloaded at any stage |
| LaTeX | only to compile the manuscript (`pdflatex`, `bibtex`; `IEEEtran.cls` is vendored in `paper/`) |

The detector itself (`sica/`) imports only **numpy** and **pandas** plus the
standard library. `scipy` is used solely for the Wilcoxon test in E7, and
`matplotlib` solely for figures. `pipeline/validate.py` asserts mechanically that
no module under `sica/` imports any machine-learning library.

`pyyaml` is **not** required. `config.yaml` is a descriptive mirror that no code
loads; nothing imports `yaml`.

## 2. Install

```bash
cd sica
python3 -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python3 -c "import sys; print(sys.version)"
```

Record the Python version you used. `results/metadata/e6_environment.json`
captures it automatically during the efficiency stage.

## 3. Datasets — already present, nothing to download

Both corpora ship with the repository and are **frozen**. Do not modify them.

| ID | Path | Bytes | Records | SHA-256 |
|---|---|---|---|---|
| W1 (primary) | `data/raw/apache_sample_1.log` | 2,370,789 | 10,000 | `f15c31e905f86c7b4b6ab44aee74d0a2086dce89f010187d983edea7ef0364ef` |
| W2 (secondary) | `data/raw/nginx_real.log` | 6,991,577 | 51,462 | `526832433ab552466dc8623390fd92dc052b4f301b2eec94836a5c42a46937df` |

Verify before running:

```bash
sha256sum data/raw/*.log
```

Both are public sample logs from the **Elastic Examples** repository
(Apache-2.0), redistributed unmodified and verified byte-identical to upstream;
only the file names differ. Provenance, licence and privacy status are in
`CITATION_OF_INPUTS.txt` and `docs/DATASET_FREEZE.md`.

**W2 is demo/sample data, not production traffic** — three placeholder URL paths
and 65.8% 404s. The file name `nginx_real.log` is historical and misleading.

If either log is missing, `run_all.sh` stops in its preflight stage naming the
missing file. The study can be re-run against any pair of NCSA combined-format
logs by editing `WORKLOADS` in `pipeline/common.py`; nothing in the code is
specific to these two files.

## 4. Run the tests first

```bash
python3 -m pytest -q
```

Expected: **50 passed** — 24 in `tests/test_sica.py`, 26 in
`tests/test_regressions.py`. `run_all.sh` runs this as a gate before generating
any result.

The suite asserts the properties that make the numbers meaningful, not merely
that the code runs: calibration reads no label (asserted adversarially, by
relabelling the whole calibration partition); the threshold meets its declared
budget even on tied, coarse score populations; injected sessions keep the
original request count; a takeover contains no victim request after the theft; a
concurrent hijack genuinely interleaves *at every swept theft delay*; masquerade
levels are defined against the victim's binding at the theft point; session
identifiers are deterministic across processes; PR-AUC is invariant to input
order under ties; and binary baselines report no ranking metric.

## 5. Run the pipeline

```bash
./run_all.sh
```

Stages run in dependency order and a failure is fatal. `results/PIPELINE_DONE` is
written **only** if every stage of a single invocation succeeded;
`results/PIPELINE_ERR` names the failed stage otherwise. Per-stage logs land in
`results/logs/`.

Options: `./run_all.sh --quick` skips the ~43-minute robustness grid (smoke test
only — **not** a reporting run); `./run_all.sh --dev` additionally re-runs the two
development studies.

### Or stage by stage

```bash
python3 pipeline/exp01_corpus.py       # E0  corpus audit                  ~2 min
python3 pipeline/exp02_main.py         # E1  main + budget sweep; E2 baselines
python3 pipeline/exp03_ablation.py     # E3  ablation and restoration
python3 pipeline/exp05_leakage.py      # E5  leakage audit
python3 pipeline/exp06_efficiency.py   # E6  efficiency
python3 pipeline/exp04_robustness.py   # E4  adversary grid + sweeps       ~43 min
python3 pipeline/exp07_stats.py        # E7  significance + base rates
python3 pipeline/make_tables.py        # LaTeX tables and number macros
python3 pipeline/exp08_figures.py      # figures
python3 pipeline/validate.py           # consistency assertions
```

Order matters: E7 reads E2's and E3's per-run CSVs; `make_tables.py` reads E0–E7;
`exp08_figures.py` reads E1, E3 and E4.

> **Before re-running over a populated `results/`:** `run_all.sh` clears only the
> marker files, and `validate.py` checks artefact *existence*, not freshness. A
> re-run that fails partway could leave a mixture of generations. Archive the
> current `results/` first, as was done for the superseded run now in
> `results_archive/2026-09-05_prefix_abandoned/`.

## 6. Seeds

| Purpose | Seeds |
|---|---|
| E1 main, E2 baselines | **0–29** |
| E1b false-alarm-budget sweep | **0–14** (`SEEDS[:15]` in `exp02_main.py`) |
| E3, E4, E5 | **0–19** (`SEEDS[:20]`) |
| E6 efficiency | none — deterministic replay |
| Development decisions | **100–119** |
| Bootstrap resampling | seed 0, 10,000 resamples |

The reporting and development blocks are disjoint and `validate.py` asserts it.
Every stochastic choice derives from `numpy.random.default_rng(seed)`: the churn
draws, which sessions are targeted, which donor supplies each attacker's content,
the theft point, and which victim requests are displaced.

**One property worth knowing when reading the intervals.** Under the reported
`temporal` split the calibration/evaluation partition is a deterministic sort and
cut — it is **not** reseeded, and is byte-identical across all seeds. Reported
variance is therefore injection and churn variance, *not* split variance.
Sensitivity to the split choice is measured separately in E5c (temporal vs
client-disjoint vs random). Development is likewise a **seed block, not a held-out
corpus**: development seeds draw different injections over the same benign
sessions. Both facts are recorded in `docs/EXPERIMENT_CONTRACT.md` §7.

## 7. Confirm the run

```bash
python3 pipeline/validate.py
cat results/metadata/leakage_report.json | python3 -m json.tool | head -40
```

Expected: **70 passed, 0 failed**, and 26 structural leakage checks passed.

See `results/RUN_STATUS.md` for why the current tree has no `PIPELINE_DONE`
marker despite a valid, fully validated run.

## 8. What is generated, and what is frozen

**Frozen — never modify:**

```
data/raw/*.log                        the two corpora
sica/invariants.py                    V1/V2/V3 and their severities
pipeline/common.py                    SEEDS, ALPHA, and the study constants
results/tables/*.csv                  current final results
results/metadata/*.json
results/figures/*
results_archive/**                    superseded run, kept as evidence
```

**Generated — reproduced by re-running the pipeline:**

```
results/tables/    39 CSVs   (27 contracted + 12 per-run *_runs.csv)
results/metadata/   3 JSONs  (leakage_report, e6_environment, e0_sessionisation)
results/figures/   12 files  (6 figures × PDF + PNG)
results/logs/      one per stage, plus RUN_ALL.log
paper/tables/      12 .tex   including numbers.tex (94 macros)
```

**Hand-written — safe to edit:** documentation, `paper/paper.tex`, `config.yaml`
(descriptive only).

## 9. Determinism, and what varies

The detector is a deterministic function of a request stream: for fixed input it
always produces the same decisions
(`tests/test_sica.py::test_run_is_reproducible_from_the_seed`). Session
identifiers use BLAKE2s and are byte-identical across processes and machines —
they do **not** depend on `PYTHONHASHSEED`
(`tests/test_regressions.py::test_session_ids_are_deterministic_across_processes`).

**Bit-identical per-seed reproduction requires the same NumPy version**, because
`numpy.random.Generator` stream values are version-dependent for some
distributions. Aggregates across 30 seeds are stable across versions; individual
per-seed rows may differ. `requirements.txt` pins minimum versions only, and
`results/metadata/e6_environment.json` records the exact versions used for the
current results.

**Timing figures are hardware-dependent** by nature. The reproducible claim in E6
is the *shape* — flat per-request cost as live sessions grow — not the absolute
microsecond values.

## 10. Reproducibility limitations you should know before relying on this

1. **The source timestamps are degenerate.** The minute field is always `05` in
   W1 and `05`/`06` in W2, so no sessionised session exceeds 59 seconds and every
   inter-arrival time is an artefact of the upstream generator. **No claim about
   realistic temporal behaviour may rest on this data, and detection latency in
   seconds is not reportable.** Latency in attacker *requests* and the
   computational latency of E6 are unaffected, and the retained invariants read no
   clock. See `docs/DATASET_VERIFICATION.md` §6.
2. **W2 is demo data**, not production traffic (§3).
3. **Session identity is reconstructed, not observed** — these logs carry no
   authentication state. Sessions are grouped by `(address, User-Agent)` as ground
   truth only; the detector never sees that key.
4. **Attacks are constructed, not naturally occurring.** The traffic substrate is
   real; the hijacking is controlled injection. No prevalence claim about real
   deployments follows.
5. **Two residual marginal shortcuts exist and are documented, not removed**:
   `distinct_paths` on W2 (≈0.73 AUC, an artefact of the three-path universe) and
   `median_gap_s` on W1 (≈0.32, an artefact of gap compression over synthetic
   timestamps). Neither can reach the detector, which reads no path count, gap,
   byte count, request count or duration.
6. **No git repository exists**, so no source-code commit can be recorded against
   the current results.
7. **`results/tables/e0_corpus.csv` carries a superseded W2 description string.**
   The label in `pipeline/common.py` was corrected on 2026-09-13; the frozen CSV
   was deliberately not regenerated for a cosmetic change. It resolves on the next
   full run. Nothing downstream reads that column.

## 11. Changing the configuration

The executable source of truth is `pipeline/common.py` and the component defaults
in `sica/`. **`config.yaml` is a descriptive mirror and is not loaded by any
code** — editing it changes nothing.

| To change | Edit |
|---|---|
| False-alarm budget | `ALPHA` in `pipeline/common.py` |
| Which invariants are used | `DEFAULT_INVARIANTS` in `sica/invariants.py` |
| Invariant severities | `InvariantParams` in `sica/invariants.py` |
| Benign mobility rates | `ChurnConfig` in `sica/churn.py`; `MONOTONE_CHURN` / `FLAPPING_CHURN` in `pipeline/common.py` |
| Attack construction | `InjectionConfig` in `sica/inject.py` |
| Sessionisation | `IDLE_SECONDS`, `MIN_REQUESTS` in `pipeline/common.py` |
| Workloads | `WORKLOADS` in `pipeline/common.py` |

Any such change invalidates the frozen results: re-run the full pipeline, since a
partially re-run `results/tables/` would mix configurations. The change-control
procedure is `CHECKPOINT.md` §9.

## 12. Compile the manuscript

```bash
cd paper
pdflatex paper && bibtex paper && pdflatex paper && pdflatex paper
```

`IEEEtran.cls` is vendored so the manuscript compiles without the
`texlive-publishers` package. On a minimal TeX Live the remaining requirements are
`amsmath`, `booktabs`, `graphicx`, `url`, `balance`, `hyperref` and `microtype`.

The manuscript reads figures from `../results/figures/` and tables from
`tables/`, so §5 must have completed first. **No number in the manuscript is typed
by hand**: `pipeline/make_tables.py` writes every table body and every inline value
as a LaTeX macro, so a table cannot drift from the run that produced it.

## 13. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ModuleNotFoundError: sica` | Run from the repository root, or rely on `tests/conftest.py` and the `sys.path` insert at the top of each pipeline script |
| Preflight reports missing logs | The two access logs are absent; see §3 |
| `make_tables.py` raises `FileNotFoundError` | An experiment stage has not run. Run them in the order in §5 |
| `exp08_figures.py` raises on `e4_*` | E4 has not run; it is skipped by `--quick` |
| `validate.py` reports a missing table | Same cause; re-run the stage that produces it |
| `validate.py` reports a missing macro | `paper.tex` references a macro `make_tables.py` no longer generates — update the manuscript, not the generator |
| LaTeX cannot find `tables/numbers.tex` | Run `make_tables.py` before compiling |
| Per-seed rows differ from ours | Different NumPy version; see §9. Aggregates should match |
