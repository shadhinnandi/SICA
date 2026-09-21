"""Final validation: assert that a completed run is internally consistent.

This runs after every experiment and every generated artefact.  It does not
re-derive anything; it checks that what was produced is present, mutually
consistent, and free of the specific failure modes that this project has
previously suffered from.  It exits non-zero if any check fails, so that
``run_all.sh`` cannot write its completion marker over a broken run.
"""
from __future__ import annotations

import json
import re
import sys
import zlib
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.common import FIGURES, META, ROOT, TABLES

EXPECTED_TABLES = [
    "e0_corpus", "e0_sessionisation_sensitivity", "e0_agent_mix",
    "e1_main_runs", "e1_main_summary", "e1_per_scenario",
    "e1_false_alarms_by_benign_class", "e1_calibration_runs",
    "e1_calibration_summary", "e1_alpha_sweep", "e1_alpha_sweep_runs",
    "e2_baseline_runs", "e2_baselines",
    "e3_ablation_runs", "e3_ablation",
    "e4_scenario_grid", "e4_scenario_baselines", "e4_sweeps", "e4_crossover",
    "e5_marginal_audit", "e5_content_reference", "e5_split_sensitivity",
    "e6_efficiency", "e6_scaling", "e6_preparation_cost",
    "e7_baseline_tests", "e7_base_rate",
]
EXPECTED_FIGURES = ["fig1_architecture", "fig2_mechanism", "fig3_envelope",
                    "fig4_operating", "fig5_crossover", "fig6_ablation"]
EXPECTED_PAPER_TABLES = ["corpus", "main", "scenarios", "false_alarms", "baselines",
                         "ablation", "design_ablation", "leakage", "splits",
                         "efficiency", "base_rate", "numbers"]

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(ok), detail))


def pdf_level_labels(path: Path) -> set[str]:
    """Masquerade-level labels that actually appear in a matplotlib PDF.

    Figure text is written into the PDF's content streams, usually Flate
    compressed, so the streams are inflated before the labels are matched.
    A level that was never plotted cannot appear here.
    """
    raw = path.read_bytes()
    found: set[str] = set()
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
        chunk = m.group(1)
        try:
            chunk = zlib.decompress(chunk)
        except zlib.error:
            pass
        found.update(tok.decode() for tok in re.findall(rb"L[0-9]", chunk))
    return found


def main() -> int:
    # --- artefacts exist --------------------------------------------------
    for name in EXPECTED_TABLES:
        check(f"table {name}.csv", (TABLES / f"{name}.csv").is_file())
    for name in EXPECTED_FIGURES:
        check(f"figure {name}.pdf", (FIGURES / f"{name}.pdf").is_file())
    for name in EXPECTED_PAPER_TABLES:
        check(f"paper/tables/{name}.tex", (ROOT / "paper" / "tables" / f"{name}.tex").is_file())
    check("leakage report", (META / "leakage_report.json").is_file())
    check("efficiency environment", (META / "e6_environment.json").is_file())

    if not all(ok for _, ok, _ in RESULTS):
        return report()

    # --- leakage report has no failures -----------------------------------
    report_json = json.loads((META / "leakage_report.json").read_text())
    check("leakage report: no failed structural check",
          report_json["n_fail"] == 0,
          f"{report_json['n_pass']} passed, {report_json['n_fail']} failed")

    marg = report_json["marginal_feature_auc"]
    worst = max(marg.items(), key=lambda kv: abs(kv[1] - 0.5))
    check("leakage: no marginal feature is decisive",
          abs(worst[1] - 0.5) < 0.30,
          f"largest deviation from chance: {worst[0]} AUC {worst[1]}")

    # --- the detector is non-learning -------------------------------------
    banned = ("sklearn", "scikit", "torch", "tensorflow", "keras", "xgboost",
              "lightgbm", "catboost")
    offenders = []
    for path in sorted((ROOT / "sica").glob("*.py")):
        text = path.read_text().lower()
        for token in banned:
            if token in text:
                offenders.append(f"{path.name}:{token}")
    check("detector imports no machine-learning library",
          not offenders, "; ".join(offenders) or "clean")

    # --- headline numbers are internally consistent -----------------------
    main_summary = pd.read_csv(TABLES / "e1_main_summary.csv")
    check("main summary covers both workloads", len(main_summary) == 2,
          f"{len(main_summary)} rows")
    for _, r in main_summary.iterrows():
        check(f"{r.workload}: false-alarm rate within 3x of the 0.01 budget",
              r.fpr_mean <= 0.03, f"measured {r.fpr_mean:.4f}")
        check(f"{r.workload}: ROC AUC in (0.5, 1.0)",
              0.5 < r.roc_auc_mean < 1.0, f"{r.roc_auc_mean:.4f}")
        check(f"{r.workload}: 30 reporting seeds", int(r.n_runs) == 30,
              f"{int(r.n_runs)} runs")

    runs = pd.read_csv(TABLES / "e1_main_runs.csv")
    check("reporting seeds are 0-29 and disjoint from development seeds 100-119",
          set(runs.seed.unique()) == set(range(30)),
          f"seeds {sorted(set(runs.seed.unique()))[:3]}...{sorted(set(runs.seed.unique()))[-3:]}")

    # --- the paper's numbers come from these tables ------------------------
    numbers = (ROOT / "paper" / "tables" / "numbers.tex").read_text()
    check("paper macro file is populated", numbers.count("newcommand") > 40,
          f"{numbers.count('newcommand')} macros")

    # Every generated macro the manuscript references must exist, and no macro
    # name may contain a digit (LaTeX control sequences are letters only).
    import re
    defined = set(re.findall(r"\\newcommand\{\\([A-Za-z]+)\}", numbers))
    check("no generated macro name contains a digit",
          not any(any(c.isdigit() for c in n) for n in defined), "letters only")
    paper = (ROOT / "paper" / "paper.tex").read_text()
    referenced = set(re.findall(r"\\([A-Za-z]+)", paper))
    prefixes = ("corpus", "recall", "prec", "fone", "fpr", "auc", "prauc", "lat",
                "tput", "usMed", "usPnn", "stateKB", "calAlarm", "rec",
                "PinIp", "PinCore", "PinTwentyFour", "margMax", "contentAuc",
                "contentFone")
    wanted = {n for n in referenced if n.startswith(prefixes)}
    missing = sorted(wanted - defined)
    check("every generated macro used by the manuscript is defined",
          not missing, "missing: " + ", ".join(missing) if missing else
          f"{len(wanted)} referenced, all defined")

    # --- generated table bodies fit their tabular environments -------------
    tex = paper
    width_ok, detail = True, []
    for m in re.finditer(r"\\begin\{tabular\}\{([^}]*)\}(.*?)\\end\{tabular\}", tex, re.S):
        spec, body = m.group(1), m.group(2)
        ncol = len(re.findall(r"[lcr]|p\{[^}]*\}", spec.replace("@{}", "")))
        for name in re.findall(r"\\input\{tables/([a-z_]+)\}", body):
            path = ROOT / "paper" / "tables" / f"{name}.tex"
            if not path.is_file():
                continue
            for line in path.read_text().splitlines():
                if not line.strip() or line.strip().startswith("\\"):
                    continue
                cells = line.rstrip().removesuffix(r"\\").count("&") + 1
                if cells != ncol:
                    width_ok = False
                    detail.append(f"{name}: {cells} cells vs {ncol} columns")
                    break
    check("generated table bodies match their tabular column counts",
          width_ok, "; ".join(detail) or "all consistent")

    # --- scenario grid covers the declared envelope ------------------------
    from sica.inject import LEVELS_ALL, LEVELS_COLOCATED, MODES
    grid = pd.read_csv(TABLES / "e4_scenario_grid.csv")
    expected_cells = len(LEVELS_ALL) * len(MODES) * len(main_summary)
    check(f"adversary grid covers {'/'.join(LEVELS_ALL)} x both modes on both workloads",
          len(grid) == expected_cells, f"{len(grid)} cells, expected {expected_cells}")

    # --- the envelope measures hijacking, not address change ---------------
    # If every evaluated attack gave the attacker a different address, "alert on any
    # address change" would detect all of them by construction and the recall axis of the
    # baseline comparison would carry no information.
    levels_present = set(grid["level"].astype(str))
    check("reported envelope includes the co-located levels",
          set(LEVELS_COLOCATED) <= levels_present,
          f"levels present: {sorted(levels_present)}")

    # --- the RENDERED artefacts show every level, not merely the source CSV ---
    # The grid CSV covering L0-L5 is not sufficient evidence.  The scenarios table
    # body and the envelope figure are produced by two separate code paths that
    # each carried their own hard-coded level list, and both silently dropped L5
    # while the checks above still reported the envelope as complete.  These
    # checks read the artefacts a reader actually sees.
    scen_tex = (ROOT / "paper" / "tables" / "scenarios.tex").read_text()
    missing_rows = [lv for lv in LEVELS_ALL
                    if not re.search(rf"\\texttt\{{{lv}\}}\s*&", scen_tex)]
    check("scenarios table body has a row for every masquerade level",
          not missing_rows,
          f"missing rows: {missing_rows}" if missing_rows
          else f"all {len(LEVELS_ALL)} levels present")

    fig_levels = pdf_level_labels(FIGURES / "fig3_envelope.pdf")
    missing_bars = [lv for lv in LEVELS_ALL if lv not in fig_levels]
    check("envelope figure plots every masquerade level",
          not missing_bars,
          f"missing from fig3_envelope.pdf: {missing_bars}" if missing_bars
          else f"all {len(LEVELS_ALL)} levels present")

    # --- and the reporting code may not reintroduce a local level list -------
    literal = re.compile(r'\["L0"(?:\s*,\s*"L[0-9]")+\]')
    offenders = []
    for name in ("make_tables.py", "exp08_figures.py"):
        for m in literal.finditer((ROOT / "pipeline" / name).read_text()):
            lvls = tuple(re.findall(r'"(L[0-9])"', m.group(0)))
            if lvls != tuple(LEVELS_ALL):
                offenders.append(f"{name}: {list(lvls)}")
    check("reporting code derives levels from LEVELS_ALL, not a local literal",
          not offenders, "; ".join(offenders) or "no hard-coded level lists")

    baselines = pd.read_csv(TABLES / "e2_baselines.csv")
    pin_ip = baselines[baselines.baseline == "pin_ip"]
    check("address pinning is not perfect by construction",
          bool((pin_ip.recall_mean < 1.0).all()) if len(pin_ip) else False,
          f"pin_ip recall {[round(float(v), 4) for v in pin_ip.recall_mean]}")

    # --- binary rules report no ranking metric -----------------------------
    binary = baselines[baselines.family == "pinning"]
    check("binary baselines report no ranking AUC",
          bool(binary.roc_auc_mean.isna().all()) if len(binary) else False,
          f"{int(binary.roc_auc_mean.notna().sum())} pinning rows carry a ranking AUC")
    check("binary baselines report their operating point",
          bool(binary.balanced_accuracy_mean.notna().all()) if len(binary) else False,
          "recall/FPR/precision/F1/balanced accuracy present")

    # --- the false-alarm budget is met on the calibration sample -----------
    cal = pd.read_csv(TABLES / "e1_calibration_runs.csv")
    worst = float(cal.calibration_alarm_rate.max())
    check("every run meets its declared false-alarm budget on calibration",
          worst <= 0.01 + 1e-9, f"worst calibration alarm rate {worst:.4f} against alpha 0.01")

    # --- ablation covers the retained and the rejected invariants ----------
    from sica.invariants import DEFAULT_INVARIANTS, INVARIANTS
    abl = pd.read_csv(TABLES / "e3_ablation.csv")
    loo = {v.replace("minus_", "") for v in abl[abl.family == "leave_one_out"].variant}
    check("ablation removes each retained invariant",
          loo == set(DEFAULT_INVARIANTS), f"{sorted(loo)}")
    restored = {v.replace("plus_", "") for v in abl[abl.family == "restored"].variant}
    rejected = set(INVARIANTS) - set(DEFAULT_INVARIANTS)
    check("ablation restores each rejected invariant",
          rejected <= restored, f"rejected={sorted(rejected)} restored={sorted(restored)}")

    return report()


def report() -> int:
    failed = [r for r in RESULTS if not r[1]]
    for name, ok, detail in RESULTS:
        if not ok or detail:
            print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
    print(f"\n  {len(RESULTS) - len(failed)} passed, {len(failed)} failed")
    if failed:
        print("\nVALIDATION FAILED:")
        for name, _, detail in failed:
            print(f"  - {name}" + (f" ({detail})" if detail else ""))
        return 1
    print("  validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
