"""Emit every LaTeX table in the paper directly from the frozen result CSVs.

No number in the manuscript is typed by hand: each table body is written here
and included by the paper, so a table cannot drift from the run that produced
it.  Inline numbers in the prose are emitted as LaTeX macros into
``paper/tables/numbers.tex`` for the same reason.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.common import ROOT, TABLES, Timer
from sica.inject import LEVELS_ALL

OUT = ROOT / "paper" / "tables"
OUT.mkdir(parents=True, exist_ok=True)

WL = {"W1_web": "W1 web", "W2_apt": "W2 apt"}
INV_SHORT = {
    "V1_agent_mutation": "$v_1$ agent", "V2_scope_discontinuity": "$v_2$ scope",
    "V3_binding_fork": "$v_3$ fork", "V4_transition_velocity": "$v_4$ velocity",
    "V5_rate_discontinuity": "$v_5$ rate", "V6_navigation_break": "$v_6$ nav.",
}
BASE_SHORT = {
    "SICA (proposed)": "\\textbf{SICA (this work)}",
    "pin_ip": "pin address", "pin_prefix24": "pin /24", "pin_scope16": "pin /16",
    "pin_useragent": "pin agent string", "pin_useragent_core": "pin agent core",
    "pin_ip_or_useragent": "pin address $\\vee$ agent",
    "pin_ip_and_useragent": "pin address $\\wedge$ agent",
    "score_distinct_bindings": "distinct bindings", "score_max_request_rate": "peak rate",
    "score_burstiness": "burstiness",
}


def t(name: str) -> pd.DataFrame:
    return pd.read_csv(TABLES / f"{name}.csv")


def write(body: str, name: str) -> None:
    (OUT / f"{name}.tex").write_text(body)
    print(f"  wrote paper/tables/{name}.tex")


def f(x, n=3):
    return "--" if pd.isna(x) else f"{float(x):.{n}f}"


def ci(row, m, n=3):
    return f"{f(row[m + '_mean'], n)}"


# ---------------------------------------------------------------------------

def tbl_corpus() -> None:
    d = t("e0_corpus")
    rows = []
    for _, r in d.iterrows():
        rows.append(" & ".join([
            WL[r.workload], f"{r.requests_parsed:,}", f"{r.unique_addresses:,}",
            f"{r.unique_scope16:,}", f"{r.unique_user_agents:,}",
            f"{r.unique_agent_cores:,}", f"{r.referrer_coverage*100:.1f}\\%",
            f"{r.span_days:.1f}", f"{r.sessions:,}", f"{r.requests_in_sessions:,}",
            f"{r.requests_per_session_median:.0f}",
            f"{r.requests_per_session_p90:.0f}"]) + r" \\")
    write("\n".join(rows), "corpus")


def tbl_main() -> None:
    d = t("e1_main_summary")
    rows = []
    for _, r in d.iterrows():
        rows.append(" & ".join([
            WL[r.workload],
            f"{r.n_attack_sessions_mean:.0f}",
            f"{ci(r,'precision')}", f"{ci(r,'recall')}",
            f"[{f(r.recall_ci_lo)}, {f(r.recall_ci_hi)}]",
            f"{ci(r,'f1')}",
            f"{f(r.fpr_mean)}", f"[{f(r.fpr_ci_lo)}, {f(r.fpr_ci_hi)}]",
            f"{ci(r,'roc_auc')}", f"{ci(r,'pr_auc')}",
            f"{r.latency_requests_median_mean:.1f}"]) + r" \\")
    write("\n".join(rows), "main")


def tbl_scenarios() -> None:
    d = t("e4_scenario_grid")
    rows = []
    # The level list is the frozen contract's LEVELS_ALL, never a local literal:
    # a hard-coded subset silently dropped L5 from this table once already.
    for level in LEVELS_ALL:
        cells = [f"\\texttt{{{level}}}"]
        for wl in ["W1_web", "W2_apt"]:
            for mode in ["takeover", "concurrent"]:
                r = d[(d.workload == wl) & (d.level == level) & (d["mode"] == mode)]
                cells.append(f(r.recall_mean.iloc[0]) if len(r) else "--")
        rows.append(" & ".join(cells) + r" \\")
    write("\n".join(rows), "scenarios")


def tbl_false_alarms() -> None:
    d = t("e1_false_alarms_by_benign_class")
    order = ["benign", "M2_agent_update", "M1_handover:host", "M1_handover:subnet",
             "M1_handover:scope", "M3_combined:host", "M3_combined:subnet",
             "M3_combined:scope", "M4_flapping:host", "M4_flapping:subnet",
             "M4_flapping:scope"]
    pretty = {"benign": "no churn (unmodified real session)",
              "M2_agent_update": "agent version upgrade",
              "M1_handover:host": "address change, same /24",
              "M1_handover:subnet": "address change, same /16",
              "M1_handover:scope": "address change, new /16",
              "M3_combined:host": "address (same /24) + agent upgrade",
              "M3_combined:subnet": "address (same /16) + agent upgrade",
              "M3_combined:scope": "address (new /16) + agent upgrade",
              "M4_flapping:host": "interface flapping, same /24",
              "M4_flapping:subnet": "interface flapping, same /16",
              "M4_flapping:scope": "interface flapping, across /16"}
    rows = []
    for key in order:
        cells = [pretty[key]]
        for wl in ["W1_web", "W2_apt"]:
            r = d[(d.workload == wl) & (d.benign_class == key)]
            if len(r):
                cells += [f"{int(r.sessions.iloc[0]):,}", f"{r.fpr.iloc[0]*100:.1f}"]
            else:
                cells += ["--", "--"]
        rows.append(" & ".join(cells) + r" \\")
    write("\n".join(rows), "false_alarms")


def tbl_baselines() -> None:
    d = t("e2_baselines")
    order = ["SICA (proposed)", "pin_ip", "pin_prefix24", "pin_scope16",
             "pin_useragent", "pin_useragent_core", "pin_ip_or_useragent",
             "pin_ip_and_useragent", "score_distinct_bindings",
             "score_max_request_rate", "score_burstiness"]
    tests = t("e7_baseline_tests") if (TABLES / "e7_baseline_tests.csv").exists() else None
    rows = []
    for name in order:
        cells = [BASE_SHORT[name]]
        for wl in ["W1_web", "W2_apt"]:
            r = d[(d.workload == wl) & (d.baseline == name)]
            if not len(r):
                cells += ["--"] * 4
                continue
            r = r.iloc[0]
            mark = ""
            if tests is not None and name != "SICA (proposed)":
                tr = tests[(tests.workload == wl) &
                           (tests.comparison == f"SICA (proposed) vs {name}")]
                if len(tr) and float(tr.f1_p_holm.iloc[0]) < 0.05:
                    mark = "$^{\\ast}$"
            cells += [f(r.recall_mean), f(r.fpr_mean), f(r.precision_mean),
                      f(r.f1_mean) + mark]
        rows.append(" & ".join(cells) + r" \\")
    write("\n".join(rows), "baselines")


def tbl_ablation() -> None:
    d = t("e3_ablation")
    tests = {}
    p = TABLES / "e7_ablation_tests_leave_one_out.csv"
    if p.exists():
        tests = t("e7_ablation_tests_leave_one_out")
    rows = []
    ref = d[d.family == "reference"].set_index("workload")
    for variant in sorted(d[d.family == "leave_one_out"].variant.unique()):
        inv = variant.replace("minus_", "")
        cells = [INV_SHORT[inv]]
        for wl in ["W1_web", "W2_apt"]:
            r = d[(d.workload == wl) & (d.variant == variant)]
            if not len(r):
                cells += ["--"] * 3
                continue
            r = r.iloc[0]
            d_f1 = r.f1_mean - ref.loc[wl].f1_mean
            d_auc = r.roc_auc_mean - ref.loc[wl].roc_auc_mean
            mark = ""
            if len(tests):
                tr = tests[(tests.workload == wl) &
                           (tests.comparison == f"full vs {variant}")]
                if len(tr) and float(tr.f1_p_holm.iloc[0]) < 0.05:
                    mark = "$^{\\ast}$"
            cells += [f(r.fpr_mean), f"{d_f1:+.3f}{mark}", f"{d_auc:+.3f}"]
        rows.append(" & ".join(cells) + r" \\")
    write("\n".join(rows), "ablation")

    rows = []
    for variant, label in [("equal_weights", "uniform weights"),
                           ("no_migration", "no reference migration"),
                           ("accumulator", "decayed evidence accumulator")]:
        cells = [label]
        for wl in ["W1_web", "W2_apt"]:
            r = d[(d.workload == wl) & (d.variant == variant)]
            if not len(r):
                cells += ["--"] * 3
                continue
            r = r.iloc[0]
            cells += [f(r.fpr_mean), f"{r.f1_mean - ref.loc[wl].f1_mean:+.3f}",
                      f"{r.roc_auc_mean - ref.loc[wl].roc_auc_mean:+.3f}"]
        rows.append(" & ".join(cells) + r" \\")
    write("\n".join(rows), "design_ablation")


def tbl_leakage() -> None:
    marg = t("e5_marginal_audit")
    ref = t("e5_content_reference")
    split = t("e5_split_sensitivity")
    rows = []
    feats = sorted(marg.feature.unique())
    for feat in feats:
        cells = [feat.replace("_", " ")]
        for wl in ["W1_web", "W2_apt"]:
            r = marg[(marg.workload == wl) & (marg.feature == feat)]
            cells.append(f(r.roc_auc_mean.iloc[0]) if len(r) else "--")
        rows.append(" & ".join(cells) + r" \\")
    rows.append(r"\midrule")
    cells = ["\\emph{all eight jointly} (one-class)"]
    for wl in ["W1_web", "W2_apt"]:
        r = ref[ref.workload == wl]
        cells.append(f(r.roc_auc_mean.iloc[0]) if len(r) else "--")
    rows.append(" & ".join(cells) + r" \\")
    write("\n".join(rows), "leakage")

    rows = []
    for sp, label in [("temporal", "temporal (reported)"),
                      ("client", "client-disjoint"), ("random", "random")]:
        cells = [label]
        for wl in ["W1_web", "W2_apt"]:
            r = split[(split.workload == wl) & (split.split == sp)]
            r = r.iloc[0]
            cells += [f(r.recall_mean), f(r.fpr_mean), f(r.roc_auc_mean)]
        rows.append(" & ".join(cells) + r" \\")
    write("\n".join(rows), "splits")


def tbl_efficiency() -> None:
    d = t("e6_scaling")
    rows = []
    for wl in ["W1_web", "W2_apt"]:
        s = d[d.workload == wl].sort_values("live_sessions")
        for _, r in s.iterrows():
            rows.append(" & ".join([
                WL[wl], f"{int(r.live_sessions):,}", f"{int(r.requests):,}",
                f"{r.throughput_req_per_s/1000:.1f}",
                f"{r.latency_us_median:.1f}", f"{r.latency_us_p99:.1f}",
                f"{r.state_bytes_per_session/1024:.2f}"]) + r" \\")
    write("\n".join(rows), "efficiency")


def tbl_base_rate() -> None:
    d = t("e7_base_rate")
    rows = []
    for pi in sorted(d.prevalence.unique()):
        exponent = math.log10(pi)
        cells = [f"$10^{{{int(round(exponent))}}}$"
                 if abs(exponent - round(exponent)) < 1e-9 else f"{pi:g}"]
        for wl in ["W1_web", "W2_apt"]:
            r = d[(d.workload == wl) & (d.prevalence == pi)].iloc[0]
            cells += [f"{r.precision*100:.1f}", f"{r.false_alerts_per_million:,.0f}"]
        rows.append(" & ".join(cells) + r" \\")
    write("\n".join(rows), "base_rate")


def macros() -> None:
    """Every number quoted in the prose, as a macro."""
    corpus = t("e0_corpus").set_index("workload")
    main = t("e1_main_summary").set_index("workload")
    eff = t("e6_efficiency").set_index("workload")
    cal = t("e1_calibration_summary").set_index("workload")
    scen = t("e4_scenario_grid")
    sweep = t("e1_alpha_sweep")
    base = t("e2_baselines")
    marg = t("e5_marginal_audit")
    ref = t("e5_content_reference").set_index("workload")

    m = {}
    for wl, tag in [("W1_web", "Web"), ("W2_apt", "Apt")]:
        m[f"corpusReq{tag}"] = f"{int(corpus.loc[wl].requests_parsed):,}"
        m[f"corpusSess{tag}"] = f"{int(corpus.loc[wl].sessions):,}"
        m[f"corpusAddr{tag}"] = f"{int(corpus.loc[wl].unique_addresses):,}"
        m[f"corpusCores{tag}"] = f"{int(corpus.loc[wl].unique_agent_cores)}"
        m[f"recall{tag}"] = f(main.loc[wl].recall_mean)
        m[f"recallLo{tag}"] = f(main.loc[wl].recall_ci_lo)
        m[f"recallHi{tag}"] = f(main.loc[wl].recall_ci_hi)
        m[f"prec{tag}"] = f(main.loc[wl].precision_mean)
        m[f"fone{tag}"] = f(main.loc[wl].f1_mean)
        m[f"fpr{tag}"] = f"{main.loc[wl].fpr_mean*100:.2f}"
        m[f"auc{tag}"] = f(main.loc[wl].roc_auc_mean)
        m[f"prauc{tag}"] = f(main.loc[wl].pr_auc_mean)
        m[f"lat{tag}"] = f"{main.loc[wl].latency_requests_median_mean:.1f}"
        m[f"tput{tag}"] = f"{eff.loc[wl].throughput_req_per_s/1000:.0f}"
        m[f"usMed{tag}"] = f"{eff.loc[wl].latency_us_median:.0f}"
        m[f"usPnn{tag}"] = f"{eff.loc[wl].latency_us_p99:.0f}"
        m[f"stateKB{tag}"] = f"{eff.loc[wl].state_bytes_per_session/1024:.1f}"
        m[f"calAlarm{tag}"] = f"{cal.loc[wl].calibration_alarm_rate_mean*100:.2f}"
        # LaTeX control sequences may not contain digits, so the level index is
        # spelled out.  A macro named \recL0TakeoverWeb would not compile.
        level_word = {"L0": "Lzero", "L1": "Lone", "L2": "Ltwo",
                      "L3": "Lthree", "L4": "Lfour", "L5": "Lfive"}
        for level, word in level_word.items():
            for mode in ["takeover", "concurrent"]:
                r = scen[(scen.workload == wl) & (scen.level == level) &
                         (scen["mode"] == mode)]
                if len(r):
                    m[f"rec{word}{mode.capitalize()}{tag}"] = f(r.recall_mean.iloc[0])
        for a, key in [(0.05, "Five"), (0.02, "Two")]:
            r = sweep[(sweep.workload == wl) & (sweep.alpha == a)]
            if len(r):
                m[f"recAlpha{key}{tag}"] = f(r.recall_mean.iloc[0])
                m[f"fprAlpha{key}{tag}"] = f"{r.fpr_mean.iloc[0]*100:.1f}"
        for bl, key in [("pin_ip", "PinIp"), ("pin_useragent_core", "PinCore"),
                        ("pin_prefix24", "PinTwentyFour")]:
            r = base[(base.workload == wl) & (base.baseline == bl)]
            if len(r):
                m[f"{key}Recall{tag}"] = f(r.recall_mean.iloc[0])
                m[f"{key}Fpr{tag}"] = f"{r.fpr_mean.iloc[0]*100:.1f}"
                # No ``...Auc...`` macro is emitted for a pinning rule.  These rules are
                # binary, so the quantity that used to fill it was identically balanced
                # accuracy, and printing it beside SICA's ranking AUC implied a score
                # resolution the rule does not have.  Balanced accuracy is emitted under its
                # own name instead; see ``sica.harness.run_baselines``.
                m[f"{key}BalAcc{tag}"] = f(r.balanced_accuracy_mean.iloc[0])
        mm = marg[marg.workload == wl]
        m[f"margMax{tag}"] = f(mm.roc_auc_mean.max())
        m[f"margMaxFeat{tag}"] = mm.loc[mm.roc_auc_mean.idxmax(), "feature"].replace("_", " ")
        m[f"contentAuc{tag}"] = f(ref.loc[wl].roc_auc_mean)
        m[f"contentFone{tag}"] = f(ref.loc[wl].f1_mean)

    body = "\n".join(f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in sorted(m.items()))
    write(body, "numbers")


if __name__ == "__main__":
    with Timer("LaTeX tables"):
        tbl_corpus(); tbl_main(); tbl_scenarios(); tbl_false_alarms()
        tbl_baselines(); tbl_ablation(); tbl_leakage(); tbl_efficiency()
        tbl_base_rate(); macros()
