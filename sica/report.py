"""Reporting: LaTeX tables for the paper, figures, summary and validation.

Everything here reads the CSVs in ``results/tables/``; nothing is recomputed and
no number is typed by hand.

    make_tables()    paper/tables/*.tex (table bodies and the numbers.tex macros)
    make_figures()   results/figures/fig1-fig6 (.pdf and .png)
    write_summary()  results/summary/summary.md
    validate()       integrity checks over the finished result set
"""
from __future__ import annotations

import json
import math
import re
import zlib
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np
import pandas as pd
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

from .benchmark import LEVELS_ALL, LEVELS_COLOCATED, MODES
from .experiments import FIGURES, ROOT, SUMMARY, TABLES, Timer
from .invariants import DEFAULT_INVARIANTS, INVARIANTS


# ============================================================================
# LaTeX tables for the paper
# ============================================================================

PAPER_TABLES = ROOT / "paper" / "tables"

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


def _write_tex(body: str, name: str) -> None:
    PAPER_TABLES.mkdir(parents=True, exist_ok=True)
    (PAPER_TABLES / f"{name}.tex").write_text(body)
    print(f"  wrote paper/tables/{name}.tex")


def fmt(x, n=3):
    return "--" if pd.isna(x) else f"{float(x):.{n}f}"


def _ci(row, m, n=3):
    return f"{fmt(row[m + '_mean'], n)}"


# ---------------------------------------------------------------------------

def tbl_corpus() -> None:
    d = table("e0_corpus")
    rows = []
    for _, r in d.iterrows():
        rows.append(" & ".join([
            WL[r.workload], f"{r.requests_parsed:,}", f"{r.unique_addresses:,}",
            f"{r.unique_scope16:,}", f"{r.unique_user_agents:,}",
            f"{r.unique_agent_cores:,}", f"{r.referrer_coverage*100:.1f}\\%",
            f"{r.span_days:.1f}", f"{r.sessions:,}", f"{r.requests_in_sessions:,}",
            f"{r.requests_per_session_median:.0f}",
            f"{r.requests_per_session_p90:.0f}"]) + r" \\")
    _write_tex("\n".join(rows), "corpus")


def tbl_main() -> None:
    d = table("e1_main_summary")
    rows = []
    for _, r in d.iterrows():
        rows.append(" & ".join([
            WL[r.workload],
            f"{r.n_attack_sessions_mean:.0f}",
            f"{_ci(r,'precision')}", f"{_ci(r,'recall')}",
            f"[{fmt(r.recall_ci_lo)}, {fmt(r.recall_ci_hi)}]",
            f"{_ci(r,'f1')}",
            f"{fmt(r.fpr_mean)}", f"[{fmt(r.fpr_ci_lo)}, {fmt(r.fpr_ci_hi)}]",
            f"{_ci(r,'roc_auc')}", f"{_ci(r,'pr_auc')}",
            f"{r.latency_requests_median_mean:.1f}"]) + r" \\")
    _write_tex("\n".join(rows), "main")


def tbl_scenarios() -> None:
    d = table("e4_scenario_grid")
    rows = []
    # The level list is the frozen contract's LEVELS_ALL, never a local literal:
    # a hard-coded subset silently dropped L5 from this table once already.
    for level in LEVELS_ALL:
        cells = [f"\\texttt{{{level}}}"]
        for wl in ["W1_web", "W2_apt"]:
            for mode in ["takeover", "concurrent"]:
                r = d[(d.workload == wl) & (d.level == level) & (d["mode"] == mode)]
                cells.append(fmt(r.recall_mean.iloc[0]) if len(r) else "--")
        rows.append(" & ".join(cells) + r" \\")
    _write_tex("\n".join(rows), "scenarios")


def tbl_false_alarms() -> None:
    d = table("e1_false_alarms_by_benign_class")
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
    _write_tex("\n".join(rows), "false_alarms")


def tbl_baselines() -> None:
    d = table("e2_baselines")
    order = ["SICA (proposed)", "pin_ip", "pin_prefix24", "pin_scope16",
             "pin_useragent", "pin_useragent_core", "pin_ip_or_useragent",
             "pin_ip_and_useragent", "score_distinct_bindings",
             "score_max_request_rate", "score_burstiness"]
    tests = table("e7_baseline_tests") if (TABLES / "e7_baseline_tests.csv").exists() else None
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
            cells += [fmt(r.recall_mean), fmt(r.fpr_mean), fmt(r.precision_mean),
                      fmt(r.f1_mean) + mark]
        rows.append(" & ".join(cells) + r" \\")
    _write_tex("\n".join(rows), "baselines")


def tbl_ablation() -> None:
    d = table("e3_ablation")
    tests = {}
    p = TABLES / "e7_ablation_tests_leave_one_out.csv"
    if p.exists():
        tests = table("e7_ablation_tests_leave_one_out")
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
            cells += [fmt(r.fpr_mean), f"{d_f1:+.3f}{mark}", f"{d_auc:+.3f}"]
        rows.append(" & ".join(cells) + r" \\")
    _write_tex("\n".join(rows), "ablation")

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
            cells += [fmt(r.fpr_mean), f"{r.f1_mean - ref.loc[wl].f1_mean:+.3f}",
                      f"{r.roc_auc_mean - ref.loc[wl].roc_auc_mean:+.3f}"]
        rows.append(" & ".join(cells) + r" \\")
    _write_tex("\n".join(rows), "design_ablation")


def tbl_leakage() -> None:
    marg = table("e5_marginal_audit")
    ref = table("e5_content_reference")
    split = table("e5_split_sensitivity")
    rows = []
    feats = sorted(marg.feature.unique())
    for feat in feats:
        cells = [feat.replace("_", " ")]
        for wl in ["W1_web", "W2_apt"]:
            r = marg[(marg.workload == wl) & (marg.feature == feat)]
            cells.append(fmt(r.roc_auc_mean.iloc[0]) if len(r) else "--")
        rows.append(" & ".join(cells) + r" \\")
    rows.append(r"\midrule")
    cells = ["\\emph{all eight jointly} (one-class)"]
    for wl in ["W1_web", "W2_apt"]:
        r = ref[ref.workload == wl]
        cells.append(fmt(r.roc_auc_mean.iloc[0]) if len(r) else "--")
    rows.append(" & ".join(cells) + r" \\")
    _write_tex("\n".join(rows), "leakage")

    rows = []
    for sp, label in [("temporal", "temporal (reported)"),
                      ("client", "client-disjoint"), ("random", "random")]:
        cells = [label]
        for wl in ["W1_web", "W2_apt"]:
            r = split[(split.workload == wl) & (split.split == sp)]
            r = r.iloc[0]
            cells += [fmt(r.recall_mean), fmt(r.fpr_mean), fmt(r.roc_auc_mean)]
        rows.append(" & ".join(cells) + r" \\")
    _write_tex("\n".join(rows), "splits")


def tbl_efficiency() -> None:
    d = table("e6_scaling")
    rows = []
    for wl in ["W1_web", "W2_apt"]:
        s = d[d.workload == wl].sort_values("live_sessions")
        for _, r in s.iterrows():
            rows.append(" & ".join([
                WL[wl], f"{int(r.live_sessions):,}", f"{int(r.requests):,}",
                f"{r.throughput_req_per_s/1000:.1f}",
                f"{r.latency_us_median:.1f}", f"{r.latency_us_p99:.1f}",
                f"{r.state_bytes_per_session/1024:.2f}"]) + r" \\")
    _write_tex("\n".join(rows), "efficiency")


def tbl_base_rate() -> None:
    d = table("e7_base_rate")
    rows = []
    for pi in sorted(d.prevalence.unique()):
        exponent = math.log10(pi)
        cells = [f"$10^{{{int(round(exponent))}}}$"
                 if abs(exponent - round(exponent)) < 1e-9 else f"{pi:g}"]
        for wl in ["W1_web", "W2_apt"]:
            r = d[(d.workload == wl) & (d.prevalence == pi)].iloc[0]
            cells += [f"{r.precision*100:.1f}", f"{r.false_alerts_per_million:,.0f}"]
        rows.append(" & ".join(cells) + r" \\")
    _write_tex("\n".join(rows), "base_rate")


def macros() -> None:
    """Every number quoted in the prose, as a macro."""
    corpus = table("e0_corpus").set_index("workload")
    main = table("e1_main_summary").set_index("workload")
    eff = table("e6_efficiency").set_index("workload")
    cal = table("e1_calibration_summary").set_index("workload")
    scen = table("e4_scenario_grid")
    sweep = table("e1_alpha_sweep")
    base = table("e2_baselines")
    marg = table("e5_marginal_audit")
    ref = table("e5_content_reference").set_index("workload")

    m = {}
    for wl, tag in [("W1_web", "Web"), ("W2_apt", "Apt")]:
        m[f"corpusReq{tag}"] = f"{int(corpus.loc[wl].requests_parsed):,}"
        m[f"corpusSess{tag}"] = f"{int(corpus.loc[wl].sessions):,}"
        m[f"corpusAddr{tag}"] = f"{int(corpus.loc[wl].unique_addresses):,}"
        m[f"corpusCores{tag}"] = f"{int(corpus.loc[wl].unique_agent_cores)}"
        m[f"recall{tag}"] = fmt(main.loc[wl].recall_mean)
        m[f"recallLo{tag}"] = fmt(main.loc[wl].recall_ci_lo)
        m[f"recallHi{tag}"] = fmt(main.loc[wl].recall_ci_hi)
        m[f"prec{tag}"] = fmt(main.loc[wl].precision_mean)
        m[f"fone{tag}"] = fmt(main.loc[wl].f1_mean)
        m[f"fpr{tag}"] = f"{main.loc[wl].fpr_mean*100:.2f}"
        m[f"auc{tag}"] = fmt(main.loc[wl].roc_auc_mean)
        m[f"prauc{tag}"] = fmt(main.loc[wl].pr_auc_mean)
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
                    m[f"rec{word}{mode.capitalize()}{tag}"] = fmt(r.recall_mean.iloc[0])
        for a, key in [(0.05, "Five"), (0.02, "Two")]:
            r = sweep[(sweep.workload == wl) & (sweep.alpha == a)]
            if len(r):
                m[f"recAlpha{key}{tag}"] = fmt(r.recall_mean.iloc[0])
                m[f"fprAlpha{key}{tag}"] = f"{r.fpr_mean.iloc[0]*100:.1f}"
        for bl, key in [("pin_ip", "PinIp"), ("pin_useragent_core", "PinCore"),
                        ("pin_prefix24", "PinTwentyFour")]:
            r = base[(base.workload == wl) & (base.baseline == bl)]
            if len(r):
                m[f"{key}Recall{tag}"] = fmt(r.recall_mean.iloc[0])
                m[f"{key}Fpr{tag}"] = f"{r.fpr_mean.iloc[0]*100:.1f}"
                # No ``...Auc...`` macro is emitted for a pinning rule.  These rules are
                # binary, so the quantity that used to fill it was identically balanced
                # accuracy, and printing it beside SICA's ranking AUC implied a score
                # resolution the rule does not have.  Balanced accuracy is emitted under its
                # own name instead; see ``sica.evaluation.run_baselines``.
                m[f"{key}BalAcc{tag}"] = fmt(r.balanced_accuracy_mean.iloc[0])
        mm = marg[marg.workload == wl]
        m[f"margMax{tag}"] = fmt(mm.roc_auc_mean.max())
        m[f"margMaxFeat{tag}"] = mm.loc[mm.roc_auc_mean.idxmax(), "feature"].replace("_", " ")
        m[f"contentAuc{tag}"] = fmt(ref.loc[wl].roc_auc_mean)
        m[f"contentFone{tag}"] = fmt(ref.loc[wl].f1_mean)

    body = "\n".join(f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in sorted(m.items()))
    _write_tex(body, "numbers")


def make_tables() -> None:
    """Write every LaTeX table body and the numbers.tex macro file."""
    with Timer("LaTeX tables"):
        tbl_corpus(); tbl_main(); tbl_scenarios(); tbl_false_alarms()
        tbl_baselines(); tbl_ablation(); tbl_leakage(); tbl_efficiency()
        tbl_base_rate(); macros()


# ============================================================================
# Figures
# ============================================================================

# Validated categorical slots (light surface); every use is paired with a
# non-colour channel so the figures survive greyscale printing.
BLUE, ORANGE, AQUA, VIOLET = "#2a78d6", "#eb6834", "#1baf7a", "#4a3aa7"
GREY, INK, MUTED = "#8a8985", "#0b0b0b", "#52514e"
COL, FULL = 3.4, 7.1

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["DejaVu Serif"], "font.size": 8,
    "axes.labelsize": 8, "axes.titlesize": 8.5, "legend.fontsize": 7,
    "xtick.labelsize": 7, "ytick.labelsize": 7,
    "axes.edgecolor": MUTED, "axes.linewidth": 0.6, "axes.grid": True,
    "grid.color": "#e4e3df", "grid.linewidth": 0.5, "axes.axisbelow": True,
    "figure.dpi": 400, "savefig.dpi": 400, "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02, "legend.frameon": False,
})

WORKLOAD_LABEL = {"W1_web": "W1 web browsing", "W2_apt": "W2 package clients"}


def save(fig, name: str) -> None:
    path = FIGURES / f"{name}.pdf"
    fig.savefig(path)
    fig.savefig(FIGURES / f"{name}.png")
    plt.close(fig)
    print(f"  wrote {path.name}")


def table(name: str) -> pd.DataFrame:
    return pd.read_csv(TABLES / f"{name}.csv")


# ---------------------------------------------------------------------------
# Figure 1 --- architecture
# ---------------------------------------------------------------------------

def fig_architecture() -> None:
    fig, ax = plt.subplots(figsize=(FULL, 1.95))
    ax.set_axis_off()
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 34)

    def box(x, y, w, h, text, fc="#ffffff", ec=MUTED, fs=7.2, lw=0.7):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.35,rounding_size=1.2",
                                    fc=fc, ec=ec, lw=lw))
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
                color=INK, linespacing=1.25)

    def arrow(x1, y1, x2, y2, style="-|>", color=MUTED, ls="-"):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                                     mutation_scale=7, lw=0.7, color=color,
                                     linestyle=ls, shrinkA=0, shrinkB=0))

    box(0.5, 13, 13, 9, "request\n(id, addr,\nagent, t, url)", fc="#f3f6fb")
    arrow(13.8, 17.5, 17.2, 17.5)
    box(17.5, 13, 13, 9, "binding\nfingerprint\n(prefix, agent)", fc="#f3f6fb")
    arrow(30.8, 17.5, 34.2, 17.5)
    box(34.5, 9.5, 17, 16,
        "session state $S$\npinned binding\nbinding ring (4)\npath window (32)",
        fc="#fbf5f1")
    arrow(51.8, 17.5, 55.2, 17.5)
    box(55.5, 8, 15, 19,
        "invariants\n$v_1$ agent mutation\n$v_2$ scope discont.\n"
        "$v_3$ binding fork",
        fc="#f1faf6")
    ax.text(63, 5.2, "($v_4$ velocity, $v_5$ rate, $v_6$ nav.:\n"
                     "implemented, not retained)",
            fontsize=6.0, color=MUTED, ha="center", style="italic", linespacing=1.2)
    arrow(70.8, 17.5, 74.2, 17.5)
    box(74.5, 12, 12, 11, "risk\n$r=\\sum_i w_i v_i$", fc="#f4f2fb")
    arrow(86.8, 17.5, 90.2, 17.5)
    box(90.5, 12, 9, 11, "alert\nif $r\\geq\\tau$", fc="#f4f2fb")

    # calibration path
    box(55.5, 0.2, 31, 3.4, "attack-free calibration split  $\\rightarrow$  applicability gate, "
                            "weights $w_i \\propto \\log 1/(\\varepsilon_i+\\varepsilon_0)$, "
                            "threshold $\\tau = Q_{1-\\alpha}$",
        fc="#f7f7f5", fs=6.6)
    arrow(80.5, 3.8, 80.5, 11.8, ls=(0, (2.4, 1.6)))
    arrow(94.5, 3.8, 94.5, 11.8, ls=(0, (2.4, 1.6)))
    ax.text(43, 29.5, "per request: $O(1)$ time, $O(1)$ state", fontsize=7,
            color=MUTED, ha="center", style="italic")
    save(fig, "fig1_architecture")


# ---------------------------------------------------------------------------
# Figure 2 --- the mechanism: monotone mobility versus an interleaved fork
# ---------------------------------------------------------------------------

def fig_mechanism() -> None:
    fig, axes = plt.subplots(3, 1, figsize=(COL, 2.55), sharex=True)
    seqs = [
        ("benign move", list("AAAABBBBB"), None),
        ("takeover", list("AAAABBBBB"), 4),
        ("live hijack", list("AAAABABAB"), 4),
    ]
    for ax, (title, seq, theft) in zip(axes, seqs):
        for i, b in enumerate(seq):
            colour = BLUE if b == "A" else ORANGE
            hatch = "" if b == "A" else "///"
            ax.add_patch(plt.Rectangle((i + 0.12, 0.18), 0.76, 0.64, fc=colour,
                                       ec=INK, lw=0.4, hatch=hatch, alpha=0.9))
            ax.text(i + 0.5, 0.5, b, ha="center", va="center", fontsize=6.5,
                    color="white", weight="bold")
        if theft is not None:
            ax.axvline(theft, color=INK, lw=0.9, ls=(0, (2, 1.4)))
            ax.text(theft + 0.08, 0.93, "theft", fontsize=6, color=INK, va="top")
        # mark revisits
        for i in range(1, len(seq)):
            if seq[i] != seq[i - 1] and seq[i] in seq[:i - 1]:
                ax.plot(i + 0.5, 0.06, marker="^", ms=4, color=VIOLET, clip_on=False)
        ax.set_xlim(0, len(seq)); ax.set_ylim(0, 1)
        ax.set_yticks([]); ax.set_ylabel(title, rotation=0, ha="right", va="center",
                                         fontsize=7, labelpad=4)
        ax.grid(False)
        for spine in ax.spines.values():
            spine.set_visible(False)
    axes[-1].set_xticks(np.arange(len(seqs[0][1])) + 0.5)
    axes[-1].set_xticklabels(range(1, len(seqs[0][1]) + 1))
    axes[-1].set_xlabel("request index in session")
    fig.text(0.5, -0.06, "A, B: distinct client bindings   "
                         "$\\blacktriangle$: revisit detected by $v_3$",
             ha="center", fontsize=6.6, color=MUTED)
    save(fig, "fig2_mechanism")


# ---------------------------------------------------------------------------
# Figure 3 --- detection envelope
# ---------------------------------------------------------------------------

def fig_envelope() -> None:
    d = table("e4_scenario_grid")
    fig, axes = plt.subplots(1, 2, figsize=(FULL, 2.2), sharey=True)
    # Frozen contract level set (LEVELS_ALL), never a local literal: a hard-coded
    # subset silently dropped L5 from this figure once already.
    levels = list(LEVELS_ALL)
    for ax, wl in zip(axes, ["W1_web", "W2_apt"]):
        sub = d[d.workload == wl]
        width = 0.36
        x = np.arange(len(levels))
        for k, (mode, colour, hatch) in enumerate(
                [("takeover", BLUE, ""), ("concurrent", ORANGE, "///")]):
            m = sub[sub["mode"] == mode].set_index("level").reindex(levels)
            vals = m.recall_mean.to_numpy()
            err = np.vstack([vals - m.recall_ci_lo.to_numpy(),
                             m.recall_ci_hi.to_numpy() - vals])
            ax.bar(x + (k - 0.5) * width, vals, width * 0.92, label=mode,
                   color=colour, ec=INK, lw=0.4, hatch=hatch)
            ax.errorbar(x + (k - 0.5) * width, vals, yerr=np.abs(err), fmt="none",
                        ecolor=INK, elinewidth=0.6, capsize=1.6)
        ax.set_xticks(x); ax.set_xticklabels(levels)
        ax.set_xlabel("masquerade level")
        ax.set_title(WORKLOAD_LABEL[wl])
        ax.set_ylim(0, 1.04)
        # L4 is the only cell in which no binding signal exists at all
        # .  L5 is co-located too but remains
        # detectable through v1, so the band covers L4 alone.  Position is
        # derived from the level list so it cannot drift if that list changes.
        blind = levels.index("L4")
        ax.axvspan(blind - 0.5, blind + 0.5, color="#eceae4", zorder=0)
        ax.text(blind, 0.97, "no binding\nsignal", ha="center", va="top",
                fontsize=6, color=MUTED)
    axes[0].set_ylabel("recall at $\\alpha = 0.01$")
    axes[0].legend(loc="upper right", ncol=1)
    save(fig, "fig3_envelope")


# ---------------------------------------------------------------------------
# Figure 4 --- operating characteristic against the baselines
# ---------------------------------------------------------------------------

def fig_operating() -> None:
    sweep = table("e1_alpha_sweep")
    base = table("e2_baselines")
    fig, axes = plt.subplots(1, 2, figsize=(FULL, 2.5), sharey=True)
    shown = {"pin_ip": ("o", ORANGE), "pin_prefix24": ("s", AQUA),
             "pin_useragent": ("^", VIOLET), "pin_useragent_core": ("D", GREY),
             "pin_ip_or_useragent": ("v", "#8a6d3b")}
    for ax, wl in zip(axes, ["W1_web", "W2_apt"]):
        s = sweep[sweep.workload == wl].sort_values("fpr_mean")
        ax.plot(s.fpr_mean, s.recall_mean, "-o", color=BLUE, ms=3.2, lw=1.3,
                label="SICA (budget sweep)", zorder=4)
        ax.fill_between(s.fpr_mean, s.recall_ci_lo, s.recall_ci_hi, color=BLUE,
                        alpha=0.14, lw=0)
        b = base[(base.workload == wl) & (base.family == "pinning")]
        for _, r in b.iterrows():
            if r.baseline not in shown:
                continue
            marker, colour = shown[r.baseline]
            ax.plot(r.fpr_mean, r.recall_mean, marker, color=colour, ms=4.6,
                    mec=INK, mew=0.4, label=r.baseline.replace("_", " "), zorder=5)
        ax.set_xlabel("false-alarm rate (benign sessions)")
        ax.set_title(WORKLOAD_LABEL[wl])
        ax.set_xlim(-0.008, 0.235); ax.set_ylim(0, 1.05)
        ax.axvline(0.01, color=MUTED, lw=0.6, ls=(0, (2, 1.6)))
        ax.text(0.012, 0.03, "budget $\\alpha=0.01$", fontsize=6, color=MUTED)
    axes[0].set_ylabel("recall")
    axes[1].legend(loc="lower right", ncol=1, fontsize=6.2)
    save(fig, "fig4_operating")


# ---------------------------------------------------------------------------
# Figure 5 --- when address pinning stops being viable
# ---------------------------------------------------------------------------

def fig_crossover() -> None:
    d = table("e4_crossover")
    fig, axes = plt.subplots(1, 2, figsize=(FULL, 2.4), sharex=True)
    series = [("SICA (proposed)", BLUE, "o", "-"),
              ("pin_ip", ORANGE, "s", "--"),
              ("pin_useragent_core", AQUA, "^", "-."),
              ("pin_prefix24", VIOLET, "D", ":")]
    sub = d[d.workload == "W1_web"]
    for ax, metric, ylabel in zip(axes, ["fpr_mean", "f1_mean"],
                                  ["false-alarm rate", "$F_1$"]):
        for name, colour, marker, ls in series:
            s = sub[sub.detector == name].sort_values("monotone_rate")
            ax.plot(s.monotone_rate, s[metric], ls, marker=marker, color=colour,
                    ms=3.4, lw=1.2, label=name.replace("_", " "))
        ax.set_xlabel("benign monotone mobility rate")
        ax.set_ylabel(ylabel)
    axes[0].axhline(0.01, color=MUTED, lw=0.6, ls=(0, (2, 1.6)))
    axes[0].text(0.012, 0.013, "budget", fontsize=6, color=MUTED)
    axes[0].set_title("cost of a fixed rule")
    axes[1].set_title("detection quality")
    axes[1].legend(loc="best", fontsize=6.2)
    fig.text(0.5, -0.04, f"workload {WORKLOAD_LABEL['W1_web']}; "
                         "flapping rate held at 0.05", ha="center", fontsize=6.4,
             color=MUTED)
    save(fig, "fig5_crossover")


# ---------------------------------------------------------------------------
# Figure 6 --- ablation
# ---------------------------------------------------------------------------

def fig_ablation() -> None:
    d = table("e3_ablation")
    fig, ax = plt.subplots(figsize=(COL, 2.3))
    ref = d[(d.family == "reference")].set_index("workload").f1_mean
    loo = d[d.family == "leave_one_out"].copy()
    loo["delta"] = loo.apply(lambda r: r.f1_mean - ref[r.workload], axis=1)
    order = (loo[loo.workload == "W1_web"].sort_values("delta").variant.tolist())
    y = np.arange(len(order))
    for k, (wl, colour, hatch) in enumerate([("W1_web", BLUE, ""),
                                             ("W2_apt", ORANGE, "///")]):
        s = loo[loo.workload == wl].set_index("variant").reindex(order)
        ax.barh(y + (k - 0.5) * 0.38, s.delta.to_numpy(), 0.35, color=colour,
                ec=INK, lw=0.4, hatch=hatch, label=WORKLOAD_LABEL[wl])
    ax.axvline(0, color=INK, lw=0.7)
    ax.set_yticks(y)
    ax.set_yticklabels([v.replace("minus_", "$-$").replace("_", " ") for v in order])
    ax.set_xlabel("change in $F_1$ when the invariant is removed")
    ax.legend(loc="lower right")
    save(fig, "fig6_ablation")


def make_figures() -> None:
    """Write figures 1-6 as PDF and PNG."""
    with Timer("figures"):
        fig_architecture()
        fig_mechanism()
        fig_envelope()
        fig_operating()
        fig_crossover()
        fig_ablation()


# ============================================================================
# Validation of the finished result set
# ============================================================================

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


def validate() -> int:
    """Run every check; return 0 when all pass, 1 otherwise."""
    RESULTS.clear()
    # --- artefacts exist --------------------------------------------------
    for name in EXPECTED_TABLES:
        check(f"table {name}.csv", (TABLES / f"{name}.csv").is_file())
    for name in EXPECTED_FIGURES:
        check(f"figure {name}.pdf", (FIGURES / f"{name}.pdf").is_file())
    for name in EXPECTED_PAPER_TABLES:
        check(f"paper/tables/{name}.tex", (ROOT / "paper" / "tables" / f"{name}.tex").is_file())
    check("leakage report", (SUMMARY / "leakage_report.json").is_file())
    check("efficiency environment", (SUMMARY / "e6_environment.json").is_file())

    if not all(ok for _, ok, _ in RESULTS):
        return _validation_report()

    # --- leakage report has no failures -----------------------------------
    report_json = json.loads((SUMMARY / "leakage_report.json").read_text())
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
        if path.name == "report.py":      # holds the list of banned names itself
            continue
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
    for name in ("report.py",):
        for m in literal.finditer((ROOT / "sica" / name).read_text()):
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
    abl = pd.read_csv(TABLES / "e3_ablation.csv")
    loo = {v.replace("minus_", "") for v in abl[abl.family == "leave_one_out"].variant}
    check("ablation removes each retained invariant",
          loo == set(DEFAULT_INVARIANTS), f"{sorted(loo)}")
    restored = {v.replace("plus_", "") for v in abl[abl.family == "restored"].variant}
    rejected = set(INVARIANTS) - set(DEFAULT_INVARIANTS)
    check("ablation restores each rejected invariant",
          rejected <= restored, f"rejected={sorted(rejected)} restored={sorted(restored)}")

    return _validation_report()


def _validation_report() -> int:
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




# ============================================================================
# Human-readable summary of the final results
# ============================================================================

def write_summary(validation_ok: bool | None = None) -> None:
    """Write results/summary/summary.md from the result tables."""
    main = table("e1_main_summary").set_index("workload")
    base = table("e2_baselines")
    grid = table("e4_scenario_grid")
    eff = table("e6_efficiency").set_index("workload")
    cal = table("e1_calibration_runs")
    names = {"W1_web": "W1 (human web)", "W2_apt": "W2 (APT-style demo)"}

    lines = ["# SICA final results", "",
             "Generated by `python run.py` from `results/tables/`. "
             "False-alarm budget alpha = 0.01; means over 30 seeds (95% bootstrap CI).", "",
             "## Main result (E1)", "",
             "| Workload | ROC AUC [95% CI] | Recall | FPR | Precision | F1 | "
             "Alert after (attacker requests, median) |",
             "|---|---|---|---|---|---|---|"]
    for wl, r in main.iterrows():
        lines.append(
            f"| {names[wl]} | {r.roc_auc_mean:.4f} [{r.roc_auc_ci_lo:.4f}, {r.roc_auc_ci_hi:.4f}] "
            f"| {r.recall_mean:.4f} | {r.fpr_mean * 100:.2f}% | {r.precision_mean:.4f} "
            f"| {r.f1_mean:.4f} | {r.latency_requests_median_mean:.1f} |")
    lines += ["", f"Worst calibration alarm rate over all runs: "
                  f"{cal.calibration_alarm_rate.max() * 100:.2f}% (budget 1.00%).", "",
              "## SICA against address and agent pinning (E2)", "",
              "| Detector | W1 recall | W1 FPR | W2 recall | W2 FPR |", "|---|---|---|---|---|"]
    for name in ["SICA (proposed)", "pin_ip", "pin_prefix24", "pin_scope16",
                 "pin_useragent", "pin_useragent_core", "pin_ip_or_useragent"]:
        cells = [name]
        for wl in ["W1_web", "W2_apt"]:
            r = base[(base.workload == wl) & (base.baseline == name)].iloc[0]
            cells += [f"{r.recall_mean:.3f}", f"{r.fpr_mean * 100:.1f}%"]
        lines.append("| " + " | ".join(cells) + " |")
    lines += ["", "## Recall per attacker level (E4)", "",
              "| Level | W1 takeover | W1 concurrent | W2 takeover | W2 concurrent |",
              "|---|---|---|---|---|"]
    for level in LEVELS_ALL:
        cells = [level]
        for wl in ["W1_web", "W2_apt"]:
            for mode in MODES:
                r = grid[(grid.workload == wl) & (grid.level == level) & (grid["mode"] == mode)]
                cells.append(f"{r.recall_mean.iloc[0]:.3f}" if len(r) else "--")
        lines.append("| " + " | ".join(cells) + " |")
    lines += ["", "L4 (same address, cloned agent) produces an identical binding and cannot "
                  "be detected by any binding-based method.", "",
              "## Detector cost (E6)", ""]
    for wl, r in eff.iterrows():
        lines.append(f"- {names[wl]}: {r.throughput_req_per_s:,.0f} requests/s, "
                     f"median {r.latency_us_median:.1f} us per request, "
                     f"about {r.state_bytes_per_session / 1024:.1f} KB state per session.")
    if validation_ok is not None:
        lines += ["", f"Validation: {'passed' if validation_ok else 'FAILED'} "
                      "(see the output of `python run.py`)."]
    lines += ["", "Other files in this folder: `decisions_seed0.csv` (ALLOW/ALERT per session "
                  "for seed 0), `leakage_report.json` (E5 checks), `e6_environment.json` "
                  "(timing environment), `e0_sessionisation.json`.", ""]
    path = SUMMARY / "summary.md"
    path.write_text("\n".join(lines))
    print(f"  wrote {path.relative_to(ROOT)}")
