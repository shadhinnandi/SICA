"""Publication figures.

Every figure is generated from the frozen result tables, never from typed-in
numbers, so a figure cannot disagree with the table it illustrates.  Figures are
sized for a two-column IEEE page (3.4 in single column, 7.1 in full width) and
are legible in greyscale: every series carries a marker, a line style or a hatch
in addition to its hue, so no distinction depends on colour alone.
"""
from __future__ import annotations

import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.common import FIGURES, TABLES, Timer
from sica.inject import LEVELS_ALL

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
        # (EXPERIMENT_CONTRACT sec.9).  L5 is co-located too but remains
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


if __name__ == "__main__":
    with Timer("figures"):
        fig_architecture()
        fig_mechanism()
        fig_envelope()
        fig_operating()
        fig_crossover()
        fig_ablation()
