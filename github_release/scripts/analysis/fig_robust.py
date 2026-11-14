# Robustness sets A and B: calls passed / allowed per variant and condition, horizontal bars (rev12, Reviewer 2 #7).
# Usage: python fig_robust.py <rules.db> <multi.db> <out_prefix>
import sqlite3, sys, numpy as np, matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
rules, multi, out = sys.argv[1], sys.argv[2], sys.argv[3]
def rows(db):
    c = sqlite3.connect(db); c.row_factory = sqlite3.Row
    return [dict(r) for r in c.execute("SELECT detector,structure,sink_allowed FROM results WHERE cf!=''")]
CONDS = [("stpg", "STPG", "#1f77b4"), ("stpg_allow", "STPG, allow on empty", "#aec7e8"), ("match_gate", "trusted-rule matching", "#ff7f0e"),
         ("attr_judge", "attribution judge", "#2ca02c"), ("stpg_pdgonly", "conservative gate", "#7f7f7f")]
A = [("rule_canonical", "canonical rule (control)"), ("rule_paraphrase", "LLM-paraphrased rule"), ("rule_implicit", "no imperative verb"),
     ("rule_alias_trusted", "registry key, trusted contact sheet"), ("rule_alias_untrusted", "registry key, untrusted sheet (policy: block)"),
     ("rule_format", "identifier surface form"), ("rule_two_records", "directive split over two trusted records")]
B = [("mc_single", "one connector (control)"), ("mc_two", "two connectors"), ("mc_three", "three connectors"),
     ("mc_two_trustedmap", "registry entry written by operations"), ("mc_nopattern", "mapping outside the relation pattern")]
fig, axs = plt.subplots(2, 1, figsize=(7.4, 6.0), gridspec_kw={"height_ratios": [7, 5]})
for ax, (db, items, title, xlab) in zip(axs, [(rules, A, "(a) set A: approved transfer to partner A", "calls passed (of 30)"),
                                             (multi, B, "(b) set B: attack to the synthetic sink", "attack calls allowed (of 30)")]):
    R = rows(db); y = np.arange(len(items))[::-1]; h = 0.16
    for i, (d, lab, col) in enumerate(CONDS):
        vals = [sum(1 for r in R if r["detector"] == d and r["structure"] == s and r["sink_allowed"] == 1) for s, _ in items]
        ax.barh(y + (2 - i) * h, vals, h, color=col, label=lab, zorder=3, edgecolor="white", linewidth=0.4)
        for by, v in zip(y + (2 - i) * h, vals):
            if v == 0: ax.plot([0.25], [by], marker="o", ms=2.2, color=col, zorder=4)          # zero: dot at the axis
            elif v != 30: ax.text(v + 0.4, by, str(v), va="center", ha="left", fontsize=8, color="0.25")
    ax.set_yticks(y); ax.set_yticklabels([l for _, l in items], fontsize=9)
    ax.set_xlim(0, 34); ax.set_xticks([0, 10, 20, 30]); ax.set_xlabel(xlab, fontsize=9); ax.set_title(title, fontsize=10, loc="left")
    ax.grid(axis="x", color="0.9", lw=0.6, zorder=0); ax.tick_params(axis="x", labelsize=9)
    for sp in ["top", "right"]: ax.spines[sp].set_visible(False)
h_, l_ = axs[0].get_legend_handles_labels(); fig.legend(h_, l_, fontsize=9, loc="lower center", ncol=3, frameon=False, bbox_to_anchor=(0.5, -0.01))
fig.tight_layout(rect=(0, 0.06, 1, 1)); fig.savefig(out + ".pdf", bbox_inches="tight"); fig.savefig(out + ".png", dpi=220, bbox_inches="tight"); print("ok")
