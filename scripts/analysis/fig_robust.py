# Robustness sets A and B (rev11): calls passed / allowed per variant and condition. Usage: python fig_robust.py <rules.db> <multi.db> <out_prefix>
import sqlite3, sys, numpy as np, matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
rules, multi, out = sys.argv[1], sys.argv[2], sys.argv[3]
def rows(db):
    c = sqlite3.connect(db); c.row_factory = sqlite3.Row
    return [dict(r) for r in c.execute("SELECT detector,structure,sink_allowed FROM results WHERE cf!=''")]
CONDS = [("stpg", "STPG", "#1f77b4"), ("stpg_allow", "STPG, allow on empty", "#aec7e8"), ("match_gate", "trusted-rule matching", "#ff7f0e"),
         ("attr_judge", "attribution judge", "#2ca02c"), ("stpg_pdgonly", "conservative gate", "#7f7f7f")]
A = [("rule_canonical", "canonical"), ("rule_paraphrase", "LLM\nparaphrase"), ("rule_implicit", "no imperative\nverb"), ("rule_alias_trusted", "trusted\nalias"),
     ("rule_alias_untrusted", "untrusted alias\n(policy block)"), ("rule_format", "identifier\nsurface form"), ("rule_two_records", "two trusted\nrecords")]
B = [("mc_single", "one\nconnector"), ("mc_two", "two\nconnectors"), ("mc_three", "three\nconnectors"), ("mc_two_trustedmap", "registry by\noperations"), ("mc_nopattern", "mapping\noutside pattern")]
fig, axs = plt.subplots(1, 2, figsize=(7.4, 3.5), gridspec_kw={"width_ratios": [7, 5]})
for ax, (db, items, title, ylab) in zip(axs, [(rules, A, "set A: approved transfer to partner A", "calls passed (of 30)"),
                                             (multi, B, "set B: attack to the synthetic sink", "attack calls allowed (of 30)")]):
    R = rows(db); x = np.arange(len(items)); w = 0.16
    for i, (d, lab, col) in enumerate(CONDS):
        vals = [sum(1 for r in R if r["detector"] == d and r["structure"] == s and r["sink_allowed"] == 1) for s, _ in items]
        bars = ax.bar(x + (i - 2) * w, vals, w, color=col, label=lab, zorder=3, edgecolor="white", linewidth=0.4)
        for bx, v in zip(x + (i - 2) * w, vals):
            if v != 30: ax.text(bx, v + 0.6, str(v), ha="center", va="bottom", fontsize=5.2, color=col if v else "0.35")
    ax.set_xticks(x); ax.set_xticklabels([l.replace("\n", " ") for _, l in items], fontsize=7, rotation=25, ha="right", rotation_mode="anchor")
    ax.set_ylim(0, 34); ax.set_yticks([0, 10, 20, 30]); ax.set_ylabel(ylab, fontsize=8.5); ax.set_title(title, fontsize=9)
    ax.grid(axis="y", color="0.9", lw=0.6, zorder=0); ax.tick_params(axis="y", labelsize=8)
    for sp in ["top", "right"]: ax.spines[sp].set_visible(False)
h, l = axs[0].get_legend_handles_labels(); fig.legend(h, l, fontsize=7.2, loc="lower center", ncol=5, frameon=False, bbox_to_anchor=(0.5, -0.02))
fig.tight_layout(rect=(0, 0.06, 1, 1)); fig.savefig(out + ".pdf", bbox_inches="tight"); fig.savefig(out + ".png", dpi=220, bbox_inches="tight"); print("ok")
