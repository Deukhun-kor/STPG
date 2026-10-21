# Read-level TSA score E* under the primary judge (gemini-2.5-flash-lite) and the swapped judge (gemini-2.5-flash).
# Usage: python fig_judgeswap.py <rev10_main.db> <rev11b_main_fjudge.db> <out_prefix>
import sqlite3, sys, numpy as np, matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
a, b, out = sys.argv[1], sys.argv[2], sys.argv[3]
def scores(db):
    c = sqlite3.connect(db); c.row_factory = sqlite3.Row
    R = [dict(r) for r in c.execute("SELECT is_attack,benign_subtype,detect_score FROM results WHERE detector='stpg' AND cf=''")]
    return (np.array([r["detect_score"] for r in R if r["is_attack"] == 1]),
            np.array([r["detect_score"] for r in R if r["is_attack"] == 0 and r["benign_subtype"] != "legit_external"]),
            np.array([r["detect_score"] for r in R if r["benign_subtype"] == "legit_external"]))
def auroc(p, n): return float(((p[:, None] > n[None, :]).sum() + 0.5 * (p[:, None] == n[None, :]).sum()) / (len(p) * len(n)))
fig, axs = plt.subplots(1, 2, figsize=(7.2, 2.8), sharey=True)
bins = np.linspace(0, 1, 21)
for ax, (db, title) in zip(axs, [(a, "primary judge: gemini-2.5-flash-lite"), (b, "swapped judge: gemini-2.5-flash")]):
    att, neg, rule = scores(db)
    ax.hist(neg, bins=bins, color="0.75", label=f"non-directive benign (n={len(neg)})", zorder=3)
    ax.hist(att, bins=bins, color="#1f77b4", alpha=0.8, label=f"attack (n={len(att)})", zorder=4)
    ax.hist(rule, bins=bins, histtype="step", color="#d62728", lw=1.6, label=f"approved rule (n={len(rule)})", zorder=5)
    ax.axvline(0.60, color="black", ls="--", lw=1.0); ax.text(0.615, 0.93, r"$\tau_{\mathrm{TSA}}$", fontsize=8, transform=ax.get_xaxis_transform())
    ax.set_title(f"{title}\nAUROC vs. non-directive {auroc(att, neg):.3f}; TPR at 0.60 {(att >= 0.6).mean():.3f}", fontsize=8.5)
    ax.set_xlabel("read-level directive score $E^{*}$", fontsize=8.5); ax.tick_params(labelsize=8); ax.set_yscale("log")
    ax.grid(axis="y", color="0.9", lw=0.6, zorder=0)
    for sp in ["top", "right"]: ax.spines[sp].set_visible(False)
axs[0].set_ylabel("reads (log scale)", fontsize=8.5); axs[0].legend(fontsize=7, frameon=False, loc="upper left")
fig.tight_layout(); fig.savefig(out + ".pdf", bbox_inches="tight"); fig.savefig(out + ".png", dpi=220, bbox_inches="tight"); print("ok")
