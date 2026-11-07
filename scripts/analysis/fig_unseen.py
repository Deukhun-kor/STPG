# Frozen evaluation set: conformance matrix per structure and condition, with the post-hoc extended-pattern column.
# Usage: python fig_unseen.py <unseen.db> <unseen_relext.db> <out_prefix>   (run from the repository root; needs stpg/)
import sqlite3, sys, os, numpy as np, matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
sys.path.insert(0, os.getcwd())
from stpg import config as C
from stpg.datagen.unseen import build_unseen_specs, STRUCTURES
db, dbx, out = sys.argv[1], sys.argv[2], sys.argv[3]
exp = {}
for sp in build_unseen_specs(C.load_profile("s4_main"), reps=5):
    for d_, e_ in sp.expected.items(): exp[sp.run_id + "#cf:" + d_] = e_
def rows(p):
    c = sqlite3.connect(p); c.row_factory = sqlite3.Row
    return [dict(r) for r in c.execute("SELECT * FROM results WHERE cf!=''")]
R, RX = rows(db), rows(dbx)
labels = ["direct trusted rule (pass)", "rule via key, trusted sheet (pass)", "rule via key, untrusted sheet (block)", "attack triple, one connector (block)",
          "attack triple, two connectors (block)", "trusted prohibition of B (block)", "two-hop chain, all trusted (pass)", "two-hop chain, poisoned hop (block)",
          "descriptive notice only (block)", "rule + untrusted mention (pass)", "rule later revoked (block)", "untrusted archive rule: store pass, A block"]
conds = [("stpg", "STPG", R), ("stpg_allow", "STPG,\nallow on\nempty", R), ("stpg_tdo", "trusted-\ndirective-\nonly", R), ("stpg_pdgonly", "conser-\nvative\ngate", R),
         ("match_gate", "trusted-\nrule\nmatching", R), ("attr_judge", "attri-\nbution\njudge", R), ("stpg", "STPG,\nextended M\n(post hoc)", RX)]
M = np.zeros((len(STRUCTURES), len(conds))); N = np.zeros_like(M)
for i, s in enumerate(STRUCTURES):
    for j, (d, _, rr) in enumerate(conds):
        rs = [r for r in rr if r["structure"] == s and r["detector"] == d]
        M[i, j] = sum(((r["sink_allowed"] == 1) == (exp.get(r["run_id"]) == "pass")) for r in rs); N[i, j] = len(rs)
F = M / np.maximum(N, 1); nr = len(STRUCTURES) + 1
G = np.vstack([F, (M.sum(0) / np.maximum(N.sum(0), 1))[None, :]])
fig, ax = plt.subplots(figsize=(8.6, 5.0))
ax.imshow(G, cmap="Blues", vmin=0, vmax=1.0, aspect="auto")
for i in range(len(STRUCTURES)):
    for j in range(len(conds)):
        ax.text(j, i, f"{int(M[i,j])}", ha="center", va="center", fontsize=10, color="white" if F[i, j] > 0.55 else "black")
tot = M.sum(0); totn = N.sum(0)
for j in range(len(conds)):
    ax.text(j, len(STRUCTURES), f"{int(tot[j])}", ha="center", va="center", fontsize=10.5, fontweight="bold", color="white" if tot[j] / totn[j] > 0.55 else "black")
ax.axhline(len(STRUCTURES) - 0.5, color="white", lw=2.0); ax.axvline(len(conds) - 1.5, color="white", lw=3.0)
ax.add_patch(plt.Rectangle((-0.5, -0.5), 1, nr, fill=False, edgecolor="#1f3b70", lw=1.6))
ax.set_xticks(range(len(conds))); ax.set_xticklabels([c[1] for c in conds], fontsize=10)
ax.set_yticks(range(nr)); ax.set_yticklabels([(f"{l[:-1]}, n={int(N[i,0])})" if l.endswith(")") else f"{l} (n={int(N[i,0])})") for i, l in enumerate(labels)] + ["all structures (n=260)"], fontsize=10); ax.get_yticklabels()[-1].set_fontweight("bold")
ax.set_xlabel("conforming decisions (n shown per row)", fontsize=10.5)
for s in ax.spines.values(): s.set_visible(False)
ax.tick_params(length=0)
fig.tight_layout(); fig.savefig(out + ".pdf"); fig.savefig(out + ".png", dpi=220); print(tot, totn)
