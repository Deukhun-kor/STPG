# Read-level directive score strip plot (color). Usage: python fig_scores.py <main.db> <out_prefix>
import sqlite3, sys, numpy as np, matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
db,out=sys.argv[1],sys.argv[2]
c=sqlite3.connect(db); c.row_factory=sqlite3.Row
rows=[dict(r) for r in c.execute("SELECT is_attack,benign_subtype,detect_score FROM results WHERE detector='stpg' AND cf=''")]
classes=[("attack (k records, untrusted)",lambda r:r['is_attack']==1,"o","#1f77b4","#1f77b4"),
         ("approved external rule (trusted)",lambda r:r['benign_subtype']=='legit_external',"s","#ff7f0e","#ff7f0e"),
         ("untrusted internal archive directive",lambda r:r['benign_subtype']=='untrusted_internal',"^","0.55","0.35"),
         ("approved internal directive (trusted)",lambda r:r['benign_subtype']=='legit_internal',"D","0.7","0.35"),
         ("index note, no directive",lambda r:r['benign_subtype']=='benign',"v","0.85","0.35")]
rng=np.random.RandomState(0)
fig,ax=plt.subplots(figsize=(6.4,2.9))
for i,(lab,f,mk,fc,ec) in enumerate(classes):
    s=np.array([r['detect_score'] for r in rows if f(r)]); y=len(classes)-1-i+rng.uniform(-0.22,0.22,len(s))
    ax.scatter(s,y,marker=mk,s=14,facecolors=fc,edgecolors=ec,linewidths=0.5,alpha=0.85,zorder=3)
    ax.text(1.03,len(classes)-1-i,f"n={len(s)}, median {np.median(s):.2f}",va="center",fontsize=8.5,color="black")
ax.axvline(0.60,color="black",ls="--",lw=1.0); ax.text(0.605,len(classes)-0.45,r"$\tau_{\mathrm{TSA}}$=0.60",fontsize=8.5)
ax.set_yticks(range(len(classes))); ax.set_yticklabels([c[0] for c in classes][::-1],fontsize=9)
ax.set_xlim(0,1.0); ax.set_xticks([0,0.2,0.4,0.6,0.8,1.0]); ax.tick_params(axis="x",labelsize=9)
ax.set_xlabel("assembled-lineage directive score $E^{*}$ of the read (maximum over lineages)",fontsize=9)
for sp in ["top","right"]: ax.spines[sp].set_visible(False)
ax.grid(axis="x",color="0.85",lw=0.6,zorder=0)
fig.tight_layout(); fig.savefig(out+".pdf"); fig.savefig(out+".png",dpi=220); print("ok")
