# Witness verdict vs. kernel verification per challenge structure (stacked bars). Usage: python fig_witness.py <holdout.db> <out_prefix>
import sqlite3, sys, collections, numpy as np, matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
db,out=sys.argv[1],sys.argv[2]
h=sqlite3.connect(db)
order=["mixed","mixed_order","crossref","value_poison","trusted_mention","untrusted_mention","missing_shard","missing_bg","missing_rule","offtask","same_record","untrusted_bundle","same_dest_both","ambiguous_key","deep_reference"]
labels=["mixed (A pass, B block)","mixed, permuted order","cross-reference","poisoned value","trusted mention","untrusted mention","missing sidecar: attack","missing sidecar: background","missing sidecar: rule","off-task string","same record: A rule, B prohibited","untrusted B rule, A mention","same destination, both","ambiguous key","three-hop reference"]
V=[];Rj=[];N=[]
for s in order:
    c=collections.Counter()
    for (w,) in h.execute("SELECT witness FROM results WHERE structure=? AND detector='stpg' AND cf!=''",(s,)):
        for x in filter(None,w.split(";")):
            lab=x.split(":")[-1]; c["v" if lab=="target" else ("r" if lab=="unsupported" else "n")]+=1
    V.append(c["v"]);Rj.append(c["r"]);N.append(c["n"])
V,Rj,N=map(np.array,(V,Rj,N)); y=np.arange(len(order))[::-1]
fig,ax=plt.subplots(figsize=(7.2,4.2))
ax.barh(y,V,color="#1f77b4",label=f"verified target ({V.sum()})",zorder=3)
ax.barh(y,Rj,left=V,color="#d62728",alpha=0.85,label=f"raw true, rejected by Eq. (2) ({Rj.sum()})",zorder=3)
ax.barh(y,N,left=V+Rj,color="0.75",label=f"negative verdict ({N.sum()})",zorder=3)
for i,(v,r,n) in enumerate(zip(V,Rj,N)):
    ax.text(v+r+n+1,y[i],f"{v} / {r} / {n}",va="center",fontsize=7.5)
ax.set_yticks(y); ax.set_yticklabels(labels,fontsize=8.5); ax.set_xlim(0,84)
ax.set_xlabel("binding lineages evaluated on the 240 counterfactual calls (396 in total)",fontsize=8.5)
ax.tick_params(axis="x",labelsize=8.5); ax.grid(axis="x",color="0.9",lw=0.6,zorder=0)
for sp in ["top","right"]: ax.spines[sp].set_visible(False)
ax.legend(fontsize=8,loc="upper right",frameon=False)
fig.tight_layout(); fig.savefig(out+".pdf",bbox_inches="tight"); fig.savefig(out+".png",dpi=220,bbox_inches="tight"); print(V.sum(),Rj.sum(),N.sum())
