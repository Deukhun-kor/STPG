# AUROC of each scorer by attack factor (k, d, hiding location) against the non-directive benign set.
# Usage: python fig_factors.py <main.db> <attack_factors.csv> <out_prefix>
import sqlite3, sys, csv, numpy as np, matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
db,fcsv,out=sys.argv[1],sys.argv[2],sys.argv[3]
loc={r['run_id']:r['hide_location'] for r in csv.DictReader(open(fcsv))}
c=sqlite3.connect(db); c.row_factory=sqlite3.Row
rows=[dict(r) for r in c.execute("SELECT detector,run_id,is_attack,benign_subtype,k,d,detect_score FROM results WHERE cf=''")]
S=[("stpg","STPG","#1f77b4","o"),("judge_gate","scalar judge","#ff7f0e","s"),("unit","unit inspection","#2ca02c","^"),("window","window scorer","#9467bd","D")]
def auroc(pos,neg):
    pos=np.asarray(pos); neg=np.asarray(neg)
    return float(((pos[:,None]>neg[None,:]).sum()+0.5*(pos[:,None]==neg[None,:]).sum())/(len(pos)*len(neg)))
factors=[("$k$ (attack records)",lambda r:r['k'],[2,3,4,5]),("$d$ (sessions)",lambda r:r['d'],[1,3,5]),("injection location",lambda r:loc.get(r['run_id']),["log_message","ticket_body","api_description_field"])]
lab={"log_message":"log\nmessage","ticket_body":"ticket\ndescription","api_description_field":"tool descr.\nfield"}
fig,axs=plt.subplots(1,3,figsize=(7.2,2.7),sharey=True)
for ax,(name,key,vals) in zip(axs,factors):
    for d,l,col,mk in S:
        R=[r for r in rows if r['detector']==d]
        neg=[r['detect_score'] for r in R if r['is_attack']==0 and r['benign_subtype']!='legit_external']
        ys=[auroc([r['detect_score'] for r in R if r['is_attack']==1 and key(r)==v],neg) for v in vals]
        ax.plot(range(len(vals)),ys,marker=mk,ms=5,color=col,lw=1.6,label=l,zorder=3)
        for i,y in enumerate(ys):
            if d=="window": ax.annotate(f"{y:.3f}",(i,y),textcoords="offset points",xytext=(0,-11),ha="center",fontsize=6.5,color=col)
            elif d=="unit" and name.startswith("$k$"): ax.annotate(f"{y:.3f}",(i,y),textcoords="offset points",xytext=(0,-11 if y<0.9 else 5),ha="center",fontsize=6.5,color=col)
            elif d=="judge_gate" and name.startswith("$k$") and y<0.999: ax.annotate(f"{y:.3f}",(i,y),textcoords="offset points",xytext=(0,-11),ha="center",fontsize=6.5,color=col)
    ax.set_xticks(range(len(vals))); ax.set_xticklabels([lab.get(v,str(v)) for v in vals],fontsize=8.5)
    ax.set_xlabel(name,fontsize=9); ax.set_ylim(0.76,1.015); ax.grid(axis="y",color="0.9",lw=0.6,zorder=0); ax.tick_params(labelsize=8.5)
    for sp in ["top","right"]: ax.spines[sp].set_visible(False)
axs[0].set_ylabel("AUROC vs. non-directive benign",fontsize=8.5)
axs[1].legend(fontsize=7.5,loc="lower left",frameon=False,ncol=2)
fig.tight_layout(); fig.savefig(out+".pdf",bbox_inches="tight"); fig.savefig(out+".png",dpi=220,bbox_inches="tight")
for d,l,_,_ in S:
    R=[r for r in rows if r['detector']==d]; neg=[r['detect_score'] for r in R if r['is_attack']==0 and r['benign_subtype']!='legit_external']
    print(l,{(n,v):round(auroc([r['detect_score'] for r in R if r['is_attack']==1 and key(r)==v],neg),3) for n,key,vals in factors for v in vals})
