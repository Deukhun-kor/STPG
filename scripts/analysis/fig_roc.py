# ROC curves of the four detection scorers on the main run. Usage: python fig_roc.py <main.db> <out_prefix>
import sqlite3, sys, numpy as np, matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
db,out=sys.argv[1],sys.argv[2]
c=sqlite3.connect(db); c.row_factory=sqlite3.Row
rows=[dict(r) for r in c.execute("SELECT detector,is_attack,benign_subtype,detect_score FROM results WHERE cf=''")]
S=[("stpg","STPG (assembled lineage)","#1f77b4"),("judge_gate","scalar full-context judge","#ff7f0e"),("unit","unit inspection","#2ca02c"),("window","window scorer","#9467bd")]
def roc(pos,neg):
    ts=np.unique(np.concatenate([pos,neg,[np.inf]]))[::-1]; fpr=[];tpr=[]
    for t in ts: fpr.append((neg>=t).mean()); tpr.append((pos>=t).mean())
    return np.array(fpr),np.array(tpr)
def auc(f,t): return float(np.sum((f[1:]-f[:-1])*(t[1:]+t[:-1])/2))
fig,axs=plt.subplots(1,2,figsize=(7.2,3.3),sharey=True)
for ax,(title,flt) in zip(axs,[("non-directive benign ($n=195$)",lambda r:r['benign_subtype']!='legit_external'),("all benign ($n=270$)",lambda r:True)]):
    for d,lab,col in S:
        R=[r for r in rows if r['detector']==d]
        pos=np.array([r['detect_score'] for r in R if r['is_attack']==1]); neg=np.array([r['detect_score'] for r in R if r['is_attack']==0 and flt(r)])
        f,t=roc(pos,neg); ax.plot(f,t,color=col,lw=1.8,label=f"{lab}, AUROC {auc(f,t):.3f}",zorder=3)
        fp=(neg>=0.60).mean(); tp=(pos>=0.60).mean(); ax.plot(fp,tp,marker="o",ms=5,color=col,mec="white",mew=0.8,zorder=4)
    ax.plot([0,1],[0,1],ls=":",color="0.6",lw=0.8); ax.set_xlim(-0.01,1); ax.set_ylim(0,1.02)
    ax.set_xlabel("false positive rate",fontsize=9); ax.set_title(title,fontsize=9.5); ax.tick_params(labelsize=8.5)
    ax.grid(color="0.9",lw=0.6,zorder=0)
    for sp in ["top","right"]: ax.spines[sp].set_visible(False)
    ax.legend(fontsize=7.2,loc="lower right",frameon=False)
axs[0].set_ylabel("true positive rate",fontsize=9)
fig.text(0.5,-0.02,r"markers: operating point at the a priori threshold $\tau_{\mathrm{TSA}}=0.60$",ha="center",fontsize=8)
fig.tight_layout(); fig.savefig(out+".pdf",bbox_inches="tight"); fig.savefig(out+".png",dpi=220,bbox_inches="tight"); print("ok")
