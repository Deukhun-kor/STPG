"""Reproduces the paper's Section 7 numbers from the result DBs. Usage: python scripts/analysis/<name>.py results/<db>"""
import sys
import sqlite3, numpy as np
c=sqlite3.connect(sys.argv[1] if len(sys.argv)>1 else "results/rev5_main.db"); c.row_factory=sqlite3.Row
rows=[dict(r) for r in c.execute("SELECT * FROM results")]
def youden_thr(att,ben):
    att=np.asarray(att); ben=np.asarray(ben)
    s=np.unique(np.concatenate([att,ben])); cand=[]
    # candidate thresholds: midpoints between consecutive unique scores, plus extremes
    mids=np.concatenate([[s[0]-1e-6],(s[:-1]+s[1:])/2,[s[-1]+1e-6]])
    J=[np.mean(att>=t)-np.mean(ben>=t) for t in mids]
    Jmax=max(J); best=[t for t,j in zip(mids,J) if abs(j-Jmax)<1e-12]
    return float(np.median(best)) if len(best)%2 else float((best[len(best)//2-1]+best[len(best)//2])/2), Jmax
doms=sorted(set(r['domain'] for r in rows))
print("=== LODO Youden-J threshold (calibrate on 2 domains: attack vs non-exfil benign) -> held-out domain ===")
for d in ["stpg","judge_gate","unit","window"]:
    print(f"  {d}:")
    agg=dict(tp=0,n_att=0,fp_nd=0,n_nd=0,fp_all=0,n_all=0)
    for h in doms:
        ca=[r['detect_score'] for r in rows if r['detector']==d and r['is_attack']==1 and r['domain']!=h]
        cb=[r['detect_score'] for r in rows if r['detector']==d and r['is_attack']==0 and r['domain']!=h and r['benign_subtype']!='legit_external']
        t,J=youden_thr(ca,cb)
        ta=np.array([r['detect_score'] for r in rows if r['detector']==d and r['is_attack']==1 and r['domain']==h])
        tb=np.array([r['detect_score'] for r in rows if r['detector']==d and r['is_attack']==0 and r['domain']==h and r['benign_subtype']!='legit_external'])
        tall=np.array([r['detect_score'] for r in rows if r['detector']==d and r['is_attack']==0 and r['domain']==h])
        agg['tp']+=int((ta>=t).sum()); agg['n_att']+=len(ta); agg['fp_nd']+=int((tb>=t).sum()); agg['n_nd']+=len(tb); agg['fp_all']+=int((tall>=t).sum()); agg['n_all']+=len(tall)
        print(f"     held-out {h:9s} thr={t:.3f} (cal J={J:.3f})  TPR={np.mean(ta>=t):.3f} ({int((ta>=t).sum())}/{len(ta)})  FPR_nonexfil={np.mean(tb>=t):.3f} ({int((tb>=t).sum())}/{len(tb)})  FPR_all={np.mean(tall>=t):.3f}")
    print(f"     pooled: TPR={agg['tp']}/{agg['n_att']}={agg['tp']/agg['n_att']:.3f} FPR_nonexfil={agg['fp_nd']}/{agg['n_nd']}={agg['fp_nd']/agg['n_nd']:.3f} FPR_all={agg['fp_all']}/{agg['n_all']}={agg['fp_all']/agg['n_all']:.3f}")
print("\n=== unit per-record claim: unit score distribution attack vs non-exfil benign ===")
for d in ["unit"]:
    att=np.array([r['detect_score'] for r in rows if r['detector']==d and r['is_attack']==1]); bnd=np.array([r['detect_score'] for r in rows if r['detector']==d and r['is_attack']==0 and r['benign_subtype']!='legit_external'])
    print(f"  attack: mean={att.mean():.3f} sd={att.std():.3f} min={att.min():.2f} max={att.max():.2f}; nonexfil benign: mean={bnd.mean():.3f} sd={bnd.std():.3f} min={bnd.min():.2f} max={bnd.max():.2f}")
    for k in [2,3,4,5]:
        a=np.array([r['detect_score'] for r in rows if r['detector']==d and r['is_attack']==1 and r['k']==k]); print(f"   k={k} unit mean={a.mean():.3f} min={a.min():.2f}")
print("\n=== window by k,d AUROC vs nonexfil ===")
def auroc(p,n): p=np.asarray(p); n=np.asarray(n); return float(np.mean(p[:,None]>n[None,:])+0.5*np.mean(p[:,None]==n[None,:]))
for d in ["window","unit","stpg","judge_gate"]:
    bnd=[r['detect_score'] for r in rows if r['detector']==d and r['is_attack']==0 and r['benign_subtype']!='legit_external']
    print(" ",d,"k:",{k:round(auroc([r['detect_score'] for r in rows if r['detector']==d and r['is_attack'] and r['k']==k],bnd),3) for k in [2,3,4,5]},
          "d:",{dd:round(auroc([r['detect_score'] for r in rows if r['detector']==d and r['is_attack'] and r['d']==dd],bnd),3) for dd in [1,3,5]})
