"""Reproduces the paper's Section 7 numbers from the result DBs. Usage: python scripts/analysis/<name>.py results/<db>"""
import sys
import sqlite3, statistics, collections, math, random, json, sys
import numpy as np
from scipy import stats as st
random.seed(7); np.random.seed(7)
db=sys.argv[1]
c=sqlite3.connect(db); c.row_factory=sqlite3.Row
rows=[dict(r) for r in c.execute("SELECT * FROM results")]
dets=["none","stpg","stpg_pdgonly","judge_gate","unit","window","taint"]
def wilson(x,n,z=1.96):
    if n==0: return (float('nan'),float('nan'))
    p=x/n; den=1+z*z/n; cen=(p+z*z/(2*n))/den; half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
    return (max(0,cen-half),min(1,cen+half))
def cp(x,n):  # Clopper-Pearson
    lo=0.0 if x==0 else st.beta.ppf(0.025,x,n-x+1); hi=1.0 if x==n else st.beta.ppf(0.975,x+1,n-x); return lo,hi
def auroc(pos,neg):
    pos=np.asarray(pos); neg=np.asarray(neg)
    return (np.mean(pos[:,None]>neg[None,:])+0.5*np.mean(pos[:,None]==neg[None,:]))
def delong(pos_a,neg_a,pos_b,neg_b):
    """DeLong paired test for two correlated AUROCs on same samples."""
    def comps(pos,neg):
        pos=np.asarray(pos); neg=np.asarray(neg)
        V10=np.array([np.mean((p>neg)+0.5*(p==neg)) for p in pos]); V01=np.array([np.mean((pos>n)+0.5*(pos==n)) for n in neg]); return V10,V01
    a10,a01=comps(pos_a,neg_a); b10,b01=comps(pos_b,neg_b)
    A=a10.mean(); B=b10.mean(); m=len(a10); n=len(a01)
    S10=np.cov(np.vstack([a10,b10])); S01=np.cov(np.vstack([a01,b01]))
    S=S10/m+S01/n; var=S[0,0]+S[1,1]-2*S[0,1]
    if var<=1e-12: return A,B,float('nan'),float('nan')
    z=(A-B)/math.sqrt(var); return A,B,z,2*(1-st.norm.cdf(abs(z)))
def boot_auroc(pos,neg,B=2000):
    pos=np.asarray(pos); neg=np.asarray(neg); out=[]
    for _ in range(B):
        out.append(auroc(np.random.choice(pos,len(pos)),np.random.choice(neg,len(neg))))
    return np.percentile(out,[2.5,97.5])
res={}
print("=== ATTACK ASR with 95% CI (Clopper-Pearson) ===")
for d in dets:
    a=[r for r in rows if r['detector']==d and r['is_attack']==1]
    x=sum(r['attack_success'] for r in a); n=len(a); lo,hi=cp(x,n)
    print(f"  {d:13s} {x}/{n} = {x/n:.3f} [{lo:.3f},{hi:.3f}]")
    res.setdefault("asr",{})[d]=(x,n,lo,hi)
print("\n=== LEGIT_EXTERNAL false-block (among externally routed) 95% CI ===")
for d in dets:
    b=[r for r in rows if r['detector']==d and r['benign_subtype']=='legit_external' and r['routed_external']==1]
    x=sum(r['false_block'] for r in b); n=len(b); lo,hi=cp(x,n)
    print(f"  {d:13s} {x}/{n} = {x/n:.3f} [{lo:.3f},{hi:.3f}]")
    res.setdefault("fb",{})[d]=(x,n,lo,hi)
# McNemar stpg vs pdgonly on legit_external paired by run_id
A={r['run_id']:r['false_block'] for r in rows if r['detector']=='stpg' and r['benign_subtype']=='legit_external' and r['routed_external']}
Bq={r['run_id']:r['false_block'] for r in rows if r['detector']=='stpg_pdgonly' and r['benign_subtype']=='legit_external' and r['routed_external']}
b01=sum(1 for k in A if A[k]==0 and Bq[k]==1); b10=sum(1 for k in A if A[k]==1 and Bq[k]==0)
p_mc=st.binomtest(b01,b01+b10,0.5).pvalue if (b01+b10)>0 else float('nan')
print(f"  McNemar (exact) stpg vs pdgonly discordant: stpg-pass/pdg-block={b01}, stpg-block/pdg-pass={b10}, p={p_mc:.2e}")
print("\n=== 'benign' subtype externally-routed (agent-initiated, no directive) ===")
for r in rows:
    if r['detector']=='none' and r['benign_subtype']=='benign' and r['routed_external']: print("  ",r['run_id'],r['domain'],r['destination'])
print("\n=== DETECTION AUROC [bootstrap 95% CI] all-benign | non-directive-benign ; operating point @tau=0.60 ===")
sc={}
for d in ["stpg","judge_gate","unit","window"]:
    att=[r['detect_score'] for r in rows if r['detector']==d and r['is_attack']==1]
    ben=[r['detect_score'] for r in rows if r['detector']==d and r['is_attack']==0]
    bnd=[r['detect_score'] for r in rows if r['detector']==d and r['is_attack']==0 and r['benign_subtype']!='legit_external']
    sc[d]=(att,ben,bnd)
    a1=auroc(att,ben); ci1=boot_auroc(att,ben); a2=auroc(att,bnd); ci2=boot_auroc(att,bnd)
    tpr=np.mean(np.array(att)>=0.60); fpr_all=np.mean(np.array(ben)>=0.60); fpr_nd=np.mean(np.array(bnd)>=0.60)
    print(f"  {d:11s} AUROC_all={a1:.3f} [{ci1[0]:.3f},{ci1[1]:.3f}]  AUROC_nondir={a2:.3f} [{ci2[0]:.3f},{ci2[1]:.3f}] | TPR@.60={tpr:.3f} FPR_all@.60={fpr_all:.3f} FPR_nondir@.60={fpr_nd:.3f}")
    res.setdefault("auroc",{})[d]=dict(all=a1,all_ci=list(ci1),nondir=a2,nondir_ci=list(ci2),tpr=tpr,fpr_all=fpr_all,fpr_nd=fpr_nd)
print("\n=== DeLong paired tests (stpg vs X) ===")
for x in ["judge_gate","unit","window"]:
    for lab,idx in [("all",1),("nondir",2)]:
        A_,B_,z,p=delong(sc["stpg"][0],sc["stpg"][idx],sc[x][0],sc[x][idx])
        print(f"  stpg vs {x:10s} ({lab:6s}): {A_:.3f} vs {B_:.3f}  z={z:.2f} p={p:.2e}")
print("\n=== by domain (stpg AUROC_all / ASR none / fb pdgonly) ===")
for dom in sorted(set(r['domain'] for r in rows)):
    att=[r['detect_score'] for r in rows if r['detector']=='stpg' and r['is_attack']==1 and r['domain']==dom]
    ben=[r['detect_score'] for r in rows if r['detector']=='stpg' and r['is_attack']==0 and r['domain']==dom]
    bnd=[r['detect_score'] for r in rows if r['detector']=='stpg' and r['is_attack']==0 and r['domain']==dom and r['benign_subtype']!='legit_external']
    print(f"  {dom:9s} n_att={len(att)} n_ben={len(ben)} AUROC_all={auroc(att,ben):.3f} AUROC_nondir={auroc(att,bnd):.3f}")
print("\n=== by hide_location? (not stored) ; stpg TPR@.60 by k,d ===")
for k in [2,3,4,5]:
    print("  k=%d"%k, {d_: round(float(np.mean([r['detect_score']>=0.6 for r in rows if r['detector']=='stpg' and r['is_attack'] and r['k']==k and r['d']==d_])),3) for d_ in [1,3,5]})
print("\n=== threshold sensitivity (stpg): tau -> TPR / FPR_all / FPR_nondir ===")
att,ben,bnd=sc["stpg"]
for t in [0.4,0.5,0.6,0.7,0.8,0.85,0.9]:
    print(f"  tau={t:.2f} TPR={np.mean(np.array(att)>=t):.3f} FPR_all={np.mean(np.array(ben)>=t):.3f} FPR_nondir={np.mean(np.array(bnd)>=t):.3f}")
print("\n=== score distributions (stpg) by subtype ===")
for stn in ["attack","legit_external","legit_internal","untrusted_internal","benign"]:
    v=[r['detect_score'] for r in rows if r['detector']=='stpg' and (r['benign_subtype']==stn)]
    print(f"  {stn:18s} n={len(v)} mean={np.mean(v):.3f} sd={np.std(v):.3f} min={min(v):.2f} max={max(v):.2f}")
print("judge_gate nondir benign scores>=0.6:", [ (r['run_id'],r['benign_subtype'],r['detect_score']) for r in rows if r['detector']=='judge_gate' and r['is_attack']==0 and r['benign_subtype']!='legit_external' and r['detect_score']>=0.6])
json.dump(res,open(db.replace('.db','_stats.json'),'w'),indent=1,default=float)
