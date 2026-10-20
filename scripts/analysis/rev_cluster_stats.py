import sqlite3, numpy as np, collections
from scipy import stats as st
np.random.seed(11)
c=sqlite3.connect("rev10_main.db"); c.row_factory=sqlite3.Row
rows=[dict(r) for r in c.execute("SELECT * FROM results WHERE cf=''")]
def auroc(p,n): p=np.asarray(p); n=np.asarray(n); return float(np.mean(p[:,None]>n[None,:])+0.5*np.mean(p[:,None]==n[None,:]))
nd=lambda r:r['benign_subtype']!='legit_external'
print("=== paired cluster bootstrap, BOTH classes by family (attack: domain x k =12; benign: domain x subtype = 12) ===")
for lab,flt in [("nondir",nd),("all",lambda r:True)]:
    S={}
    for d in ["stpg","judge_gate","unit","window"]:
        att={}; ben={}
        for r in rows:
            if r['detector']!=d: continue
            if r['is_attack']: att.setdefault((r['domain'],r['k']),[]).append(r['detect_score'])
            elif flt(r): ben.setdefault((r['domain'],r['benign_subtype']),[]).append(r['detect_score'])
        S[d]=(att,ben)
    ac=list(S["stpg"][0].keys()); bc=list(S["stpg"][1].keys())
    boots={d:[] for d in S}
    for _ in range(2000):
        ai=np.random.randint(0,len(ac),len(ac)); bi=np.random.randint(0,len(bc),len(bc))
        for d,(att,ben) in S.items():
            pa=[x for i in ai for x in att[ac[i]]]; nb=[x for i in bi for x in ben[bc[i]]]; boots[d].append(auroc(pa,nb))
    for d in S:
        b=np.array(boots[d]); print(f"  [{lab}] {d:11s} point={auroc([x for v in S[d][0].values() for x in v],[x for v in S[d][1].values() for x in v]):.3f} both-family CI=[{np.percentile(b,2.5):.3f},{np.percentile(b,97.5):.3f}]")
    for d in ["judge_gate","unit","window"]:
        diff=np.array(boots["stpg"])-np.array(boots[d]); print(f"  [{lab}] dAUROC stpg-{d:10s} {np.mean(diff):+.3f} [{np.percentile(diff,2.5):+.3f},{np.percentile(diff,97.5):+.3f}]")
print("\n=== legit_external false blocks by domain (rule family) ===")
for d in ["stpg","attr_judge","stpg_pdgonly","match_gate"]:
    print(" ",d,{dom:f"{sum(r['false_block'] for r in rows if r['detector']==d and r['benign_subtype']=='legit_external' and r['routed_external'] and r['domain']==dom)}/{sum(1 for r in rows if r['detector']==d and r['benign_subtype']=='legit_external' and r['routed_external'] and r['domain']==dom)}" for dom in ["billing","iam","incident"]})
print("\n=== internal routing breakdown (none) ===")
for st_ in ["legit_internal","untrusted_internal","benign"]:
    n=[r for r in rows if r['detector']=='none' and r['benign_subtype']==st_]
    print(f"  {st_:18s} n={len(n)} internal={sum(1 for r in n if r['did_route'] and not r['routed_external'])} external={sum(r['routed_external'] for r in n)} status={sum(1 for r in n if not r['did_route'])}")
print("\n=== FPR<=5% with raw counts (non-directive benign, n=195 -> FP<=9) ===")
for d in ["stpg","judge_gate","unit","window"]:
    att=np.array([r['detect_score'] for r in rows if r['detector']==d and r['is_attack']==1]); bnd=np.array([r['detect_score'] for r in rows if r['detector']==d and r['is_attack']==0 and nd(r)])
    best=(0,None,None)
    for t in np.unique(np.concatenate([att,bnd])):
        fp=int((bnd>=t).sum())
        if fp<=9:
            tp=int((att>=t).sum())
            if tp>best[0]: best=(tp,fp,t)
    print(f"  {d:11s} TP={best[0]}/648 FP={best[1]}/195 thr={best[2]}")
