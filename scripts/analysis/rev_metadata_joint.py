import pandas as pd, numpy as np, sys
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import roc_auc_score
df=pd.read_csv(sys.argv[1] if len(sys.argv)>1 else "rev3_metadata_features.csv")
feats=[c for c in df.columns if c not in ("run_id","label","domain","k","d","g","subtype")]
X=df[feats].values; y=df.label.values; rng=np.random.RandomState(0)
models={"logistic":lambda: make_pipeline(StandardScaler(),LogisticRegression(max_iter=3000)),
        "tree(depth3)":lambda: DecisionTreeClassifier(max_depth=3,random_state=0),
        "boosting":lambda: GradientBoostingClassifier(random_state=0)}
print("=== LODO: per-fold counts and AUROC (scaler fit on training fold only; fold AUROC, then mean) ===")
for dom in sorted(df.domain.unique()):
    te=df.domain==dom; print(f"  fold held-out={dom}: train n={(~te).sum()} (attack {int(y[~te].sum())}), test n={te.sum()} (attack {int(y[te].sum())}, benign {int((1-y[te]).sum())})")
for name,mk in models.items():
    outs=[]
    for dom in sorted(df.domain.unique()):
        tr=df.domain!=dom; te=df.domain==dom; m=mk().fit(X[tr],y[tr]); outs.append(roc_auc_score(y[te],m.predict_proba(X[te])[:,1]))
    print(f"  {name:12s} fold AUROCs={np.round(outs,3)} mean={np.mean(outs):.3f}")
print("\n=== balanced leave-one-attack-family-out: hold out one (domain,k) family (54 attacks) + a seeded quarter of that domain's benign (~22); rest trains ===")
for name,mk in models.items():
    outs=[]; fold_info=[]
    for dom in sorted(df.domain.unique()):
        ben_idx=np.where((df.domain==dom)&(df.label==0))[0]; rng2=np.random.RandomState(sum(map(ord,dom)))
        parts=np.array_split(rng2.permutation(ben_idx),4)
        for i,k in enumerate([2,3,4,5]):
            te=np.zeros(len(df),bool); te[np.where((df.domain==dom)&(df.k==k)&(df.label==1))[0]]=True; te[parts[i]]=True
            m=mk().fit(X[~te],y[~te]); outs.append(roc_auc_score(y[te],m.predict_proba(X[te])[:,1])); fold_info.append((dom,k,int(y[te].sum()),int((1-y[te]).sum())))
    print(f"  {name:12s} fold AUROCs={np.round(outs,2)} mean={np.mean(outs):.3f} min={np.min(outs):.3f} max={np.max(outs):.3f}")
print("  fold sizes (domain,k,attack,benign):",fold_info[:4],"...")
print("\n=== permutation (LODO, 50 runs): mean, 2.5-97.5 pct ===")
for name,mk in models.items():
    ps=[]
    for it in range(50):
        yp=rng.permutation(y); outs=[]
        for dom in sorted(df.domain.unique()):
            tr=df.domain!=dom; te=df.domain==dom; m=mk().fit(X[tr],yp[tr]); outs.append(roc_auc_score(yp[te],m.predict_proba(X[te])[:,1]))
        ps.append(np.mean(outs))
    print(f"  {name:12s} mean={np.mean(ps):.3f} [{np.percentile(ps,2.5):.3f},{np.percentile(ps,97.5):.3f}]")
