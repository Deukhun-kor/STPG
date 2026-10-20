import pandas as pd, numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import roc_auc_score
df=pd.read_csv("rev3_metadata_features.csv")
feats=[c for c in df.columns if c not in ("run_id","label","domain","k","d","g","subtype")]
print(feats)
lenf=[c for c in feats if "len" in c]; nolen=[c for c in feats if c not in lenf]
y=df.label.values
def lofo(cols):
    X=df[cols].values; outs=[]
    for dom in sorted(df.domain.unique()):
        ben_idx=np.where((df.domain==dom)&(df.label==0))[0]; rng2=np.random.RandomState(sum(map(ord,dom)))
        parts=np.array_split(rng2.permutation(ben_idx),4)
        for i,k in enumerate([2,3,4,5]):
            te=np.zeros(len(df),bool); te[np.where((df.domain==dom)&(df.k==k)&(df.label==1))[0]]=True; te[parts[i]]=True
            m=GradientBoostingClassifier(random_state=0).fit(X[~te],y[~te]); outs.append(roc_auc_score(y[te],m.predict_proba(X[te])[:,1]))
    return np.mean(outs), np.round(outs,2)
print("boosting all feats", lofo(feats)); print("length-only", lofo(lenf)); print("no-length", lofo(nolen))
t=DecisionTreeClassifier(max_depth=3,random_state=0).fit(df[feats].values,y)
imp=sorted(zip(feats,t.feature_importances_),key=lambda x:-x[1])[:4]; print("tree importances (in-sample)",imp)
# in-sample fit
b=GradientBoostingClassifier(random_state=0).fit(df[feats].values,y); print("boost in-sample AUROC",roc_auc_score(y,b.predict_proba(df[feats].values)[:,1]))
