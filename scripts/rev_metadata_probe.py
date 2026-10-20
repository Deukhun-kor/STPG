"""메타데이터 전용 프로브용 특징 추출(본문 미사용). 트레이스별 특징을 CSV 로 내보낸다 (rev_metadata_joint.py 가 분석)."""
import sys, os, csv, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stpg import config as C
from stpg.datagen.realistic import build_realistic_specs
cfg=C.load_profile('s4_main'); cfg.factors.n_benign_per_domain=90
sp=build_realistic_specs(cfg, benign_mode='with_legit', n_distractor=2)
def lineage_key(r): return r["_origin_ref"] if r["_origin_ref"] else (r["_writer"],r["_origin"],r["_session"])
rows=[]
for s in sp:
    recs=s.ingest_records
    groups=collections.Counter(lineage_key(r) for r in recs)
    unt=[r for r in recs if r["_origin"].startswith("/ingest")]
    ug=collections.Counter(r["_origin_ref"] for r in unt if r["_origin_ref"])
    sess=[r["_session"] for r in recs]
    rows.append(dict(run_id=s.run_id, label=int(s.is_attack), domain=s.domain, k=s.k, d=s.d, g=s.g, subtype=s.benign_subtype or "attack",
        n_records=len(recs), n_sessions=len(set(sess)), n_groups=len(groups), n_untrusted=len(unt),
        max_untrusted_lineage=max(ug.values()) if ug else 0, n_untrusted_lineages=len(ug),
        n_trusted_writers=len({r["_writer"] for r in recs if not r["_origin"].startswith("/ingest")}),
        frac_untrusted=len(unt)/len(recs), n_hide_api=sum(r["hide_location"]=="api_description_field" for r in recs),
        n_hide_ticket=sum(r["hide_location"]=="ticket_body" for r in recs), n_hide_log=sum(r["hide_location"]=="log_message" for r in recs),
        mean_len=sum(len(r["text"]) for r in recs)/len(recs), max_len=max(len(r["text"]) for r in recs), min_len=min(len(r["text"]) for r in recs),
        untrusted_mean_len=(sum(len(r["text"]) for r in unt)/len(unt)) if unt else 0,
        first_untrusted_pos=next((i for i,r in enumerate(recs) if r["_origin"].startswith("/ingest")), -1),
        last_untrusted_pos=max((i for i,r in enumerate(recs) if r["_origin"].startswith("/ingest")), default=-1),
        untrusted_sessions=len({r["_session"] for r in unt}), records_per_session=len(recs)/max(1,len(set(sess)))))
os.makedirs("results", exist_ok=True)
with open("results/rev3_metadata_features.csv","w",newline="") as f:
    w=csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
print(len(rows), "rows ->", "results/rev3_metadata_features.csv")
