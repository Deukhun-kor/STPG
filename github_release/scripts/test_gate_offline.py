"""게이트 v3.3 오프라인 검증(모델 호출 없음): 키워드 모의 점수기·모의 witness 로 정책 분기를 점검."""
import sys, os, re, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stpg import config as C
from stpg.datagen.holdout import build_holdout_specs
from stpg.datagen.realistic import build_realistic_specs
from stpg.storage.sqlite_store import SqliteStore
from stpg.gateway.stpg import STPGGateway

class KW:
    calls=0; second_stage_calls=0
    def individual(self, r): return 0.3
    def assembled(self, recs):
        t=" ".join(r["text"] for r in recs).lower()
        return 0.9 if re.search(r"(mirrored to|forward|deliver|distributed to|route|export)", t) else 0.3
    def targets(self, recs, dest):
        # 모의 witness(v3.3): 레코드별 역할과 지지 레코드를 반환. 전송 동사가 있는 레코드가 'target', 매핑형은 'mapping'.
        import re as _re
        roles={}; support=[]; tg=False
        for r in recs:
            tx=r["text"]; low=tx.lower()
            i=tx.find(dest)
            if i>=0 and _re.search(r"(retired|must not|reference only|listed for reference)", low[i:i+len(dest)+30]): roles[r["record_id"]]="prohibited"; continue
            if _re.search(r"(mirrored to|forward|deliver|distributed to|route|export|archived)", low):
                roles[r["record_id"]]="target"; support.append(r["record_id"]); tg=True
            elif _re.search(r"(=|maps to|resolves to)", low): roles[r["record_id"]]="mapping"
            else: roles[r["record_id"]]="none"
        return (tg, roles, support)

def _ctx(agent, sess, run_id, origin, origin_ref=None):
    prof=C.AGENT_PROFILES[agent]
    class X: pass
    c=X(); c.agent=agent; c.agent_trust=prof["trust"]; c.agent_priv=prof["priv"]; c.session_id=sess
    c.run_id=run_id; c.origin_endpoint=origin; c.allowed_tools=tuple(prof["tools"]); c.origin_ref=origin_ref; return c

def evaluate(sp, gw, dest):
    store=SqliteStore(); store.reset()
    for r in sp.ingest_records:
        prov=gw.on_write({k:v for k,v in r.items() if k not in ("shard","kind")}, _ctx(r["_writer"], r["_session"], sp.run_id, r["_origin"], r.get("_origin_ref")))
        if r.get("_drop_provenance"): prov=None
        store.write_record(r, prov)
    recs=store.read_records(sp.domain)
    recs, fl=gw.on_read(recs, _ctx("sa-agent-ops","trig",sp.run_id,"n/a"), store)
    ok,_,d=gw.on_sink("/route",{"destination":dest}, _ctx("sa-agent-ops","trig",sp.run_id,"n/a"), recs, store, flag=fl)
    return ok, d["evidence"]

cfg=C.load_profile("s4_main")
gws={"stpg":STPGGateway(KW(),0.6,1,gate_mode="attributed"),
     "allow":STPGGateway(KW(),0.6,1,gate_mode="attributed-allow"),
     "tdo":STPGGateway(KW(),0.6,1,gate_mode="trusted-only"),
     "tdo_allow":STPGGateway(KW(),0.6,1,gate_mode="trusted-only-allow"),
     "pdgonly":STPGGateway(KW(),0.6,1,enable_tsa=False,gate_mode="any-untrusted"),
     "match":STPGGateway(KW(),0.6,1,enable_tsa=False,gate_mode="match")}
print("=== holdout: per condition correct/total ===")
hs=build_holdout_specs(cfg,2,2)
names=[]; [names.append(s.structure) for s in hs if s.structure not in names]
for name in names:
    line=f"{name:18s}"
    for g,gw in gws.items():
        ok=tot=0; ev=collections.Counter()
        for sp in [s for s in hs if s.structure==name]:
            for dest,exp in sp.expected.items():
                a,e=evaluate(sp,gw,dest); dec="pass" if a else "block"; tot+=1; ok+=(dec==exp)
                if dec!=exp: ev[e]+=1
        line+=f" | {g}:{ok}/{tot}"+(f"{dict(ev)}" if ev else "")
    print(line)
print("\n=== endpoint pre-check: routing to a label/key that the context resolves must be blocked as non-endpoint ===")
for sp in [s for s in hs if s.structure=="deep_reference"][:2]:
    lab=[r["text"] for r in sp.ingest_records if "resolves to recipient" in r["text"]][0].split("`")[1]
    print("  dest=",lab, {g:("pass" if evaluate(sp,gw,lab)[0] else "block")+"/"+evaluate(sp,gw,lab)[1] for g,gw in gws.items()})
print("\n=== main sanity ===")
cfg.factors.n_benign_per_domain=6
ms=build_realistic_specs(cfg, benign_mode="with_legit", n_distractor=2)
seen=collections.Counter()
for sp in ms:
    st=sp.benign_subtype or "attack"
    if seen[st]>=2: continue
    seen[st]+=1
    if sp.is_attack: dest=[r["text"] for r in sp.ingest_records if r.get("kind")=="shard"][-1].split("=")[-1].strip(" .")
    elif st=="legit_external": dest=[r["text"] for r in sp.ingest_records if "partner" in r["text"]][0].split("partner ")[-1].strip(" .")
    else: dest="internal-ops-queue"
    print(f"  {st:18s}", {g:("pass" if evaluate(sp,gw,dest)[0] else "block")+"/"+evaluate(sp,gw,dest)[1] for g,gw in gws.items()})
