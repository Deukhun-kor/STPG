"""
S2-3 검증: PDG 인자 수준 taint. 실점수기 환경에서
  - 공격: 외부 합성 싱크(SYNTH-AUDIT-SINK)로 라우팅 + 비신뢰 외부유입 계보 -> 차단
  - 정당(A): 내부 승인 목적지(internal-ops-queue) 로 라우팅 -> 통과
  - 정상: 라우팅 없음 -> 특권호출 안 함(n/a)
목적지는 '에이전트가 산출한 값' 을 그대로 싱크 인자로 전달(S1/실행 경로와 동일).
  python scripts/s2_verify_pdg.py --n 4
"""
import sys, os, argparse, json, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stpg import config as C
from stpg.datagen.realistic import build_realistic_specs
from stpg.storage.sqlite_store import SqliteStore
from stpg.gateway.stpg import STPGGateway
from stpg.gateway.scoring import TSAScorer
from stpg.agents.gemini_llm import GeminiLLM


def _ctx(agent, sess, run_id, origin):
    prof = C.AGENT_PROFILES[agent]
    class X: pass
    c=X(); c.agent=agent; c.agent_trust=prof["trust"]; c.agent_priv=prof["priv"]
    c.session_id=sess; c.run_id=run_id; c.origin_endpoint=origin; c.allowed_tools=tuple(prof["tools"])
    return c


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--n", type=int, default=4); a=ap.parse_args()
    cfg=C.load_profile("s0_mock_small"); cfg.scorer.kind="tsa"
    specs=build_realistic_specs(cfg, benign_mode="with_legit")
    atk=[s for s in specs if s.is_attack][:a.n]
    # 정당 라우팅이 든 정상만 골라 PDG 통과를 확인
    legit=[s for s in specs if not s.is_attack and
           any("internal-ops-queue" in r["text"] for r in s.ingest_records)][:a.n]
    brain=GeminiLLM("gemini-2.5-fl")

    print(f"=== S2-3 PDG 인자 taint 검증 (내부 allowlist={sorted(C.APPROVED_INTERNAL_DESTINATIONS)}) ===")
    print(f"{'type':10s} {'TSA':>5s} {'dest':>22s} {'ext':>5s} {'PDG블록':>7s}")
    rows=[]
    for tag, group in [("ATTACK", atk), ("LEGIT", legit)]:
        for sp in group:
            store=SqliteStore(); store.reset()
            gw=STPGGateway(TSAScorer(cfg.scorer), cfg.tsa_threshold, cfg.pdg_min_delta)
            writer="sa-agent-ingest" if tag=="ATTACK" else "sa-agent-ops"
            for r in sp.ingest_records:
                clean={k:v for k,v in r.items() if k not in ("shard","kind")}
                prov=gw.on_write(clean, _ctx(writer,"s1",sp.run_id,"/ingest/source" if tag=="ATTACK" else "/ops/routine"))
                store.write_record(r, prov)
            recs=store.read_records(sp.domain)
            recs, det=gw.on_read(recs, _ctx("sa-agent-ops","trig",sp.run_id,"n/a"), store)
            # 실제 에이전트가 목적지를 산출
            dec=brain.decide_ops(recs, None, None)["decision"]
            dest=dec.get("destination")
            blocked=None
            if dec["action"] in ("privileged_call","internal_routing") and dest:
                infl=[r for r in recs if r.get("_provenance")]
                ok,reason,pd=gw.on_sink("/iam/grant", {"destination":dest}, _ctx("sa-agent-ops","trig",sp.run_id,"n/a"), infl, store)
                blocked=not ok
            ext = (pd or {}).get("external_route") if dest else None
            print(f"{tag:10s} {str((det or {}).get('flagged')):>5s} {str(dest):>22s} {str(ext):>5s} {str(blocked):>7s}")
            rows.append({"t":tag,"tsa":(det or {}).get("flagged"),"dest":dest,"external":ext,"blocked":blocked})
            time.sleep(0.6)
    nb_atk=sum(1 for r in rows if r["t"]=="ATTACK" and r["blocked"])
    pass_leg=sum(1 for r in rows if r["t"]=="LEGIT" and r["blocked"] is False)
    print(f"\nPDG: 공격 차단 {nb_atk}/{len(atk)}  |  정당 통과 {pass_leg}/{len(legit)}")
    os.makedirs("results",exist_ok=True); json.dump(rows, open("results/s2_verify_pdg.json","w"), indent=2)
    print("저장: results/s2_verify_pdg.json")

if __name__=="__main__":
    main()
