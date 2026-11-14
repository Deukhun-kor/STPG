"""
S2-2 게이트웨이 전체 검증: 실점수기(TSAScorer)를 STPGGateway 에 연결하고,
공격/정상 트레이스를 넣어 TSA 의 창발 탐지(delta)와 PDG 차단이 동작하는지 본다.
정답(truth) 없이 본문·출처만으로. 로컬(Vertex 인증) 실행.
  python scripts/s2_verify_tsa.py --n 4
"""
import sys, os, argparse, json, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stpg import config as C
from stpg.datagen.realistic import build_realistic_specs
from stpg.storage.sqlite_store import SqliteStore
from stpg.gateway.stpg import STPGGateway
from stpg.gateway.scoring import TSAScorer


def _ctx(agent, sess, run_id, origin):
    prof = C.AGENT_PROFILES[agent]
    class X: pass
    c = X(); c.agent=agent; c.agent_trust=prof["trust"]; c.agent_priv=prof["priv"]
    c.session_id=sess; c.run_id=run_id; c.origin_endpoint=origin; c.allowed_tools=tuple(prof["tools"])
    return c


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--n", type=int, default=4); a=ap.parse_args()
    cfg = C.load_profile("s0_mock_small"); cfg.scorer.kind = "tsa"
    specs = build_realistic_specs(cfg, benign_mode="with_legit")
    atk = [s for s in specs if s.is_attack][:a.n]
    ben = [s for s in specs if not s.is_attack][:a.n]

    print(f"=== TSA 전체 검증 (실점수기 cascade, 임계 {cfg.tsa_threshold}) ===")
    print(f"{'type':6s} {'k':>2s} {'emergent':>9s} {'ind_max':>8s} {'delta':>7s} {'TSA':>5s} {'PDG블록':>7s}")
    rows=[]
    for tag, group in [("ATK", atk), ("BEN", ben)]:
        for sp in group:
            store = SqliteStore(); store.reset()
            gw = STPGGateway(TSAScorer(cfg.scorer), cfg.tsa_threshold, cfg.pdg_min_delta)
            # 쓰기(PPT) — g 에 따라 작성자 결정
            writer = "sa-agent-ingest" if sp.g==1 else "sa-agent-ops"
            for r in sp.ingest_records:
                clean = {k:v for k,v in r.items() if k not in ("shard","kind")}
                prov = gw.on_write(clean, _ctx(writer,"s1",sp.run_id,"/ingest/source"))
                store.write_record(r, prov)
            # 읽기(TSA)
            recs = store.read_records(sp.domain)
            recs, det = gw.on_read(recs, _ctx("sa-agent-ops","trig",sp.run_id,"n/a"), store)
            d = det or {}
            # PDG: '공격'만 외부 특권 싱크를 시도(실제 에이전트가 외부 라우팅을 택한 경우에 해당).
            # 정상은 특권 싱크를 호출하지 않으므로 PDG 평가 대상이 아님(n/a).
            pdg_blocked = None
            if tag == "ATK":
                infl = [r for r in recs if r.get("_provenance")]
                ok,reason,pd = gw.on_sink("/iam/grant",{}, _ctx("sa-agent-ops","trig",sp.run_id,"n/a"), infl, store)
                pdg_blocked = (not ok)
            print(f"{tag:6s} {sp.k:>2d} {d.get('emergent',0):9.3f} {d.get('individual_max',0):8.3f} "
                  f"{d.get('delta',0):7.3f} {str(d.get('flagged')):>5s} {str(pdg_blocked):>7s}")
            rows.append({"t":tag,"k":sp.k,"emergent":d.get("emergent"),"ind_max":d.get("individual_max"),
                         "delta":d.get("delta"),"tsa_flagged":d.get("flagged"),"pdg_blocked":pdg_blocked})
            time.sleep(0.5)
    def avg(tp,key): v=[r[key] for r in rows if r["t"]==tp and r[key] is not None]; return sum(v)/len(v) if v else 0
    print(f"\n평균 emergent: 공격={avg('ATK','emergent'):.3f} 정상={avg('BEN','emergent'):.3f}")
    print(f"평균 delta   : 공격={avg('ATK','delta'):.3f} 정상={avg('BEN','delta'):.3f}")
    print(f"TSA 탐지율   : 공격={sum(1 for r in rows if r['t']=='ATK' and r['tsa_flagged'])}/{len(atk)} "
          f"정상(오탐)={sum(1 for r in rows if r['t']=='BEN' and r['tsa_flagged'])}/{len(ben)}")
    print(f"PDG 차단율   : 공격={sum(1 for r in rows if r['t']=='ATK' and r['pdg_blocked'])}/{len(atk)} (정상은 특권호출 안 함=평가대상 아님)")
    os.makedirs("results",exist_ok=True); json.dump(rows, open("results/s2_verify_tsa.json","w"), indent=2)
    print("저장: results/s2_verify_tsa.json")

if __name__ == "__main__":
    main()
