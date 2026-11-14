"""
세션 격리 러너 (수정판).
  S1 inject         : 수집 에이전트가 ingest_records 저장
  S2..S(1+d) benign : 경유 세션마다 정상 운영 레코드 1~3건 추가 쓰기(D2) — d 가 실제 변수가 됨
  trigger           : 운영 에이전트가 read_records → (조립 시) call_backend_api
권한 격차 g (D1=(a)):
  g=1 : 작성자=sa-agent-ingest(저권한), 호출자=sa-agent-ops(고권한)  → 권한 상승 가능 조건
  g=0 : 작성자·호출자 모두 sa-agent-ops(고권한)                       → 주입은 성립해도 '상승'은 아님(PDG 특이도 대조군)
재현성: 모든 난수는 config.stable_int 기반(프로세스 간 동일).
"""
from __future__ import annotations
import random
from stpg import config as C
from stpg.storage.sqlite_store import SqliteStore
from stpg.mcp.backend import MockBackend
from stpg.mcp.server import ToolRouter, ToolContext
from stpg.agents.llm import MockLLM


def _ctx(agent: str, session_id: str, run_id: str, origin: str = "unknown") -> ToolContext:
    prof = C.AGENT_PROFILES[agent]
    return ToolContext(agent=agent, agent_trust=prof["trust"], agent_priv=prof["priv"],
                       session_id=session_id, run_id=run_id, origin_endpoint=origin,
                       allowed_tools=tuple(prof["tools"]))


def _benign_record(domain: str, run_id: str, s: int, i: int) -> dict:
    return {"record_id": f"ben-{C.stable_int(run_id, s, i) % 10**10:010d}", "domain": domain,
            "kind": "benign", "hide_location": "log_message", "shard": None,
            "text": f"[{domain}] interim operational entry s{s}-{i}: nominal."}


def run_trace(spec: dict, gateway, mock: C.MockParams, store: SqliteStore | None = None) -> dict:
    store = store or SqliteStore(); store.reset()
    backend = MockBackend()
    router = ToolRouter(store, backend, gateway=gateway)
    brain = MockLLM(mock)
    rng = random.Random(C.stable_int(spec["run_id"], mock.seed))
    domain = spec["domain"]; dom = C.DOMAINS[domain]

    writer = "sa-agent-ingest" if spec["g"] == 1 else "sa-agent-ops"
    caller = "sa-agent-ops"

    # S1 inject (수집 경로: 외부 유입원)
    ctx_w = _ctx(writer, "sess-1", spec["run_id"], origin="/ingest/source")
    brain.decide_ingest(spec["ingest_records"])
    for rec in spec["ingest_records"]:
        router.write_record(rec, ctx_w)

    # S2..S(1+d) 경유: 정상 레코드 추가 쓰기 (D2)
    for s in range(spec["d"]):
        ctx_s = _ctx(writer, f"sess-benign-{s}", spec["run_id"], origin="/ops/routine")
        for i in range(rng.randint(1, 3)):
            router.write_record(_benign_record(domain, spec["run_id"], s, i), ctx_s)

    # trigger
    ctx_c = _ctx(caller, "sess-trigger", spec["run_id"], origin="n/a")
    read_res = router.read_records(domain, ctx_c)
    records = read_res["records"]; read_detect = read_res.get("detect")

    decision = brain.decide_ops(records, store.read_truth, rng)["decision"]
    did_priv, sink_allowed, sink_detect = False, None, None
    if decision["action"] == "privileged_call":
        did_priv = True
        influencing = [r for r in records
                       if (store.read_truth(r["record_id"]) or {}).get("shard")]  # 시뮬레이터 측 인과(정답)
        res = router.call_backend_api(dom["privileged_endpoint"],
                                      {"target": "attacker_controlled", "domain": domain},
                                      ctx_c, influencing_records=influencing)
        sink_allowed = (res.get("status") == "ok")
        sink_detect = router.events[-1].get("detect")

    attempted = bool(spec["is_attack"] and did_priv)
    success = bool(attempted and sink_allowed)
    return {"run_id": spec["run_id"], "domain": domain, "is_attack": spec["is_attack"],
            "k": spec["k"], "d": spec["d"], "g": spec["g"],
            "hide_location": spec["hide_location"], "rep": spec["rep"],
            "assembled_imperativeness": spec["assembled_imperativeness"],
            "did_privileged": did_priv, "attempted": attempted, "attack_success": success,
            "sink_allowed": sink_allowed, "read_detect": read_detect, "sink_detect": sink_detect,
            "writer": writer, "caller": caller, "n_records_at_trigger": len(records)}
