"""
Cloud Run 서비스 3종 (ROLE 환경변수로 선택). 모두 Flask.
  ROLE=backend : 모의 특권 API. 게이트웨이 SA 만 invoker.
  ROLE=mcp     : MCP 도구 서버(Firestore 접근). 게이트웨이 SA 만 invoker.
  ROLE=gateway : STPG 게이트웨이. 에이전트 SA 2개만 invoker. 호출자 ID 토큰에서 SA 이메일을 추출해
                 권한 프로파일에 매핑(=실제 IAM 신원이 ToolContext 가 된다).
S1 에서는 LLM 호출이 없다(에이전트 Job 이 MockLLM 을 사용).
"""
from __future__ import annotations
import os, json, time
from flask import Flask, request, jsonify

ROLE = os.environ.get("ROLE", "backend")
PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
app = Flask(__name__)


def _caller_email() -> str:
    """Cloud Run 이 검증한 ID 토큰에서 호출자 서비스 계정 이메일을 꺼낸다."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return "anonymous"
    try:
        from google.oauth2 import id_token
        from google.auth.transport import requests as greq
        info = id_token.verify_oauth2_token(auth.split(" ", 1)[1], greq.Request())
        return info.get("email", "unknown")
    except Exception as e:  # 검증 실패는 거부
        return f"invalid:{e.__class__.__name__}"


# --------------------------------------------------------------------------- backend
if ROLE == "backend":
    CALLS = []
    @app.post("/<path:endpoint>")
    def backend_call(endpoint):
        body = request.get_json(silent=True) or {}
        CALLS.append({"endpoint": "/" + endpoint, "args": body.get("args"), "caller": body.get("caller"),
                      "run_id": body.get("run_id"), "at": time.time()})
        return jsonify({"status": "ok", "endpoint": "/" + endpoint, "effect": "recorded"})
    @app.get("/calls/<run_id>")
    def backend_calls(run_id):
        return jsonify([c for c in CALLS if c["run_id"] == run_id])

# --------------------------------------------------------------------------- mcp
elif ROLE == "mcp":
    from stpg.storage.firestore_store import FirestoreStore
    from stpg.storage.base import Provenance
    @app.post("/tool/<name>")
    def tool(name):
        body = request.get_json(force=True)
        store = FirestoreStore(PROJECT, body["run_id"])
        if name == "write_record":
            prov = Provenance(**body["provenance"]) if body.get("provenance") else None
            store.write_record(body["record"], prov); return jsonify({"status": "ok"})
        if name == "read_records":
            return jsonify({"status": "ok", "records": store.read_records(body["domain"])})
        if name == "read_provenance":
            p = store.read_provenance(body["record_id"]); return jsonify({"provenance": p.__dict__ if p else None})
        if name == "read_truth":          # 오라클 전용 엔드포인트(S0/S1 Mock 에이전트만 호출)
            return jsonify({"truth": store.read_truth(body["record_id"])})
        if name == "reset":
            store.reset(); return jsonify({"status": "ok"})
        return jsonify({"status": "error", "reason": "unknown tool"}), 404

# --------------------------------------------------------------------------- gateway
elif ROLE == "gateway":
    import requests as rq
    import google.auth.transport.requests, google.oauth2.id_token
    from stpg import config as C
    from stpg.gateway.stpg import STPGGateway
    from stpg.gateway.scoring import OracleScorer
    MCP_URL, BACKEND_URL = os.environ["MCP_URL"], os.environ["BACKEND_URL"]
    # 호출자 SA 이메일 -> 권한 프로파일. SA 이메일은 결정적이므로 프로젝트 ID 로 생성(환경변수 불필요).
    SA_MAP = {f"{name}@{PROJECT}.iam.gserviceaccount.com": name for name in C.AGENT_PROFILES}
    for kv in filter(None, os.environ.get("SA_MAP_EXTRA", "").split(";")):   # 선택적 추가 매핑 "email:profile"
        em, prof = kv.split(":", 1); SA_MAP[em] = prof

    def _idtok(aud):
        return google.oauth2.id_token.fetch_id_token(google.auth.transport.requests.Request(), aud)
    def _mcp(name, body):
        r = rq.post(f"{MCP_URL}/tool/{name}", json=body,
                    headers={"Authorization": f"Bearer {_idtok(MCP_URL)}"}, timeout=30)
        try:
            out = r.json()
        except ValueError:
            raise RuntimeError(f"mcp non-json {r.status_code}: {r.text[:300]}")
        if r.status_code >= 400 or out.get("status") == "error":
            raise RuntimeError(f"mcp {name} failed {r.status_code}: {out}")
        return out

    class RemoteStore:
        """게이트웨이가 쓰는 원격 저장소 뷰(MCP 경유). STPGGateway 는 read_provenance/read_truth 만 호출."""
        def __init__(self, run_id): self.run_id = run_id
        def read_provenance(self, rid):
            from stpg.storage.base import Provenance
            p = _mcp("read_provenance", {"run_id": self.run_id, "record_id": rid})["provenance"]
            return Provenance(**p) if p else None
        def read_truth(self, rid):
            return _mcp("read_truth", {"run_id": self.run_id, "record_id": rid})["truth"]

    class Ctx:
        def __init__(self, agent, session_id, run_id, origin):
            prof = C.AGENT_PROFILES[agent]
            self.agent, self.agent_trust, self.agent_priv = agent, prof["trust"], prof["priv"]
            self.session_id, self.run_id, self.origin_endpoint = session_id, run_id, origin
            self.allowed_tools = tuple(prof["tools"])

    @app.post("/tool/<name>")
    def gw_tool(name):
        body = request.get_json(force=True)
        email = _caller_email()
        agent = SA_MAP.get(email)
        if agent is None:
            return jsonify({"status": "denied", "reason": f"unmapped caller {email}"}), 403
        ctx = Ctx(agent, body.get("session_id", "?"), body["run_id"], body.get("origin", "unknown"))
        if name not in ctx.allowed_tools:
            return jsonify({"status": "denied", "reason": "iam"}), 403
        store = RemoteStore(body["run_id"])
        gw = STPGGateway(OracleScorer(store.read_truth, seed=1), 0.35, 1,
                         quarantine=os.environ.get("TSA_QUARANTINE", "0") == "1") \
             if os.environ.get("DETECTOR", "stpg") == "stpg" else None
        if name == "write_record":
            prov = gw.on_write(body["record"], ctx) if gw else None
            return jsonify(_mcp("write_record", {"run_id": body["run_id"], "record": body["record"],
                                                 "provenance": prov.__dict__ if prov else None}))
        if name == "read_records":
            recs = _mcp("read_records", {"run_id": body["run_id"], "domain": body["domain"]})["records"]
            detect = None
            if gw: recs, detect = gw.on_read(recs, ctx, store)
            return jsonify({"status": "ok", "records": recs, "detect": detect})
        if name == "call_backend_api":
            allowed, reason, detect = (True, "", None)
            if gw: allowed, reason, detect = gw.on_sink(body["endpoint"], body["args"], ctx,
                                                         body.get("influencing_records", []), store)
            if not allowed:
                return jsonify({"status": "blocked", "reason": reason, "detect": detect})
            r = rq.post(f"{BACKEND_URL}{body['endpoint']}", json={"args": body["args"], "caller": agent,
                        "run_id": body["run_id"]}, headers={"Authorization": f"Bearer {_idtok(BACKEND_URL)}"}, timeout=30)
            out = r.json(); out["detect"] = detect; return jsonify(out)
        if name == "reset":
            return jsonify(_mcp("reset", {"run_id": body["run_id"]}))
        return jsonify({"status": "error"}), 404

    @app.post("/oracle/read_truth")
    def oracle_truth():
        """Mock 에이전트(시뮬레이터) 전용. S2+ 에서는 ORACLE_MODE=0 으로 닫힌다."""
        if os.environ.get("ORACLE_MODE", "0") != "1":
            return jsonify({"status": "denied", "reason": "oracle disabled"}), 403
        body = request.get_json(force=True)
        return jsonify({"truth": RemoteStore(body["run_id"]).read_truth(body["record_id"])})


@app.errorhandler(Exception)
def _any_error(e):
    import traceback
    return jsonify({"status": "error", "role": ROLE, "error": f"{type(e).__name__}: {e}",
                    "trace": traceback.format_exc()[-1500:]}), 500


@app.get("/healthz")
def healthz():
    return jsonify({"role": ROLE, "ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
