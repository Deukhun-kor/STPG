"""
MCP 도구 계층 (S0 인프로세스 구현).

모든 도구 호출은 STPG 게이트웨이를 경유한다:
    agent --> ToolRouter.call(tool, args, ctx) --> gateway.on_<phase>() --> 실제 동작
게이트웨이가 None 이면(무방어 베이스라인) 그대로 통과한다.

도구:
  - write_record(record)            : 저장소 쓰기 (PPT 가 출처 부착)
  - read_records(domain)            : 저장소 읽기 (PPT 재부착 / TSA 조립 점수)
  - call_backend_api(endpoint,args) : 특권 호출 (PDG 권한 격차 검증)
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Callable

from stpg.storage.base import StorageAdapter
from stpg.mcp.backend import MockBackend


@dataclass
class ToolContext:
    """호출 맥락: 어느 에이전트가 어느 세션에서 호출했는가."""
    agent: str
    agent_trust: int
    agent_priv: int
    session_id: str
    run_id: str
    origin_endpoint: str = "unknown"
    allowed_tools: tuple = ()      # IAM 허용목록(서비스 계정 역할에 대응)


class ToolRouter:
    def __init__(self, store: StorageAdapter, backend: MockBackend, gateway=None):
        self.store = store
        self.backend = backend
        self.gateway = gateway           # STPGGateway | None
        self.events: list[dict] = []     # 트레이스(관측) 적재 — BigQuery/Pub/Sub 대응

    def _emit(self, ev: dict) -> None:
        self.events.append(ev)

    def _iam_check(self, tool: str, ctx: ToolContext) -> bool:
        return tool in ctx.allowed_tools

    @staticmethod
    def _sanitize(record: dict) -> dict:
        """탐지기에 전달할 사본: 그라운드트루스(shard/kind) 제거."""
        return {k: v for k, v in record.items() if k not in ("shard", "kind")}

    # --- tools ---------------------------------------------------------------
    def write_record(self, record: dict, ctx: ToolContext) -> dict:
        if not self._iam_check("write_record", ctx):
            self._emit({"phase": "write", "agent": ctx.agent, "denied": "iam", "run_id": ctx.run_id})
            return {"status": "denied", "reason": "iam"}
        prov = None
        if self.gateway is not None:
            prov = self.gateway.on_write(self._sanitize(record), ctx)   # PPT
        self.store.write_record(record, prov)
        self._emit({"phase": "write", "agent": ctx.agent, "session": ctx.session_id,
                    "record_id": record["record_id"], "run_id": ctx.run_id})
        return {"status": "ok", "record_id": record["record_id"]}

    def read_records(self, domain: str, ctx: ToolContext) -> dict:
        if not self._iam_check("read_records", ctx):
            return {"status": "denied", "reason": "iam", "records": [], "detect": None}
        records = self.store.read_records(domain)       # 본문만(출처·정답 없음)
        detect = None
        if self.gateway is not None:
            records, detect = self.gateway.on_read(records, ctx, self.store)
        self._emit({"phase": "read", "agent": ctx.agent, "session": ctx.session_id,
                    "n_records": len(records), "run_id": ctx.run_id,
                    "detect": detect})
        return {"status": "ok", "records": records, "detect": detect}

    def call_backend_api(self, endpoint: str, args: dict, ctx: ToolContext,
                         influencing_records: Optional[list] = None) -> dict:
        if not self._iam_check("call_backend_api", ctx):
            res = self.backend.invoke(endpoint, args, ctx.agent, False, "iam-denied")
            self._emit({"phase": "sink", "agent": ctx.agent, "session": ctx.session_id,
                        "endpoint": endpoint, "allowed": False, "denied": "iam",
                        "run_id": ctx.run_id, "detect": None})
            return res
        allowed, reason = True, ""
        detect = None
        if self.gateway is not None:
            # PDG: 싱크 직전 권한 격차 검증
            allowed, reason, detect = self.gateway.on_sink(
                endpoint, args, ctx, influencing_records or [], self.store)
        res = self.backend.invoke(endpoint, args, ctx.agent, allowed, reason)
        self._emit({"phase": "sink", "agent": ctx.agent, "session": ctx.session_id,
                    "endpoint": endpoint, "allowed": allowed, "run_id": ctx.run_id,
                    "detect": detect})
        return res
