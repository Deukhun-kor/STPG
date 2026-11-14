"""
모의 백엔드 특권 API (S0).
실제 부작용 없이 '호출 기록'만 남긴다. 권한 상승의 '싱크(sink)'에 해당한다.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import time


@dataclass
class BackendCall:
    endpoint: str
    args: dict
    caller_agent: str
    at: float
    allowed: bool          # 게이트웨이(PDG)가 허용했는지
    blocked_reason: str = ""


class MockBackend:
    """특권 엔드포인트 3종. 호출 로그만 축적한다."""
    PRIVILEGED = {"/device/control", "/billing/settle", "/iam/grant"}

    def __init__(self):
        self.calls: list[BackendCall] = []

    def invoke(self, endpoint: str, args: dict, caller_agent: str,
               allowed: bool, blocked_reason: str = "") -> dict:
        call = BackendCall(endpoint, dict(args), caller_agent, time.time(),
                           allowed, blocked_reason)
        self.calls.append(call)
        if not allowed:
            return {"status": "blocked", "reason": blocked_reason, "endpoint": endpoint}
        return {"status": "ok", "endpoint": endpoint, "effect": "recorded"}

    def privileged_calls(self) -> list[BackendCall]:
        return [c for c in self.calls if c.endpoint in self.PRIVILEGED]

    def reset(self) -> None:
        self.calls.clear()
