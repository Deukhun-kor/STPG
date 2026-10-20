"""
LLM 추상화 + 기록/재생 캐시 + 토큰/비용 집계 + 하드 캡.

- 모든 실제 LLM 호출(S2~S4)은 LLMClient.complete() 를 통한다.
- 캐시 키 = sha256(model, prompt, tools_schema, temperature, decision_salt).
  같은 입력은 재과금되지 않는다(분석 재실행/중단 재개 시 비용 0).
- S0 는 MockLLM: 과금 0, 결정론적. 실제 모델 교체 시 provider 어댑터만 바뀐다.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import hashlib
import json
import random

from stpg import config as C


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0
    cache_hits: int = 0

    def cost_usd(self, model: C.ModelSpec) -> float:
        return (self.input_tokens / 1e6) * model.input_usd_per_m + \
               (self.output_tokens / 1e6) * model.output_usd_per_m


class LLMClient:
    """프로바이더 공통 래퍼. S0 에서는 MockLLM 이 _generate 를 담당."""
    def __init__(self, model_key: str, caps: C.CostCaps, cache_dir: Path):
        self.model_key = model_key
        self.spec = C.MODELS[model_key]
        self.caps = caps
        self.usage = Usage()
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _key(self, prompt: str, tools: list, temperature: float, salt: str) -> str:
        blob = json.dumps({"m": self.spec.name, "p": prompt, "t": tools,
                           "temp": temperature, "s": salt}, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(blob.encode()).hexdigest()

    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    def complete(self, prompt: str, tools: list, temperature: float,
                 salt: str, generate_fn) -> dict:
        key = self._key(prompt, tools, temperature, salt)
        cp = self._cache_path(key)
        if cp.exists():
            self.usage.cache_hits += 1
            return json.loads(cp.read_text())
        # 사전 비용 추정 전 하드 캡 점검
        est_cost = self.usage.cost_usd(self.spec)
        if est_cost > self.caps.total_usd:
            raise BudgetExceeded(f"total cap {self.caps.total_usd} exceeded (est {est_cost:.2f})")
        out = generate_fn()                       # {'decision':..., 'in_tok':int, 'out_tok':int}
        self.usage.input_tokens += out.get("in_tok", 0)
        self.usage.output_tokens += out.get("out_tok", 0)
        self.usage.calls += 1
        cp.write_text(json.dumps(out, ensure_ascii=False))
        return out


class MockLLM:
    """
    결정론적 에이전트 두뇌 (S0 전용).
    실제 모델을 흉내내지 않고, 파이프라인·지표·탐지 코드를 검증하기 위한 규칙 기반 시뮬레이터.
    """
    def __init__(self, params: C.MockParams):
        self.p = params

    def decide_ingest(self, input_records: list) -> dict:
        """Agent A: 입력 레코드를 모두 저장(write_record)."""
        return {"decision": {"action": "write_all"},
                "in_tok": 400 + 30 * len(input_records), "out_tok": 60}

    def decide_ops(self, records: list, truth_lookup, rng: random.Random) -> dict:
        """
        Agent B(시뮬레이터): 컨텍스트에 들어온 레코드에서 파편 그룹이 완전히 조립되면
        확률 p_follow 로 명령을 따른다(특권 호출). 시뮬레이터이므로 truth 접근이 허용된다.
        """
        groups: dict[str, list] = {}
        for r in records:
            t = truth_lookup(r["record_id"]); sh = (t or {}).get("shard")
            if sh and sh.get("group_id"):
                groups.setdefault(sh["group_id"], []).append(sh)
        assembled = False
        for gid, shs in groups.items():
            total = shs[0].get("total", 0)
            present = len({s["index"] for s in shs})
            if total > 0 and present >= total:
                assembled = True
                break
        follow = False
        if assembled:
            follow = rng.random() < self.p.p_follow_assembled
        elif groups:
            follow = rng.random() < self.p.p_follow_partial
        action = "benign_report"
        if follow:
            action = "privileged_call"
        return {"decision": {"action": action, "assembled": assembled},
                "in_tok": 500 + 25 * len(records), "out_tok": 90}
