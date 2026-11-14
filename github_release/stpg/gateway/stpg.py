"""
STPG: Spatio-Temporal Provenance Guard (MCP 게이트웨이 삽입형).
  PPT (on_write): 출처 사이드카 생성 — 작성자/세션/유입원/시각만 사용(정답 메타 접근 없음)
  TSA (on_read) : 출처로 계보 군집화 → Scorer 로 조립 창발 점수 → (옵션) 격리
  PDG (on_sink) : 싱크 직전 (호출자 권한 − 작성자 권한) 격차 + 비신뢰 출처 → 차단
탐지기는 레코드 본문(text) 과 출처(provenance) 만 본다. 그라운드트루스는 Scorer 내부에만 있다.
"""
from __future__ import annotations
import time
from stpg import config as C
from stpg.storage.base import Provenance
from stpg.gateway.scoring import Scorer


class STPGGateway:
    def __init__(self, scorer: Scorer, tsa_threshold: float, pdg_min_delta: int,
                 enable_ppt=True, enable_tsa=True, enable_pdg=True, quarantine=False,
                 gate_mode="attributed", grouping="lineage", inherit_read_trust=False, second_scorer=None):
        self.scorer = scorer
        # second_scorer (rev13, R2-1 round 2): witness of a second model family; a trusted lineage authorizes only if both
        # witnesses give a verified target verdict (gate.apply_gate witness2).
        self.second_scorer = second_scorer
        self.tsa_threshold = tsa_threshold
        self.pdg_min_delta = pdg_min_delta
        self.enable_ppt, self.enable_tsa, self.enable_pdg = enable_ppt, enable_tsa, enable_pdg
        self.quarantine = quarantine
        # gate_mode: 'attributed'(STPG, TSA 플래그 계보에 귀속) | 'any-untrusted'(보수적)
        self.gate_mode = gate_mode
        # grouping (v3.4 ablation): 'lineage' (STPG) | 'record' | 'session' — 군집 단위만 바뀌고 커널은 동일
        self.grouping = grouping
        # inherit_read_trust (v3.4, trusted-rewrite laundering mitigation): 신뢰 에이전트의 쓰기가 같은 세션에서 읽은
        # 레코드 집합에서 파생되었음을 게이트웨이가 알면(ctx.read_min_trust), 쓰기의 출처 신뢰를 읽기 집합의 최솟값으로 낮춘다
        self.inherit_read_trust = inherit_read_trust
        self.timing = {"read_ms": [], "sink_ms": []}
        self._witness_cache = {}; self._witness_raw = {}; self._raws_this_call = []; self._witness2_cache = {}

    # --- PPT -----------------------------------------------------------------
    def on_write(self, record: dict, ctx) -> Provenance | None:
        if not self.enable_ppt:
            return None
        source_trust = C.TRUST_EXTERNAL if ctx.origin_endpoint.startswith("/ingest") else ctx.agent_trust
        # 계보 키(PPT=Persistent Provenance Tagging):
        #   유입 소스 식별자(origin_ref)가 있으면 '소스 지속' 계보로 묶는다.
        #   => 같은 외부 소스에서 비롯된 파편은 세션 경계를 넘어도 하나의 계보로 재조립된다
        #      (시공간적 '시간적' 상실의 복원 — 윈도우/세션 범위 탐지기가 못 하는 지점).
        #   origin_ref 가 없으면(정상 내부 기록) 작성자·유입원·세션 범위로 고립시킨다(과대군집 방지).
        origin_ref = getattr(ctx, "origin_ref", None)
        # 계보 키: 인증된 소스 식별자가 있으면 소스 계보(세션·저장소 경계를 넘어 유지), 없으면 쓰기 단위 계보.
        lineage = (f"src:{origin_ref}" if origin_ref else f"write:{record['record_id']}")
        rmt = getattr(ctx, "read_min_trust", None)
        if self.inherit_read_trust and rmt is not None:
            source_trust = min(source_trust, int(rmt))
        return Provenance(record_id=record["record_id"], source_trust=source_trust,
                          writer_agent=ctx.agent, writer_trust=ctx.agent_trust,
                          written_at=time.time(), session_id=ctx.session_id,
                          origin_endpoint=ctx.origin_endpoint, group_id=lineage)

    # --- TSA -----------------------------------------------------------------
    def on_read(self, records: list, ctx, store) -> tuple[list, dict | None]:
        """계보별 조립 지시 점수 E(G) (탐지 신호·감사용). 결정은 싱크의 목적지 조건부 witness 가 내린다."""
        from stpg.gateway import gate as G
        t0 = time.perf_counter()
        groups = G.group_by_lineage(records, store, self.grouping)
        best = {"emergent": 0.0, "group_id": None, "flagged": False, "flag_trust": None, "quarantined": 0,
                "group_scores": {}, "flagged_gids": [], "n_groups": len(groups)}
        if not self.enable_tsa:
            return records, best
        for gid, recs in groups.items():
            emergent = float(self.scorer.assembled(recs))
            best["group_scores"][gid] = round(emergent, 3)
            if emergent >= self.tsa_threshold:
                best["flagged_gids"].append(gid)
            if emergent > best["emergent"]:
                gtrust = min((rr["_provenance"]["source_trust"] for rr in recs), default=C.TRUST_SYSTEM)
                best.update(emergent=round(emergent, 3), group_id=gid,
                            flagged=emergent >= self.tsa_threshold, flag_trust=gtrust)
        if self.quarantine and best["flagged_gids"]:
            fl = set(best["flagged_gids"])
            kept = [r for r in records if r.get("_provenance", {}).get("group_id") not in fl]
            best["quarantined"] = len(records) - len(kept)
            records = kept
        best["read_min_trust"] = min((r["_provenance"]["source_trust"] for r in records), default=C.TRUST_SYSTEM)
        self.timing["read_ms"].append((time.perf_counter() - t0) * 1000.0)
        return records, best

    # --- PDG: 공통 커널 + 조건별 어댑터 (gate_mode) ---------------------------------
    #   attributed            : witness 판정, 신뢰 승인 / 비신뢰 차단 / 증거 없음 -> BLOCK   (STPG)
    #   attributed-allow      : 같은 증거, 증거 없음 -> PASS
    #   trusted-only          : witness 판정, 비신뢰 분기 생략, 증거 없음 -> BLOCK          (trusted-directive-only ablation)
    #   trusted-only-allow    : 비신뢰 분기 생략, 증거 없음 -> PASS
    #   match                 : witness 없음, 신뢰 계보의 결합(언급)으로 승인, 증거 없음 -> BLOCK
    #   any-untrusted         : 보수 게이트
    def on_sink(self, endpoint, args, ctx, influencing_records, store, flag=None):
        if not self.enable_pdg:
            return True, "", None
        from stpg.gateway import gate as G
        t0 = time.perf_counter()
        dest = (args or {}).get("destination", "")
        groups = G.group_by_lineage(influencing_records, store, self.grouping)
        mode = self.gate_mode
        if mode == "any-untrusted":
            out = G.apply_gate(dest, groups, ctx, conservative=True)
            self.timing["sink_ms"].append((time.perf_counter() - t0) * 1000.0); return out
        if mode == "match":
            out = G.apply_gate(dest, groups, ctx, witness=None, authorize_mention=True, empty_policy="block")
            self.timing["sink_ms"].append((time.perf_counter() - t0) * 1000.0); return out
        from stpg.gateway.scoring import WITNESS_VERSION
        self._raws_this_call = []
        def witness(recs, d):
            key = (WITNESS_VERSION, tuple(sorted(r["record_id"] for r in recs)), d)   # prompt 버전으로 네임스페이스
            if key not in self._witness_cache:
                self._witness_cache[key] = (self.scorer.targets(recs, d) if self.enable_tsa
                                            else (False, {r["record_id"]: "none" for r in recs}, []))
                try:
                    self._witness_raw[key] = self.scorer._casc.second.last_raw
                except Exception:
                    self._witness_raw[key] = ""
            self._raws_this_call.append(self._witness_raw.get(key, ""))
            return self._witness_cache[key]
        witness2 = None
        if self.second_scorer is not None:
            def witness2(recs, d):
                key = (WITNESS_VERSION, tuple(sorted(r["record_id"] for r in recs)), d)
                if key not in self._witness2_cache:
                    self._witness2_cache[key] = self.second_scorer.targets(recs, d)
                return self._witness2_cache[key]
        ok, reason, detect = G.apply_gate(dest, groups, ctx, witness=witness,
                                          empty_policy=("allow" if mode.endswith("-allow") else "block"),
                                          untrusted_branch=(not mode.startswith("trusted-only")), witness2=witness2)
        if detect is not None:
            detect["witness_raw"] = " || ".join(self._raws_this_call)
        self.timing["sink_ms"].append((time.perf_counter() - t0) * 1000.0)
        return ok, reason, detect
