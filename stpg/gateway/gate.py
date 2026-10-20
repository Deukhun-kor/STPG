"""
공통 결정 커널(PDG 정책 v3.3)과 PPT 출처 생성 — 모든 조건이 같은 커널을 쓰고, 조건별 '증거 어댑터' 만 다르다.

커널(실제 호출 목적지 δ 에 대한 목적지 수준 승인):
  (0) 내부 승인 목적지                                  -> PASS (정책 범위 밖)
  (0') δ 가 문맥에서 다른 값으로 해소되는 참조 토큰(라벨/키) -> BLOCK (non-endpoint: 라우팅 인자가 최종 엔드포인트가 아님)
  (1) δ 를 '대상'으로 지시하는 신뢰 계보(해소 체인도 신뢰, 모호하지 않음) 존재 -> PASS  (승인 증거)
  (2) δ 를 '대상'으로 지시하는 비신뢰 계보(또는 비신뢰/모호 체인) 존재          -> BLOCK (공격 증거; 감사용 귀속)
  (3) 둘 다 없음                                        -> empty default (BLOCK 기본 / PASS 변형)
'대상으로 지시'는 목적지 조건부 witness 판정(targets)으로 결정하되(v3.3), witness 가 지목한 지지 레코드 중 적어도 하나가
'target' 역할이고 δ 또는 허용 체인 토큰(2홉 이내)을 실제로 언급해야만 판정을 인정한다(지원 경로 검증). 언급·예시·금지·과거 기록은
대상이 아니며, 해소되지 않은 경로·허용 체인 밖의 레코드·mapping 전용 레코드는 승인 근거가 될 수 없다.
어댑터(조건별로 무엇을 증거로 내놓는가):
  - STPG                 : 결합 계보 각각에 witness 판정; (1)(2)(3) 모두 사용
  - trusted-directive-only: (2) 생략 — 신뢰 승인 없으면 모두 default 로
  - trusted-rule matching: witness 없음 — 신뢰 계보가 δ 를 결합(언급)하면 승인
  - PPT+PDG-only(보수)   : 결합 무관 — 문맥에 비신뢰 레코드가 있으면 BLOCK
  - attribution judge    : LLM 이 지지 레코드·승인 여부를 반환 -> 같은 신뢰 규칙
  - ephemeral taint      : 사이드카·해소·판정 모두 없음 -> 게이트 입력 없음 -> PASS
누락 provenance 는 EXTERNAL 로, 모호한 참조는 비신뢰 체인으로 취급한다. Δπ 는 증거 계보와 체인 레코드의 작성자 권한으로 계산한다.
"""
from __future__ import annotations
import time
from stpg import config as C
from stpg.storage.base import Provenance
from stpg.gateway import binding as B

KERNEL_VERSION = "v3.3"
STATS = {"witness_calls": 0, "witness_evals": 0, "witness_evals_trusted": 0, "witness_evals_untrusted": 0,
         "witness_unsupported": 0, "non_endpoint": 0}
_ROLE_RANK = {"prohibited": 4, "mention": 3, "mapping": 2, "none": 1}
_TARGET_ROLES = {"target", "instruction", "directive", "rule"}   # witness 역할 표기의 동의어 허용


def _summarize_roles(roles: dict) -> str:
    best = "none"
    for r in roles.values():
        if _ROLE_RANK.get(r, 0) > _ROLE_RANK.get(best, 0):
            best = r
    return best


def make_provenance(record: dict, ctx) -> Provenance:
    source_trust = C.TRUST_EXTERNAL if ctx.origin_endpoint.startswith("/ingest") else ctx.agent_trust
    origin_ref = getattr(ctx, "origin_ref", None)
    # 계보 키: 인증된 소스 식별자가 있으면 소스 계보(세션·저장소 경계를 넘어 유지), 없으면 쓰기 단위 계보.
    lineage = (f"src:{origin_ref}" if origin_ref else f"write:{record['record_id']}")
    return Provenance(record_id=record["record_id"], source_trust=source_trust,
                      writer_agent=ctx.agent, writer_trust=ctx.agent_trust,
                      written_at=time.time(), session_id=ctx.session_id,
                      origin_endpoint=ctx.origin_endpoint, group_id=lineage)


def _is_internal(dest: str):
    d = str(dest or "").strip().rstrip(".,;:")
    if not d:
        return d, None
    return d, (d in C.APPROVED_INTERNAL_DESTINATIONS)


def group_by_lineage(records: list, store) -> dict:
    groups: dict[str, list] = {}
    for r in records:
        p = store.read_provenance(r["record_id"])
        if p is None:
            r["_provenance"] = {"source_trust": C.TRUST_EXTERNAL, "writer_agent": "unknown",
                                "writer_priv": C.PRIV_READ, "group_id": f"unknown:{r['record_id']}"}
        else:
            r["_provenance"] = {"source_trust": p.source_trust, "writer_agent": p.writer_agent,
                                "writer_priv": C.AGENT_PROFILES.get(p.writer_agent, {}).get("priv", C.PRIV_READ),
                                "group_id": p.group_id}
        groups.setdefault(r["_provenance"]["group_id"], []).append(r)
    return groups


def _trust_of(recs: list) -> tuple[int, int]:
    t = min((r["_provenance"]["source_trust"] for r in recs), default=C.TRUST_SYSTEM)
    w = min((r["_provenance"]["writer_priv"] for r in recs), default=C.PRIV_IAM)
    return t, w


def apply_gate(dest, groups: dict, ctx, witness=None, empty_policy: str = "block",
               conservative: bool = False, authorize_mention: bool = False, untrusted_branch: bool = True):
    """
    공통 커널. groups: gid -> records(_provenance 부착).
    witness(records, dest) -> (targets: bool, roles: {record_id: role}, support: [record_id]) :
        목적지 조건부 지시 판정(어댑터가 제공; None 이면 판정 없음). 커널이 지원 경로를 검증한다.
    반환 (allowed, reason, detect). detect["evidence"] 는 결정 분기 이름(감사·집계용).
    """
    d, dest_internal = _is_internal(dest)
    detect = {"destination": d or None, "dest_internal": dest_internal, "external_route": (dest_internal is False),
              "evidence": None, "bound_gids": [], "min_source_trust": None, "delta": None, "witness": {},
              "ambiguous": False}
    if dest_internal is True:
        detect["evidence"] = "internal"
        return True, "", detect
    if not d:                                                   # 호출 인자 없음: 게이트 입력이 아님(사전 검증 경로)
        detect["evidence"] = "no-call"
        return True, "", detect
    allrecs = [r for recs in groups.values() for r in recs]
    if B.is_reference_token(d, allrecs):                          # (0') 라우팅 인자가 라벨/키: 최종 엔드포인트 아님
        STATS["non_endpoint"] += 1
        detect.update(evidence="non-endpoint-destination", delta=None)
        return False, "destination is a reference token, not an endpoint", detect
    if conservative:
        unt = [r for r in allrecs if r["_provenance"]["source_trust"] <= C.TRUST_AGENT_INGEST]
        t, w = _trust_of(unt) if unt else (C.TRUST_SYSTEM, ctx.agent_priv)
        detect.update(evidence="conservative-untrusted" if unt else "conservative-clean",
                      min_source_trust=t, delta=(ctx.agent_priv - w) if unt else None)
        return (not unt), ("untrusted influence present" if unt else ""), detect
    chain = B.resolve_chain(d, allrecs)
    adm = B.admissible_tokens(d, chain)
    detect["roles"] = {}
    trusted, untrusted = [], []
    for gid, recs in groups.items():
        bound, used, amb = B.bind(recs, d, chain)
        if not bound:
            continue
        detect["bound_gids"].append(gid)
        t, w = _trust_of(recs + used)
        if amb:
            t = min(t, C.TRUST_EXTERNAL); detect["ambiguous"] = True
        if witness is not None:
            STATS["witness_calls"] += 1; STATS["witness_evals"] += 1
            STATS["witness_evals_trusted" if t >= C.TRUST_AGENT_OPS else "witness_evals_untrusted"] += 1
            tg, roles, support = witness(recs + used, d)
            # 지원 경로 검증: 'target' 역할 레코드가 (i) 해소 관계문이 아닌 지시 레코드이고 (ii) δ 또는 허용 체인 토큰을
            # 실제로 언급해야 한다. witness 가 support 를 비워 보내면 역할이 target 인 레코드 전체를 후보로 본다.
            byid = {r["record_id"]: r for r in recs + used}
            # 후보: witness 가 지목한 support, 없으면 target 역할 레코드, 그것도 없으면 전체(역할 표기 불일치 대비).
            # 의미 판정(targets)은 witness 가, 경로 검증(매핑문 아님 + δ/허용 체인 토큰 언급)은 커널이 맡는다.
            sup = [rid for rid in support if rid in byid]
            cands = sup or [rid for rid in byid if roles.get(rid) in _TARGET_ROLES] or list(byid)
            verified = bool(tg) and any(
                not B.is_mapping_record(byid[rid].get("text", ""))
                and B.mentions_any(byid[rid].get("text", ""), adm)
                for rid in cands)
            if tg and not verified:
                STATS["witness_unsupported"] += 1
            detect["witness"][gid] = "target" if verified else ("unsupported" if tg else _summarize_roles(roles))
            detect["roles"][gid] = {rid: roles.get(rid, "none") for rid in byid}
            tg = verified
        else:
            tg = authorize_mention                               # matching: 결합(언급) 자체를 지시로 간주
        if not tg:
            continue
        if t >= C.TRUST_AGENT_OPS:
            trusted.append((gid, t, w))
        elif t <= C.TRUST_AGENT_INGEST:
            untrusted.append((gid, t, w))
    if trusted:
        t = min(a[1] for a in trusted); w = min(a[2] for a in trusted)
        detect.update(evidence="trusted-authorized", min_source_trust=t, delta=ctx.agent_priv - w)
        return True, "", detect
    if untrusted and untrusted_branch:
        t = min(a[1] for a in untrusted); w = min(a[2] for a in untrusted)
        detect.update(evidence="ambiguous-reference" if detect["ambiguous"] else "untrusted-directive",
                      min_source_trust=t, delta=ctx.agent_priv - w)
        return False, "destination targeted by an untrusted directive lineage", detect
    detect.update(evidence="no-evidence", delta=None)
    if empty_policy == "allow":
        return True, "", detect
    return False, "no trusted directive targets this destination", detect
