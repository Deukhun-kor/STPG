"""
Action binding: 실제 호출의 목적지 δ 와 계보(lineage) 를 결합한다.
  - 리터럴 결합: δ 문자열이 계보 본문에 그대로 등장
  - 참조 결합: 문맥의 레지스트리형 레코드("`key` = δ", "label X maps to registry key `key`", "resolves to")를
    최대 2홉까지 거슬러 올라가, 계보 본문이 그 key/label 을 언급하면 결합(해소 체인 레코드 반환)
  - 모호성: 같은 토큰이 서로 다른 값으로도 해소되면(동일 key 에 복수 값) 그 토큰을 통한 결합은 '모호(ambiguous)'로 표시
  - 2홉을 넘는 참조·순환은 해소되지 않는다(결합 없음 -> 증거 없음 분기).
결합·해소는 집합 연산이며 순회 순서에 의존하지 않는다.
  - 엔드포인트 사전검사(v3.3): 문맥이 δ 자체를 다른 값으로 해소하면(δ = X, δ maps to ..., δ resolves to ...) δ 는
    라벨/키(참조 토큰)이지 최종 엔드포인트가 아니다 -> 게이트는 PASS 를 고려하지 않는다(non-endpoint).
    데이터셋 문자열을 하드코딩하지 않고 문맥의 해소 관계만으로 판정한다.
  - 허용 지원 토큰(v3.3): δ 와, δ 로 2홉 이내 해소되는 체인 토큰만이 witness 의 지시-목적지 관계를 지지할 수 있다.
"""
from __future__ import annotations
import re

_TOK = r"[`\"']?([A-Za-z0-9_\-\.]+)[`\"']?"
_REL = r"\s*(?:=|maps to registry key|maps to|resolves to(?: recipient)?|is bound to)\s*"
MAX_HOPS = 2


def _norm(t: str) -> str:
    return t.strip().strip("`\"'").rstrip(".,;:")


def _values_of(token: str, records: list) -> set:
    """token 이 해소되는 모든 값(모호성 검사용)."""
    pat = re.compile(r"(?<![A-Za-z0-9_\-])[`\"']?" + re.escape(token) + r"[`\"']?" + _REL + _TOK)
    vals = set()
    for r in records:
        for m in pat.finditer(r.get("text", "")):
            vals.add(_norm(m.group(1)))
    return vals


def resolve_chain(dest: str, records: list) -> dict:
    """
    δ 로 해소되는 토큰(키/라벨) -> {"records": [해소 레코드...], "ambiguous": bool, "hop": n}. 최대 MAX_HOPS 홉.
    """
    dest = _norm(dest or "")
    if not dest:
        return {}
    chain: dict[str, dict] = {}
    frontier = [dest]
    for hop in range(1, MAX_HOPS + 1):
        nxt = []
        for tok in frontier:
            pat = re.compile(_TOK + _REL + r"[`\"']?" + re.escape(tok) + r"[`\"']?(?![A-Za-z0-9_\-])")
            for r in records:
                for m in pat.finditer(r.get("text", "")):
                    key = _norm(m.group(1))
                    if not key or key == dest:
                        continue
                    if key not in chain:
                        others = _values_of(key, records) - {tok}
                        chain[key] = {"records": [r], "ambiguous": bool(others), "hop": hop}
                        nxt.append(key)
                    elif r not in chain[key]["records"]:
                        chain[key]["records"].append(r)
        frontier = nxt
        if not frontier:
            break
    return chain


def _mentions(text: str, token: str) -> bool:
    return re.search(r"(?<![A-Za-z0-9_\-])" + re.escape(token) + r"(?![A-Za-z0-9_\-])", text) is not None


def bind(group_records: list, dest: str, chain: dict) -> tuple[bool, list, bool]:
    """
    계보가 δ 를 결합하는가. 반환 (결합 여부, 사용된 해소 체인 레코드, 모호성).
    리터럴 결합이면 체인 없음; 참조 결합이면 해당 토큰의 해소 레코드(계보 외부) 와 모호성 플래그.
    """
    dest = _norm(dest or "")
    if not dest:
        return False, [], False
    text = " ".join(r.get("text", "") for r in group_records)
    if _mentions(text, dest):
        return True, [], False
    ids = {r["record_id"] for r in group_records}
    used, amb, bound = [], False, False
    for tok, info in chain.items():
        if _mentions(text, tok):
            bound = True
            used.extend(r for r in info["records"] if r["record_id"] not in ids and r not in used)
            amb = amb or info["ambiguous"]
    return bound, used, amb


def is_reference_token(dest: str, records: list) -> bool:
    """δ 가 문맥에서 다른 값으로 해소되는 참조 토큰(라벨/키)인가 — 그러면 최종 엔드포인트가 아니다."""
    dest = _norm(dest or "")
    return bool(dest) and bool(_values_of(dest, records))


def admissible_tokens(dest: str, chain: dict) -> set:
    """witness 의 지지 레코드가 언급해야 하는 토큰 집합: δ 와 2홉 이내 해소 체인의 키/라벨."""
    return {_norm(dest or "")} | set(chain.keys())


def mentions_any(text: str, tokens: set) -> bool:
    return any(tok and _mentions(text, tok) for tok in tokens)


_MAPPING_LINE = re.compile(_TOK + _REL + _TOK)


def is_mapping_record(text: str) -> bool:
    """레코드가 해소 관계문(`X = Y`, `label maps to key`, `resolves to`, `is bound to`)을 포함하는 매핑 레코드인가.
    해소기가 쓰는 것과 같은 패턴이므로 데이터셋 문자열에 의존하지 않는다. 매핑 레코드는 witness 의 지지 '지시' 레코드가 될 수 없다."""
    return _MAPPING_LINE.search(text or "") is not None
