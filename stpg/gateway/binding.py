"""
Action binding (kernel v3.5): 실제 호출의 목적지 δ 와 계보(lineage) 를 결합한다.
  - 목적지 문법과 정규화(v3.5, R1-5/R2-3, 재검토 M1): 엔드포인트 식별자는 공백이 없는 하나의 토큰이다.
      strip(s) = 양끝 따옴표/백틱 제거, 꼬리 괄호 주석 제거( "(ext)" ), 꼬리 구두점 제거.
      well-formed(s) <=> strip(s) 가 비어 있지 않고 공백·따옴표·괄호류 문자를 포함하지 않는다.
      canon(s) = strip(s) 의 대소문자 접기, 구분자 연속([-_]+) 을 '-' 하나로 통일.
      두 식별자는 canon 이 같을 때만 같은 목적지다. 공백은 식별자 구분자가 아니라 낱말 경계다: "PARTNER EXT 194",
      "partner PARTNER-EXT-424", "partner registered under `key`" 는 식별자가 아니라 구(句)이며, 게이트는 그런 목적지를
      어떤 분기보다 먼저 malformed 로 차단한다(v3.4 는 공백을 구분자로 접어 규칙 본문의 낱말이 식별자에 흡수되었고,
      그 결과 해소되지 않은 참조구("partner registered under `contact_sec`") 가 trusted-authorized 로 통과했다).
      유사 식별자(접두/접미 추가, 자릿수 추가·전치, 다른 세그먼트)는 canon 이 다르므로 결합되지 않는다. 본문 매칭은
      식별자 경계(영숫자가 아닌 문자, 단 -/_ 로 영숫자가 이어지면 같은 식별자의 일부) 를 지키는 구분자 유연 정규식으로 한다.
  - 리터럴 결합: δ(정규형) 가 계보 본문에 등장
  - 참조 결합: 문맥의 레지스트리형 레코드("`key` = δ", "label X maps to registry key `key`", "resolves to")를
    최대 2홉까지 거슬러 올라가, 계보 본문이 그 key/label 을 언급하면 결합.
  - 전체 경로 보존(v3.4, R1-2): 체인의 각 토큰은 부모 토큰을 가리키며, 결합에 쓰인 토큰에서 δ 까지의 '모든 홉' 의
    해소 레코드가 사용 레코드(used) 로 반환된다. 신뢰 최솟값과 모호성은 경로 전체에서 계산된다
    (v3.3 은 계보가 언급한 토큰의 해소 레코드만 반환하여 2홉 체인의 엔드포인트 매핑이 신뢰 계산에서 빠졌다).
  - 모호성: 경로 위 어느 토큰이 서로 다른 값으로도 해소되면 그 결합은 '모호(ambiguous)'.
  - 2홉을 넘는 참조·순환은 해소되지 않는다(결합 없음 -> 증거 없음 분기).
결합·해소는 집합 연산이며 순회 순서에 의존하지 않는다.
  - 엔드포인트 사전검사(v3.3): 문맥이 δ 자체를 다른 값으로 해소하면 δ 는 라벨/키(참조 토큰)이지 최종 엔드포인트가
    아니다 -> 게이트는 PASS 를 고려하지 않는다(non-endpoint).
  - 허용 지원 토큰(v3.3): δ 와, δ 로 2홉 이내 해소되는 체인 토큰만이 witness 의 지시-목적지 관계를 지지할 수 있다.
"""
from __future__ import annotations
import re

_TOK = r"[`\"']?([A-Za-z0-9_\-\.]+)[`\"']?"
_REL_BASE = r"\s*(?:=|maps to registry key|maps to|resolves to(?: recipient)?|is bound to)\s*"
# post-hoc extension of the relation pattern M (rev12, evaluated separately from the frozen run; STPG_RELATION_EXT=1):
# relation phrases observed in the LLM-written mapping records of the frozen set. Tokens must look like identifiers
# (contain a digit, '-' or '_'). Direction: forward phrases give <key> REL <value>; "registered under" phrases give
# <value> REL <key>; symmetric phrases ("is associated with") are read forward unless the token after the relation is
# introduced by a key noun (registry key / key / label / tag) while the first token is not -> then <value> REL <key>.
_TOKX = r"[`\"']?([A-Za-z0-9\.]*[0-9_\-][A-Za-z0-9_\-\.]*)[`\"']?"
_KN = r"(?:registry key|registry entry|key|label|tag|alias)"
_ART = r"(?:(?:the|our|an?)\s+)?"
_NOUN = r"(?:(?:registry key|registry entry|key|label|tag|alias|partner|external endpoint|endpoint|recipient|contact|destination|address|binding for)\s+)?"
_SYM = r"is associated with|is now associated with|is linked to|is bound to|bound to|is mapped to|mapped to|corresponds to|is tied to"
_FWD = r"=|maps to registry key|maps to|resolves to recipient|resolves to|is registered to|is registered as|is listed as|is set to|is for|is registry key|points to|refers to"
_RVO = r"is registered under|is listed under|is filed under|is stored under|registered under"
_REL_X = re.compile(r"(?P<pre>" + _NOUN + r")" + _TOKX.replace("(", "(?P<x>", 1) + r"\s+(?P<rel>" + _SYM + "|" + _FWD + "|" + _RVO + r")\s+"
                    + _ART + r"(?P<yn>" + _NOUN + r")" + _TOKX.replace("(", "(?P<y>", 1), re.I)
import os as _os
RELATION_EXT = bool(_os.environ.get("STPG_RELATION_EXT"))
_REL = _REL_BASE


def _relations_ext(text: str) -> list:
    """확장 패턴의 관계 추출: [(key, value), ...] (정규형)."""
    out = []
    for m in _REL_X.finditer(text or ""):
        x, y, rel = canon(m.group("x")), canon(m.group("y")), m.group("rel").lower()
        pre, yn = (m.group("pre") or "").strip().lower(), (m.group("yn") or "").strip().lower()
        if not x or not y or x == y:
            continue
        if re.fullmatch(_RVO, rel):
            out.append((y, x))                                   # <value> registered under <key>
        elif re.fullmatch(_SYM, rel) and re.match(_KN, yn) and not re.match(_KN, pre):
            out.append((y, x))                                   # "<value> is associated with registry key <key>"
        else:
            out.append((x, y))                                   # <key> REL <value>
    return out


MAX_HOPS = 2
_SEP = r"[-_]+"                                       # v3.5: 공백은 구분자가 아니다(낱말 경계)
_BAD = re.compile(r"[\s`\"'()\[\]{}<>]")             # 식별자에 올 수 없는 문자: 공백, 따옴표, 괄호류


def strip_wrapping(t: str) -> str:
    """양끝 따옴표/백틱, 꼬리 괄호 주석, 꼬리 구두점을 벗긴 문자열(정규화 전)."""
    t = (t or "").strip().strip("`\"'").strip()
    t = re.sub(r"\s*\([^()]*\)\s*$", "", t)          # 꼬리 괄호 주석: "A (ext)" -> "A"
    return t.rstrip(".,;:").strip().strip("`\"'")


def is_malformed(t: str) -> bool:
    """목적지가 엔드포인트 식별자 하나가 아닌가(공백·따옴표·괄호류 포함, 또는 비어 있음). 비어 있는 입력은 호출자가
    먼저 처리한다(no-call); 여기서는 비어 있지 않은 입력에 대해 문법만 본다."""
    t = strip_wrapping(t)
    return (not t) or _BAD.search(t) is not None


def canon(t: str) -> str:
    """목적지 식별자의 정규형(백엔드 엔드포인트 동치 기준): 대소문자 접기, -/_ 연속을 '-' 하나로."""
    t = re.sub(_SEP, "-", strip_wrapping(t).lower())
    return t.strip("-")


def _norm(t: str) -> str:
    return canon(t)


def _tokbody(tok: str) -> str:
    """정규형 토큰의 구분자 유연 본문 정규식(경계 없음)."""
    parts = [re.escape(p) for p in canon(tok).split("-") if p]
    return _SEP.join(parts) if parts else r"(?!x)x"


_LB = r"(?<![A-Za-z0-9])(?<![A-Za-z0-9][-_])"     # 식별자 시작 경계
_RB = r"(?![A-Za-z0-9])(?![-_][A-Za-z0-9])"       # 식별자 끝 경계


def _tokpat(tok: str) -> str:
    """정규형 토큰의 본문 매칭 정규식: 구분자 유연, 대소문자 무시, 식별자 경계 보존."""
    return _LB + _tokbody(tok) + _RB


def _mentions(text: str, token: str) -> bool:
    return re.search(_tokpat(token), text or "", re.I) is not None


def _values_of(token: str, records: list) -> set:
    """token 이 해소되는 모든 값(모호성 검사용)."""
    tb = _tokbody(token); vals = set(); ct = canon(token)
    if RELATION_EXT:
        for r in records:
            for k, v in _relations_ext(r.get("text", "")):
                if k == ct and v != ct:
                    vals.add(v)
        return vals
    pat = re.compile(_LB + r"[`\"']?" + tb + r"[`\"']?" + _REL + _TOK, re.I)
    for r in records:
        for m in pat.finditer(r.get("text", "")):
            vals.add(canon(m.group(1)))
    return vals


def _keys_of(token: str, records: list) -> list:
    """token 으로 해소되는 (key, record) 쌍 — resolve_chain 용."""
    out = []; ct = canon(token)
    if RELATION_EXT:
        for r in records:
            for k, v in _relations_ext(r.get("text", "")):
                if v == ct and k != ct:
                    out.append((k, r))
        return out
    pat = re.compile(_TOK + _REL + r"[`\"']?" + _tokbody(token) + r"[`\"']?" + _RB, re.I)
    for r in records:
        for m in pat.finditer(r.get("text", "")):
            out.append((canon(m.group(1)), r))
    return out


def resolve_chain(dest: str, records: list) -> dict:
    """
    δ 로 해소되는 토큰(키/라벨) -> {"records": [이 홉의 해소 레코드...], "ambiguous": bool, "hop": n,
                                    "parent": 다음 홉 토큰(δ 쪽) 또는 None, "path": [토큰->δ 경로의 모든 레코드],
                                    "path_ambiguous": 경로 위 모호성 OR}. 최대 MAX_HOPS 홉.
    """
    dest = canon(dest or "")
    if not dest:
        return {}
    chain: dict[str, dict] = {}
    frontier = [dest]
    for hop in range(1, MAX_HOPS + 1):
        nxt = []
        for tok in frontier:
            for key, r in _keys_of(tok, records):
                if not key or key == dest:
                    continue
                if key not in chain:
                    others = _values_of(key, records) - {tok}
                    chain[key] = {"records": [r], "ambiguous": bool(others), "hop": hop,
                                  "parent": (None if tok == dest else tok)}
                    nxt.append(key)
                elif r not in chain[key]["records"]:
                    chain[key]["records"].append(r)
        frontier = nxt
        if not frontier:
            break
    # 전체 경로(토큰 -> ... -> δ) 의 레코드와 모호성을 각 토큰에 부착(v3.4)
    for key, info in chain.items():
        path, amb, cur, seen = [], False, key, set()
        while cur is not None and cur in chain and cur not in seen:
            seen.add(cur)
            for r in chain[cur]["records"]:
                if r not in path:
                    path.append(r)
            amb = amb or chain[cur]["ambiguous"]
            cur = chain[cur]["parent"]
        info["path"] = path; info["path_ambiguous"] = amb
    return chain


def bind(group_records: list, dest: str, chain: dict) -> tuple[bool, list, bool]:
    """
    계보가 δ 를 결합하는가. 반환 (결합 여부, 사용된 해소 체인 레코드(전체 경로), 모호성(경로 전체)).
    리터럴 결합이면 체인 없음; 참조 결합이면 언급된 토큰에서 δ 까지 모든 홉의 해소 레코드(계보 외부) 와 모호성 플래그.
    """
    dest = canon(dest or "")
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
            used.extend(r for r in info.get("path", info["records"]) if r["record_id"] not in ids and r not in used)
            amb = amb or info.get("path_ambiguous", info["ambiguous"])
    return bound, used, amb


def is_reference_token(dest: str, records: list) -> bool:
    """δ 가 문맥에서 다른 값으로 해소되는 참조 토큰(라벨/키)인가 — 그러면 최종 엔드포인트가 아니다."""
    dest = canon(dest or "")
    return bool(dest) and bool(_values_of(dest, records) - {dest})


def admissible_tokens(dest: str, chain: dict) -> set:
    """witness 의 지지 레코드가 언급해야 하는 토큰 집합: δ 와 2홉 이내 해소 체인의 키/라벨(정규형)."""
    return {canon(dest or "")} | set(chain.keys())


def mentions_any(text: str, tokens: set) -> bool:
    return any(tok and _mentions(text, tok) for tok in tokens)


_MAPPING_LINE = re.compile(_TOK + _REL + _TOK)


def is_mapping_record(text: str) -> bool:
    """레코드가 해소 관계문(`X = Y`, `label maps to key`, `resolves to`, `is bound to`)을 포함하는 매핑 레코드인가.
    해소기가 쓰는 것과 같은 패턴이므로 데이터셋 문자열에 의존하지 않는다. 매핑 레코드는 witness 의 지지 '지시' 레코드가 될 수 없다."""
    if RELATION_EXT:
        return bool(_relations_ext(text))
    return _MAPPING_LINE.search(text or "") is not None
