"""
저장소 어댑터 공통 인터페이스.

핵심 설계: write_record 는 '데이터 본문'과 '출처 사이드카(provenance)'를 분리 저장한다.
- 본문 컬렉션(records): 에이전트가 실제로 읽는 내용. 이것만 읽으면 출처가 상실된다(=취약점).
- 사이드카 컬렉션(provenance): 게이트웨이(PPT)가 기록. 읽기 시 재부착할 수 있다(=방어).
S0 는 SQLite, S1+ 는 Firestore 로 같은 인터페이스를 구현한다.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Optional
import time


@dataclass
class Provenance:
    """레코드 1건의 출처 메타데이터 (PPT 가 쓰기 시점에 부착)."""
    record_id: str
    source_trust: int        # 유입 데이터의 신뢰 등급 (config.TRUST_*)
    writer_agent: str        # 작성 에이전트 (서비스 계정)
    writer_trust: int        # 작성 에이전트의 신뢰 등급
    written_at: float        # epoch seconds
    session_id: str
    origin_endpoint: str     # 유입 API/소스
    group_id: Optional[str] = None   # 같은 계보(파편 그룹) 식별자 — 조립 탐지의 근거


class StorageAdapter(ABC):
    """에이전트↔저장소 사이 모든 접근은 이 인터페이스를 통한다."""

    @abstractmethod
    def write_record(self, record: dict, provenance: Optional[Provenance]) -> None: ...

    @abstractmethod
    def read_records(self, domain: str) -> list[dict]:
        """본문만 반환 (출처 없음). 에이전트 B 가 호출하는 기본 경로."""

    @abstractmethod
    def read_provenance(self, record_id: str) -> Optional[Provenance]:
        """게이트웨이가 출처를 조회 (PPT 재부착용)."""

    @abstractmethod
    def read_truth(self, record_id: str) -> Optional[dict]:
        """[오라클 전용] 그라운드트루스(파편 메타). Scorer/MockLLM 만 사용. 탐지기 접근 금지."""

    @abstractmethod
    def reset(self) -> None:
        """실행 간 격리: 컬렉션 비우기."""
