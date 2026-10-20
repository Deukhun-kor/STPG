"""SQLite 구현 (S0). 본문(records) / 출처(provenance) / 그라운드트루스(truth) 를 분리 저장.
- read_records  : 본문만 (에이전트·탐지기가 보는 것) — 출처·정답 없음
- read_provenance: 게이트웨이(PPT) 전용
- read_truth    : 오라클(Scorer/MockLLM) 전용 — 탐지기는 절대 호출하지 않음
"""
from __future__ import annotations
from typing import Optional
import sqlite3, json, threading
from stpg.storage.base import StorageAdapter, Provenance


class SqliteStore(StorageAdapter):
    def __init__(self, path: str = ":memory:"):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock, self._conn:
            self._conn.execute("""CREATE TABLE IF NOT EXISTS records(
                record_id TEXT PRIMARY KEY, domain TEXT, text TEXT,
                hide_location TEXT, seq INTEGER)""")
            self._conn.execute("""CREATE TABLE IF NOT EXISTS provenance(
                record_id TEXT PRIMARY KEY, source_trust INT, writer_agent TEXT,
                writer_trust INT, written_at REAL, session_id TEXT,
                origin_endpoint TEXT, group_id TEXT)""")
            self._conn.execute("""CREATE TABLE IF NOT EXISTS truth(
                record_id TEXT PRIMARY KEY, kind TEXT, shard_json TEXT)""")

    def write_record(self, record: dict, provenance: Optional[Provenance]) -> None:
        with self._lock, self._conn:
            seq = self._conn.execute("SELECT COALESCE(MAX(seq),0)+1 FROM records").fetchone()[0]
            self._conn.execute("INSERT OR REPLACE INTO records VALUES(?,?,?,?,?)",
                (record["record_id"], record["domain"], record["text"],
                 record["hide_location"], seq))
            self._conn.execute("INSERT OR REPLACE INTO truth VALUES(?,?,?)",
                (record["record_id"], record.get("kind", "benign"),
                 json.dumps(record.get("shard"))))
            if provenance is not None:
                p = provenance
                self._conn.execute("INSERT OR REPLACE INTO provenance VALUES(?,?,?,?,?,?,?,?)",
                    (p.record_id, p.source_trust, p.writer_agent, p.writer_trust,
                     p.written_at, p.session_id, p.origin_endpoint, p.group_id))

    def read_records(self, domain: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM records WHERE domain=? ORDER BY seq", (domain,)).fetchall()
        return [{"record_id": r["record_id"], "domain": r["domain"], "text": r["text"],
                 "hide_location": r["hide_location"]} for r in rows]

    def read_provenance(self, record_id: str) -> Optional[Provenance]:
        with self._lock:
            r = self._conn.execute("SELECT * FROM provenance WHERE record_id=?",
                                   (record_id,)).fetchone()
        if not r: return None
        return Provenance(r["record_id"], r["source_trust"], r["writer_agent"],
                          r["writer_trust"], r["written_at"], r["session_id"],
                          r["origin_endpoint"], r["group_id"])

    def read_truth(self, record_id: str) -> Optional[dict]:
        with self._lock:
            r = self._conn.execute("SELECT * FROM truth WHERE record_id=?",
                                   (record_id,)).fetchone()
        if not r: return None
        return {"kind": r["kind"], "shard": json.loads(r["shard_json"]) if r["shard_json"] else None}

    def reset(self) -> None:
        with self._lock, self._conn:
            for t in ("records", "provenance", "truth"):
                self._conn.execute(f"DELETE FROM {t}")
