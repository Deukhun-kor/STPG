"""Firestore 구현 (S1+). SqliteStore 와 동일 인터페이스. 컬렉션 3개: records / provenance / truth.
실행(run_id) 단위 네임스페이스로 격리한다: <collection>/<run_id>/items/<record_id>"""
from __future__ import annotations
from typing import Optional
import json, time
from stpg.storage.base import StorageAdapter, Provenance


class FirestoreStore(StorageAdapter):
    def __init__(self, project: str, run_id: str, database: str = "(default)"):
        from google.cloud import firestore   # S1 에서만 import
        self.db = firestore.Client(project=project, database=database)
        self.run_id = run_id

    def _col(self, name: str):
        return self.db.collection(name).document(self.run_id).collection("items")

    def write_record(self, record: dict, provenance: Optional[Provenance]) -> None:
        seq = int(time.time() * 1e6)
        self._col("records").document(record["record_id"]).set({
            "record_id": record["record_id"], "domain": record["domain"],
            "text": record["text"], "hide_location": record["hide_location"], "seq": seq})
        self._col("truth").document(record["record_id"]).set({
            "kind": record.get("kind", "benign"), "shard_json": json.dumps(record.get("shard"))})
        if provenance is not None:
            self._col("provenance").document(record["record_id"]).set(provenance.__dict__)

    def read_records(self, domain: str) -> list[dict]:
        # where+order_by 는 복합 인덱스를 요구하므로 정렬은 파이썬에서 수행
        docs = [s.to_dict() for s in self._col("records").where("domain", "==", domain).stream()]
        docs.sort(key=lambda d: d.get("seq", 0))
        return [{k: d.get(k) for k in ("record_id", "domain", "text", "hide_location")} for d in docs]

    def read_provenance(self, record_id: str) -> Optional[Provenance]:
        d = self._col("provenance").document(record_id).get()
        return Provenance(**d.to_dict()) if d.exists else None

    def read_truth(self, record_id: str) -> Optional[dict]:
        d = self._col("truth").document(record_id).get()
        if not d.exists: return None
        t = d.to_dict(); return {"kind": t["kind"], "shard": json.loads(t["shard_json"]) if t["shard_json"] else None}

    def reset(self) -> None:
        for c in ("records", "provenance", "truth"):
            for s in self._col(c).stream():
                s.reference.delete()
