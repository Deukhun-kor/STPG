"""
실험 오케스트레이터.
- 각 탐지 조건(none/stpg/unit/window/structural/taint)에 대해 모든 트레이스를 실행.
- 체크포인트/재개: (detector, run_id) 단위로 완료 상태 기록 → 중단 후 완료분 건너뜀.
- 사전 비용 추정: 실행 전 토큰·비용 예측 출력(S0 는 0).
- 결과를 JSONL + SQLite 로 저장.
"""
from __future__ import annotations
from pathlib import Path
import json
import sqlite3
import time

from stpg import config as C
from stpg.datagen.generator import build_trace_specs
from stpg.runner.session import run_trace
from stpg.storage.sqlite_store import SqliteStore
from stpg.gateway.scoring import Scorer
from stpg.gateway.stpg import STPGGateway
from stpg.gateway import baselines as B

DETECTORS = ["none", "stpg", "unit", "window", "structural", "taint"]


def make_detector(name: str, cfg: C.ExperimentConfig, store=None):
    """store 가 주어지면 Scorer 가 그 저장소의 truth 를 조회한다(오라클)."""
    if name == "none":
        return None
    sc = Scorer(store.read_truth if store else (lambda rid: None),
                seed=cfg.mock.seed + C.stable_int(name) % 1000)
    if name == "stpg":
        return STPGGateway(sc, cfg.tsa_threshold, cfg.pdg_min_delta,
                           quarantine=cfg.tsa_quarantine)
    if name == "unit":
        return B.UnitInspection(sc, cfg.tsa_threshold)
    if name == "window":
        return B.WindowJudge(sc, cfg.tsa_threshold, window=cfg.window_sizes[-1])
    if name == "structural":
        return B.StructuralSignal(sc, cfg.tsa_threshold)
    if name == "taint":
        return B.TaintNoPersist(sc, cfg.tsa_threshold)
    raise ValueError(name)


def detect_score(detector: str, row: dict) -> float:
    """트레이스 1건에 대한 탐지기의 연속 점수(0~1). AUROC/TPR 계산용."""
    rd, sd = row.get("read_detect"), row.get("sink_detect")
    s_read = 0.0
    if rd:
        if "emergent" in rd:         # STPG TSA
            s_read = float(rd.get("emergent", 0.0))
        elif "score" in rd:          # unit/window/structural/taint
            s_read = float(rd.get("score", 0.0))
    s_sink = 0.0
    if sd:
        if "delta" in sd:            # STPG PDG: 권한격차 정규화(최대 3)
            s_sink = max(0.0, float(sd["delta"]) / 3.0)
        elif "score" in sd:
            s_sink = float(sd.get("score", 0.0))
    return round(max(s_read, s_sink), 4)


def preflight(cfg: C.ExperimentConfig, n_traces: int) -> dict:
    model = C.MODELS[cfg.model]
    n_runs = n_traces * len(DETECTORS)
    # S0 mock = 0. 실제 모델은 트레이스당 추정 토큰으로 환산.
    est_in = n_runs * 60000
    est_out = n_runs * 5000
    cost = (est_in / 1e6) * model.input_usd_per_m + (est_out / 1e6) * model.output_usd_per_m
    return {"n_traces": n_traces, "detectors": len(DETECTORS), "n_runs": n_runs,
            "model": model.name, "est_input_tokens": est_in,
            "est_output_tokens": est_out, "est_cost_usd": round(cost, 4)}


class ExperimentDB:
    def __init__(self, path: Path):
        self.conn = sqlite3.connect(path)
        self.conn.execute("""CREATE TABLE IF NOT EXISTS results(
            detector TEXT, run_id TEXT, domain TEXT, is_attack INT, k INT, d INT, g INT,
            hide_location TEXT, rep INT, did_privileged INT, attempted INT,
            attack_success INT, sink_allowed INT, detect_score REAL, status TEXT,
            PRIMARY KEY(detector, run_id))""")
        self.conn.commit()

    def done(self, detector: str, run_id: str) -> bool:
        r = self.conn.execute("SELECT 1 FROM results WHERE detector=? AND run_id=? AND status='done'",
                              (detector, run_id)).fetchone()
        return r is not None

    def save(self, detector: str, row: dict, score: float) -> None:
        self.conn.execute("INSERT OR REPLACE INTO results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (detector, row["run_id"], row["domain"], int(row["is_attack"]), row["k"],
             row["d"], row["g"], row["hide_location"], row["rep"],
             int(bool(row["did_privileged"])), int(bool(row["attempted"])),
             int(bool(row["attack_success"])),
             int(bool(row["sink_allowed"])) if row["sink_allowed"] is not None else -1,
             score, "done"))
        self.conn.commit()

    def all_rows(self) -> list[dict]:
        cols = [c[1] for c in self.conn.execute("PRAGMA table_info(results)")]
        return [dict(zip(cols, r)) for r in self.conn.execute("SELECT * FROM results")]


def run_experiment(profile: str = "s0_mock", out_name: str | None = None,
                   detectors: list[str] | None = None) -> dict:
    cfg = C.load_profile(profile)
    C.ensure_dirs()
    specs = build_trace_specs(cfg)
    dets = detectors or DETECTORS
    pf = preflight(cfg, len(specs))
    print(f"[preflight] {json.dumps(pf, ensure_ascii=False)}")
    if pf["est_cost_usd"] > cfg.caps.total_usd:
        raise RuntimeError(f"preflight cost {pf['est_cost_usd']} > cap {cfg.caps.total_usd}")

    out_name = out_name or cfg.name
    dbp = C.RESULTS_DIR / f"{out_name}.db"
    db = ExperimentDB(dbp)
    t0 = time.time()
    n_run, n_skip = 0, 0
    for det in dets:
        for sp in specs:
            if db.done(det, sp.run_id):
                n_skip += 1
                continue
            store = SqliteStore()
            gw = make_detector(det, cfg, store)
            row = run_trace(sp.to_dict(), gateway=gw, mock=cfg.mock, store=store)
            db.save(det, row, detect_score(det, row))
            n_run += 1
    dt = time.time() - t0
    summary = {"profile": profile, "db": str(dbp), "ran": n_run, "skipped": n_skip,
               "seconds": round(dt, 2), "preflight": pf}
    (C.RESULTS_DIR / f"{out_name}_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2))
    return summary
