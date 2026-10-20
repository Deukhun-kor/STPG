"""STPG 모듈 절제 실험: PPT/TSA/PDG 를 하나씩 제거했을 때의 효과."""
from __future__ import annotations
import os
from pathlib import Path

from stpg import config as C
from stpg.datagen.generator import build_trace_specs
from stpg.runner.session import run_trace
from stpg.storage.sqlite_store import SqliteStore
from stpg.runner.experiment import detect_score, ExperimentDB
from stpg.gateway.scoring import Scorer
from stpg.gateway.stpg import STPGGateway

ABLATIONS = {
    "stpg_full":  dict(enable_ppt=True,  enable_tsa=True,  enable_pdg=True),
    "no_ppt":     dict(enable_ppt=False, enable_tsa=True,  enable_pdg=True),
    "no_tsa":     dict(enable_ppt=True,  enable_tsa=False, enable_pdg=True),
    "no_pdg":     dict(enable_ppt=True,  enable_tsa=True,  enable_pdg=False),
    "tsa_quar":   dict(enable_ppt=True,  enable_tsa=True,  enable_pdg=True, quarantine=True),  # D3
}


def run_ablation(profile: str, out_name: str) -> dict:
    cfg = C.load_profile(profile)
    C.ensure_dirs()
    specs = build_trace_specs(cfg)
    db = ExperimentDB(C.RESULTS_DIR / f"{out_name}.db")
    for name, flags in ABLATIONS.items():
        for sp in specs:
            if db.done(name, sp.run_id):
                continue
            store = SqliteStore()
            sc = Scorer(store.read_truth, seed=cfg.mock.seed + C.stable_int(name) % 1000)
            gw = STPGGateway(sc, cfg.tsa_threshold, cfg.pdg_min_delta, **flags)
            row = run_trace(sp.to_dict(), gateway=gw, mock=cfg.mock, store=store)
            db.save(name, row, detect_score(name, row))
    return {"db": str(C.RESULTS_DIR / f"{out_name}.db"), "variants": list(ABLATIONS)}
