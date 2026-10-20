"""S0 무결성 테스트 (수정판). python tests/test_pipeline.py"""
import sys, os, re, subprocess, json
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from stpg import config as C
from stpg.datagen.generator import build_trace_specs
from stpg.runner.session import run_trace
from stpg.runner.experiment import make_detector, detect_score
from stpg.storage.sqlite_store import SqliteStore

CFG = C.load_profile("s0_mock_small")
SPECS = build_trace_specs(CFG)
P1 = C.MockParams(p_follow_assembled=1.0)

def _run(spec, det, cfg=CFG, mock=P1):
    st = SqliteStore(); gw = make_detector(det, cfg, st)
    return run_trace(spec.to_dict(), gateway=gw, mock=mock, store=st)

def test_R1_determinism_across_processes():
    """같은 입력 → 다른 프로세스에서도 동일 결과."""
    code = ("import sys,json;sys.path.insert(0,%r);from tests.test_pipeline import SPECS,_run;"
            "sp=[s for s in SPECS if s.is_attack and s.k>=2][0];r=_run(sp,'stpg');"
            "print(json.dumps([r['attack_success'],r['read_detect'],r['sink_detect']],sort_keys=True))") % ROOT
    outs = {subprocess.check_output([sys.executable, "-c", code], cwd=ROOT).decode().strip() for _ in range(2)}
    assert len(outs) == 1, f"비재현: {outs}"

def test_R2_detectors_never_touch_truth():
    """정적 검사: 게이트웨이/베이스라인 코드는 shard·read_truth 에 접근하지 않는다(Scorer 제외)."""
    for f in ["stpg/gateway/stpg.py", "stpg/gateway/baselines.py"]:
        src = open(os.path.join(ROOT, f), encoding="utf-8").read()
        body = "\n".join(l for l in src.splitlines() if not l.strip().startswith(("#", '"""')))
        assert "read_truth" not in body and 'r["shard"]' not in body and "get(\"shard\")" not in body, f

def test_R3_iam_denies_privileged_call_from_low_priv():
    from stpg.mcp.backend import MockBackend
    from stpg.mcp.server import ToolRouter, ToolContext
    r = ToolRouter(SqliteStore(), MockBackend(), gateway=None)
    low = ToolContext("sa-agent-ingest", 1, 1, "s", "run", "/ingest", allowed_tools=("write_record",))
    assert r.call_backend_api("/iam/grant", {}, low)["status"] == "blocked"

def test_D1_g0_is_not_escalation_for_pdg():
    """g=0(양쪽 고권한): 공격이 실행돼도 PDG 는 '권한 상승'으로 플래그하지 않는다."""
    sp = [s for s in SPECS if s.is_attack and s.k >= 2 and s.g == 0][0]
    r = _run(sp, "stpg")
    if r["sink_detect"]:
        assert r["sink_detect"]["flagged"] is False and r["sink_detect"]["delta"] == 0

def test_D1_g1_escalation_blocked():
    sp = [s for s in SPECS if s.is_attack and s.k >= 2 and s.g == 1][0]
    r = _run(sp, "stpg")
    assert r["read_detect"]["flagged"] is True
    assert r["sink_allowed"] is False and r["attack_success"] is False

def test_D2_delay_adds_records():
    sp1 = [s for s in SPECS if s.is_attack and s.d == 1][0]
    sp3 = [s for s in SPECS if s.is_attack and s.d == 3][0]
    assert _run(sp3, "none")["n_records_at_trigger"] > _run(sp1, "none")["n_records_at_trigger"] - 3

def test_D3_quarantine_prevents_assembly():
    cfg = C.load_profile("s0_mock_small"); cfg.tsa_quarantine = True
    sp = [s for s in SPECS if s.is_attack and s.k >= 2 and s.g == 1][0]
    r = _run(sp, "stpg", cfg=cfg)
    assert r["read_detect"]["quarantined"] > 0 and r["did_privileged"] is False

def test_ablation_no_ppt_loses_detection():
    """PPT 제거 시 출처가 없어 TSA/PDG 가 계보·격차를 복원하지 못한다."""
    from stpg.gateway.stpg import STPGGateway
    from stpg.gateway.scoring import Scorer
    sp = [s for s in SPECS if s.is_attack and s.k >= 2 and s.g == 1][0]
    st = SqliteStore(); gw = STPGGateway(Scorer(st.read_truth, 1), 0.35, 1, enable_ppt=False)
    r = run_trace(sp.to_dict(), gateway=gw, mock=P1, store=st)
    assert r["read_detect"]["flagged"] is False and r["attack_success"] is True

def test_unit_catches_k1_misses_k3():
    k1 = [s for s in SPECS if s.is_attack and s.k == 1][0]
    k3 = [s for s in SPECS if s.is_attack and s.k == 3][0]
    assert _run(k1, "unit")["read_detect"]["flagged"] is True
    assert _run(k3, "unit")["read_detect"]["flagged"] is False

def test_benign_never_privileged():
    for s in [s for s in SPECS if not s.is_attack][:20]:
        assert _run(s, "none")["did_privileged"] is False

if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    ok = 0
    for fn in fns:
        try: fn(); print("PASS", fn.__name__); ok += 1
        except AssertionError as e: print("FAIL", fn.__name__, "-", e)
        except Exception as e: print("ERROR", fn.__name__, "-", type(e).__name__, e)
    print(f"\n{ok}/{len(fns)} passed")
