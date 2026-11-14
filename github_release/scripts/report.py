"""S0 결과 종합 보고 (지표 + 절제)."""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stpg.runner.experiment import DETECTORS
from stpg.analysis.metrics import full_report, _load, attack_metrics
from pathlib import Path

def main():
    rdir = Path(os.environ.get("STPG_RESULTS_DIR", "results"))
    db = sys.argv[1] if len(sys.argv) > 1 else str(rdir / "s0_full.db")
    rep = full_report(db, DETECTORS, n_boot=1000)
    print("="*70); print("STPG S0 모의 실험 결과 보고"); print("="*70)
    a = rep["attack"]
    print(f"\n[공격 성립]  ASR(무방어)={a['ASR_none']}  ASR(STPG)={a['ASR_stpg']}  STPG차단율={a['block_rate_stpg']}")
    print(f"           k별 ASR(무방어): {a['ASR_none_by_k']}")
    import sqlite3
    c=sqlite3.connect(db)
    print("           g별 ASR  (g=1: 권한상승 조건 / g=0: 양쪽 고권한 대조군)")
    for det in ["none","stpg"]:
        for g in [0,1]:
            n,s=c.execute("SELECT COUNT(*),SUM(attack_success) FROM results WHERE detector=? AND is_attack=1 AND g=?",(det,g)).fetchone()
            print(f"             {det:5s} g={g}: {s/n:.3f}")
    print(f"\n[탐지 성능]  (label=is_attack, score=detect_score)")
    print(f"  {'detector':12s} {'AUROC':>8s} {'95% CI':>18s} {'TPR@5%FPR':>10s} {'95% CI':>18s}")
    for d, m in rep["detectors"].items():
        ci=f"[{m['AUROC_CI'][0]:.3f},{m['AUROC_CI'][1]:.3f}]"
        tci=f"[{m['TPR@5%FPR_CI'][0]:.3f},{m['TPR@5%FPR_CI'][1]:.3f}]"
        print(f"  {d:12s} {m['AUROC']:8.3f} {ci:>18s} {m['TPR@5%FPR']:10.3f} {tci:>18s}")
    # 절제
    abdb = str(rdir / "s0_ablation.db")
    if Path(abdb).exists():
        print(f"\n[절제 실험]  (STPG 모듈 제거 효과)")
        rows=_load(Path(abdb))
        for v in ["stpg_full","no_ppt","no_tsa","no_pdg","tsa_quar"]:
            am=attack_metrics([r for r in rows if r["detector"]==v])
            sub=[r for r in rows if r["detector"]==v and r["is_attack"]==1]
            if not sub: continue
            g1=[r for r in sub if r["g"]==1]; g0=[r for r in sub if r["g"]==0]
            f=lambda L: round(sum(r["attack_success"] for r in L)/len(L),3) if L else None
            print(f"  {v:12s} ASR 전체={f(sub)}  g=1(상승)={f(g1)}  g=0(대조)={f(g0)}")
    print()

if __name__ == "__main__":
    main()
