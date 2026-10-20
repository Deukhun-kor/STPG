"""
S2-2 점수기 단독 검증: 그라운드트루스 없이, 실점수기가
  - 공격(조립된 외부 라우팅 텍스트)에 높은 점수
  - 정상(운영 로그)에 낮은 점수
를 내는지 확인. 임베딩/판정기/캐스케이드 각각.
사용(로컬, Vertex 인증 상태):
  python scripts/s2_verify_scorer.py --n 6
"""
import sys, os, argparse, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stpg import config as C
from stpg.datagen.realistic import build_realistic_specs
from stpg.gateway.scoring import EmbeddingFilter, LLMJudge, CascadeScorer


def assembled_text(spec):
    # 같은 계보(파편) 레코드의 본문만 연접 — 탐지기가 보는 것과 동일(정답 미사용)
    return " ".join(r["text"] for r in spec.ingest_records if r.get("shard"))

def benign_text(spec):
    return " ".join(r["text"] for r in spec.ingest_records)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--n", type=int, default=6); a = ap.parse_args()
    cfg = C.load_profile("s0_mock_small")
    specs = build_realistic_specs(cfg, benign_mode="with_legit")
    atk = [s for s in specs if s.is_attack][:a.n]
    ben = [s for s in specs if not s.is_attack][:a.n]

    emb = EmbeddingFilter(cfg.scorer)
    judge = LLMJudge(cfg.scorer)
    casc = CascadeScorer(EmbeddingFilter(cfg.scorer), LLMJudge(cfg.scorer),
                         cfg.scorer.cascade_pass_threshold)

    print(f"=== 점수기 단독 검증 (임베딩={cfg.scorer.embedding_model}, 판정={cfg.scorer.judge_model}) ===")
    print(f"{'type':6s} {'k':>2s} {'embed':>7s} {'judge':>7s} {'cascade':>8s}")
    rows = []
    for s in atk:
        t = assembled_text(s)
        e = emb.assembled([{"text": t}]); j = judge.assembled([{"text": t}]); c = casc.assembled([{"text": t}])
        rows.append(("ATK", s.k, e, j, c)); print(f"{'ATK':6s} {s.k:>2d} {e:7.3f} {j:7.3f} {c:8.3f}")
    for s in ben:
        t = benign_text(s)
        e = emb.assembled([{"text": t}]); j = judge.assembled([{"text": t}]); c = casc.assembled([{"text": t}])
        rows.append(("BEN", 0, e, j, c)); print(f"{'BEN':6s} {0:>2d} {e:7.3f} {j:7.3f} {c:8.3f}")

    def avg(tp, idx): 
        v=[r[idx] for r in rows if r[0]==tp]; return sum(v)/len(v) if v else 0
    print("\n평균:")
    for name, idx in [("embed",2),("judge",3),("cascade",4)]:
        print(f"  {name:8s} 공격={avg('ATK',idx):.3f}  정상={avg('BEN',idx):.3f}  분리={avg('ATK',idx)-avg('BEN',idx):+.3f}")
    print(f"\n캐스케이드 2차 호출: {casc.second_stage_calls}/{casc.calls} "
          f"(1차에서 걸러진 비율 {1-casc.second_stage_calls/max(1,casc.calls):.0%})")
    print(f"판정기 토큰: in={judge.in_tok} out={judge.out_tok}")
    os.makedirs("results", exist_ok=True)
    json.dump({"rows":[{"t":r[0],"k":r[1],"embed":r[2],"judge":r[3],"cascade":r[4]} for r in rows]},
              open("results/s2_verify_scorer.json","w"), indent=2)
    print("저장: results/s2_verify_scorer.json")

if __name__ == "__main__":
    main()
