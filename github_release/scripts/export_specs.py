"""트레이스 명세를 JSON 으로 내보낸다(클라우드 Job 인자용). 사용: python scripts/export_specs.py s0_mock_small 6"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stpg import config as C
from stpg.datagen.generator import build_trace_specs
profile = sys.argv[1] if len(sys.argv) > 1 else "s0_mock_small"
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 0
specs = [s.to_dict() for s in build_trace_specs(C.load_profile(profile))]
if limit:   # 파일럿: 공격(g=1,k>=2) / 공격(g=0) / 정상 을 섞어 소량
    a1=[s for s in specs if s["is_attack"] and s["g"]==1 and s["k"]>=2][:limit//3 or 1]
    a0=[s for s in specs if s["is_attack"] and s["g"]==0 and s["k"]>=2][:limit//3 or 1]
    bn=[s for s in specs if not s["is_attack"]][:limit - len(a1) - len(a0)]
    specs = a1+a0+bn
os.makedirs("data", exist_ok=True)
out = f"data/specs_{profile}{'_pilot' if limit else ''}.json"
json.dump(specs, open(out, "w", encoding="utf-8"), ensure_ascii=False)
print(out, len(specs))
