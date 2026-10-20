# rev8: kernel v3.3 (endpoint pre-check + support-verified witness, witness cache namespaced by prompt version)
# 사용: powershell -ExecutionPolicy Bypass -File scripts\RUN_rev8.ps1   (프로젝트 루트에서, .venv 활성 + Vertex 인증 상태)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:STPG_RESULTS_DIR = Join-Path $root "results"
$env:STPG_LLM_BACKEND = "vertex"

# 0) 오프라인 커널 검증(모델 호출 없음) — 모든 구조가 사양과 일치해야 함
python scripts\test_gate_offline.py

# 1) 이전 중단 실행의 부분 결과 제거(요약 JSON 을 깨끗하게 만들기 위해) 후 victim 결정 캐시 재사용
foreach ($f in "rev8_main","rev8_holdout","rev8_flash") { Remove-Item "results\$f.db","results\$f`_summary.json" -ErrorAction SilentlyContinue } (rev7 과 동일 트레이스·동일 seed -> victim 토큰 0)
Copy-Item results\rev7_main_agent.db    results\rev8_main_agent.db    -Force
Copy-Item results\rev7_holdout_agent.db results\rev8_holdout_agent.db -Force
Copy-Item results\rev7_flash_agent.db   results\rev8_flash_agent.db   -Force

# 2) main run (918 traces, 12 conditions)
python scripts\s2_experiment.py --profile s4_main --out rev8_main --n-benign 90 --n-distractor 2

# 3) policy challenge set (180 traces, 240 counterfactual calls)
python scripts\s2_experiment.py --profile s4_main --out rev8_holdout --holdout --reps 4 --n-distractor 2

# 4) second victim (gemini-2.5-flash; gate conditions only)
python scripts\s2_experiment.py --profile s4_main --out rev8_flash --model gemini-2.5-flash --n-benign 90 --n-distractor 2 `
  --detectors none,stpg,stpg_allow,stpg_tdo,stpg_tdo_allow,stpg_pdgonly,match_gate,attr_judge

# 결과: results\rev8_main.db, rev8_main_summary.json, rev8_holdout.db, rev8_holdout_summary.json, rev8_flash.db, rev8_flash_summary.json
