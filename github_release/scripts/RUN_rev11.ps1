# rev11: robustness sets (A degraded rules, B multi-connector attacks) and judge/witness model swap (C).
# 사용: powershell -ExecutionPolicy Bypass -File scripts\RUN_rev11.ps1   (프로젝트 루트, .venv 활성, Vertex 인증, 결제 연결 상태)
$ErrorActionPreference = "Stop"
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:STPG_RESULTS_DIR = Join-Path $root "results"
$env:STPG_LLM_BACKEND = "vertex"

# 0) offline kernel check of the new sets (no model calls)
python scripts\test_robust_offline.py
Check "offline check"

# 1) LLM paraphrases of the approved rule (gemini-2.5-flash, saved to results\rev11_paraphrases.json; skip if the file exists)
if (-not (Test-Path "results\rev11_paraphrases.json")) { python scripts\gen_paraphrases.py --model gemini-2.5-flash --n 6; Check "paraphrases" }

# 2) A. degraded approved rules: 3 domains x 10 reps x 7 variants = 210 benign traces (new victim decisions)
foreach ($f in "rev11_rules") { Remove-Item "results\$f.db","results\$f`_summary.json" -ErrorAction SilentlyContinue }
python scripts\s2_experiment.py --profile s4_main --out rev11_rules --robust rules --reps 10 --n-distractor 2 `
  --detectors none,stpg,stpg_allow,stpg_tdo,stpg_tdo_allow,stpg_pdgonly,match_gate,attr_judge
Check "set A"

# 3) B. multi-connector attacks: 3 domains x 10 reps x 5 variants = 150 attack traces (new victim decisions)
foreach ($f in "rev11_multi") { Remove-Item "results\$f.db","results\$f`_summary.json" -ErrorAction SilentlyContinue }
python scripts\s2_experiment.py --profile s4_main --out rev11_multi --robust multi --reps 10 --n-distractor 2 `
  --detectors none,stpg,stpg_allow,stpg_tdo,stpg_tdo_allow,stpg_pdgonly,match_gate,attr_judge,taint,judge_gate,unit,window
Check "set B"

# 4) C. judge / witness model swap (gemini-2.5-flash) on the main run and the challenge set; victim decisions from the rev10 caches
foreach ($f in "rev11_main_fjudge","rev11_holdout_fjudge") { Remove-Item "results\$f.db","results\$f`_summary.json" -ErrorAction SilentlyContinue }
Copy-Item results\rev10_main_agent.db    results\rev11_main_fjudge_agent.db    -Force
Copy-Item results\rev10_holdout_agent.db results\rev11_holdout_fjudge_agent.db -Force
python scripts\s2_experiment.py --profile s4_main --out rev11_main_fjudge --n-benign 90 --n-distractor 2 --judge-model gemini-2.5-flash `
  --detectors stpg,stpg_allow,attr_judge,judge_gate
Check "set C main"
python scripts\s2_experiment.py --profile s4_main --out rev11_holdout_fjudge --holdout --reps 4 --n-distractor 2 --judge-model gemini-2.5-flash `
  --detectors stpg,attr_judge
Check "set C holdout"

# 결과: results\rev11_rules.db, rev11_multi.db, rev11_main_fjudge.db, rev11_holdout_fjudge.db (+ *_summary.json, *_agent.db, rev11_paraphrases.json)
# 분석: python scripts\analysis\rev_robust.py
