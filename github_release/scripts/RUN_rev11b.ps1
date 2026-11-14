# rev11b: re-run of (C) judge/witness model swap and of the gemini-2.5-flash victim after disabling Gemini 2.5 "thinking"
# (with thinking on, gemini-2.5-flash spent the output budget on reasoning and returned truncated JSON; the rev10_flash
#  victim decisions and the first rev11 set-C runs were therefore parse-failure artifacts and are superseded by these runs).
# 사용: powershell -ExecutionPolicy Bypass -File scripts\RUN_rev11b.ps1
$ErrorActionPreference = "Stop"
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:STPG_RESULTS_DIR = Join-Path $root "results"
$env:STPG_LLM_BACKEND = "vertex"

# 1) C. judge / witness model swap (gemini-2.5-flash, thinking off); victim decisions from the rev10 caches
$skipC = (Test-Path "results\rev11b_main_fjudge_summary.json") -and (Test-Path "results\rev11b_holdout_fjudge_summary.json")
if (-not $skipC) {
Copy-Item results\rev10_main_agent.db    results\rev11b_main_fjudge_agent.db    -Force
Copy-Item results\rev10_holdout_agent.db results\rev11b_holdout_fjudge_agent.db -Force
python scripts\s2_experiment.py --profile s4_main --out rev11b_main_fjudge --n-benign 90 --n-distractor 2 --judge-model gemini-2.5-flash `
  --detectors stpg,stpg_allow,attr_judge,judge_gate
Check "set C main"
python scripts\s2_experiment.py --profile s4_main --out rev11b_holdout_fjudge --holdout --reps 4 --n-distractor 2 --judge-model gemini-2.5-flash `
  --detectors stpg,attr_judge
Check "set C holdout"
} else { Write-Host "set C already complete - skipped" }

# 2) second victim (gemini-2.5-flash, thinking off): fresh victim decisions (NO cache copy), gate conditions as in rev10_flash
# (resume-safe: completed rows and cached victim decisions are kept)
Remove-Item "results\rev11b_flash_summary.json" -ErrorAction SilentlyContinue
python scripts\s2_experiment.py --profile s4_main --out rev11b_flash --model gemini-2.5-flash --n-benign 90 --n-distractor 2 --max-agent-calls 5000 `
  --detectors none,stpg,stpg_allow,stpg_tdo,stpg_tdo_allow,stpg_pdgonly,match_gate,attr_judge
Check "flash victim"

# 결과: results\rev11b_main_fjudge.db, rev11b_holdout_fjudge.db, rev11b_flash.db (+ summaries)
# 분석: python scripts\analysis\rev_robust.py   (set C 는 rev11b_* 를 읽도록 갱신됨)
