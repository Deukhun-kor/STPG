# rev12 stage D: POST-HOC analysis on the frozen set (reported separately, never as a frozen result): the relation
# pattern M extended with the phrases observed in the LLM-written mapping records (STPG_RELATION_EXT=1, kernel v3.4+relext).
# Victim decisions are reused from rev12_unseen; only witness / judge calls are made.
# 사용: powershell -ExecutionPolicy Bypass -File scripts\RUN_rev12d.ps1 -Witness w3
param([string]$Witness = "w3")
$ErrorActionPreference = "Stop"
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:STPG_RESULTS_DIR = Join-Path $root "results"
$env:STPG_LLM_BACKEND = "vertex"
$env:STPG_WITNESS = $Witness
$env:STPG_RELATION_EXT = "1"
python scripts\check_unseen_offline.py | Select-Object -First 50;                                  Check "offline ext"
foreach ($f in "rev12_unseen_relext") { Remove-Item "results\$f.db","results\$f`_summary.json" -ErrorAction SilentlyContinue }
Copy-Item results\rev12_unseen_agent.db results\rev12_unseen_relext_agent.db -Force
python scripts\s2_experiment.py --profile s4_main --out rev12_unseen_relext --robust unseen --reps 5 --n-distractor 2 `
  --detectors "none,stpg,stpg_allow,stpg_tdo,match_gate";                                         Check "unseen relext"
# regression of the extended pattern on the challenge set (victim cache from rev10)
foreach ($f in "rev12_holdout_relext") { Remove-Item "results\$f.db","results\$f`_summary.json" -ErrorAction SilentlyContinue }
Copy-Item results\rev10_holdout_agent.db results\rev12_holdout_relext_agent.db -Force
python scripts\s2_experiment.py --profile s4_main --out rev12_holdout_relext --holdout --reps 4 --n-distractor 2 `
  --detectors "stpg,stpg_allow";                                                                  Check "holdout relext"
Remove-Item Env:STPG_RELATION_EXT
python scripts\analysis\rev12_report.py --unseen > results\rev12_report.txt
Get-Content results\rev12_report.txt | Select-Object -Last 80
