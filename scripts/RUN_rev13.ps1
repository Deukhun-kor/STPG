# rev13 (Round-2 revision, Reviewer 2 #1 / Reviewer 1 #1): witness agreement. The condition stpg_dual authorizes a
# trusted lineage only when the primary witness (gemini-2.5-flash-lite, w3) AND a second-family witness (Llama 4 Maverick,
# same prompt w3) both give a verified target verdict; untrusted-branch blocking and the default are unchanged.
# Runs the new condition (and its allow-on-empty variant where informative) on the main run, the challenge set, set E
# (descriptive notices, w3) and the frozen evaluation set, all under kernel v3.5 with the cached victim decisions, so only
# witness calls are made. Results: results\v35\rev13_*.db.
# 사용: powershell -ExecutionPolicy Bypass -File scripts\RUN_rev13.ps1   (프로젝트 루트, .venv 활성, Vertex 인증)
param([string]$Llama = "meta/llama-4-maverick-17b-128e-instruct-maas")
$ErrorActionPreference = "Stop"
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:STPG_RESULTS_DIR = Join-Path $root "results\v35"
$env:STPG_LLM_BACKEND = "vertex"
$env:STPG_WITNESS = "w3"
$env:STPG_SECOND_WITNESS = $Llama
Remove-Item Env:STPG_RELATION_EXT -ErrorAction SilentlyContinue

python scripts\test_rev13_offline.py;       Check "offline rev13"

# victim decisions are served from the existing caches (no victim call)
Copy-Item results\v35\rev12_main_agent.db      results\v35\rev13_main_agent.db      -Force
Copy-Item results\v35\rev12_holdout_agent.db   results\v35\rev13_holdout_agent.db   -Force
Copy-Item results\v35\rev12_notice_w3_agent.db results\v35\rev13_notice_agent.db    -Force
Copy-Item results\v35\rev12_unseen_agent.db    results\v35\rev13_unseen_agent.db    -Force
foreach ($f in "rev13_main","rev13_holdout","rev13_notice","rev13_unseen") { Remove-Item "results\v35\$f.db","results\v35\$f`_summary.json" -ErrorAction SilentlyContinue }

# 1) set E (descriptive notices, w3): the target of the criterion
python scripts\s2_experiment.py --profile s4_main --out rev13_notice --robust notice --reps 10 --n-distractor 2 `
  --detectors "stpg,stpg_dual";                                                                   Check "rev13 notice"
# 2) frozen evaluation set (same traces and specified decisions as run 5; nothing re-tuned)
python scripts\s2_experiment.py --profile s4_main --out rev13_unseen --robust unseen --reps 5 --n-distractor 2 `
  --detectors "stpg,stpg_dual";                                                                   Check "rev13 unseen"
# 3) main run: cost of the criterion on the 71 approved transfers (and attack blocking)
python scripts\s2_experiment.py --profile s4_main --out rev13_main --n-benign 90 --n-distractor 2 `
  --detectors "stpg,stpg_dual";                                                                   Check "rev13 main"
# 4) challenge set: policy conformance of the criterion
python scripts\s2_experiment.py --profile s4_main --out rev13_holdout --holdout --reps 4 --n-distractor 2 `
  --detectors "stpg,stpg_dual";                                                                   Check "rev13 holdout"

python scripts\analysis\rev13_report.py > results\v35\rev13_report.txt
Get-Content results\v35\rev13_report.txt
Write-Host "`nDONE: results\v35\rev13_report.txt"
