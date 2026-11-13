# rev14 (Round-2 revision, run 7): second held-out set H2 for Reviewer 2 #1 (witness agreement on previously unseen notice
# formulations and legitimate standing arrangements) and Reviewer 2 #2 (extended resolver on previously unseen relation
# formulations, without adaptation). Two stages so that the phrasings are reviewed before anything is evaluated:
#   Stage 1  freeze (hashes of kernel, resolver, prompt, agreement rule, policy) -> second model family writes the
#            phrasings -> review sheet + lock. STOP and read results\v35\rev14_phrasings_review.txt.
#   Stage 2  evaluate STPG and witness agreement (rev14_unseen2.db), then the same traces with the extended resolver
#            (rev14_unseen2_relext.db, victim decisions copied so only gate decisions differ), then the report.
# 사용 (프로젝트 루트, .venv 활성, Vertex 인증):
#   powershell -ExecutionPolicy Bypass -File scripts\RUN_rev14.ps1 -Stage 1
#   powershell -ExecutionPolicy Bypass -File scripts\RUN_rev14.ps1 -Stage 2
param([int]$Stage = 1, [string]$Llama = "meta/llama-4-maverick-17b-128e-instruct-maas")
$ErrorActionPreference = "Stop"
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:STPG_RESULTS_DIR = Join-Path $root "results\v35"
$env:STPG_LLM_BACKEND = "vertex"
$env:STPG_WITNESS = "w3"
$env:STPG_SECOND_WITNESS = $Llama
Remove-Item Env:STPG_RELATION_EXT -ErrorAction SilentlyContinue

if ($Stage -eq 1) {
    python scripts\test_rev14_offline.py;                    Check "offline rev14"
    python scripts\freeze_rev14.py;                          Check "freeze"
    python scripts\gen_rev14_phrasings.py --model $Llama;    Check "phrasings"
    python scripts\review_rev14_phrasings.py;                Check "review"
    Write-Host "`nSTAGE 1 DONE: read results\v35\rev14_phrasings_review.txt (and rev14_unseen2_phrasings.json)."
    Write-Host "If an item must be removed, delete it from the JSON (no rewording) and rerun: python scripts\review_rev14_phrasings.py"
    Write-Host "Then: powershell -ExecutionPolicy Bypass -File scripts\RUN_rev14.ps1 -Stage 2"
    exit 0
}

python scripts\freeze_rev14.py --check;                      Check "freeze check"
foreach ($f in "rev14_unseen2","rev14_unseen2_relext") { Remove-Item "results\v35\$f.db","results\v35\$f`_summary.json" -ErrorAction SilentlyContinue }
Remove-Item results\v35\rev14_unseen2_relext_agent.db -ErrorAction SilentlyContinue

# 1) frozen resolver: STPG and witness agreement on H2 (victim decisions are made once here and cached)
python scripts\s2_experiment.py --profile s4_main --out rev14_unseen2 --robust unseen2 --reps 5 --n-distractor 2 `
  --detectors "stpg,stpg_dual";                                                                   Check "rev14 unseen2"

# 2) extended resolver (post-hoc pattern frozen in binding.py) on the same traces and the same victim decisions
Copy-Item results\v35\rev14_unseen2_agent.db results\v35\rev14_unseen2_relext_agent.db -Force
$env:STPG_RELATION_EXT = "1"
python scripts\s2_experiment.py --profile s4_main --out rev14_unseen2_relext --robust unseen2 --reps 5 --n-distractor 2 `
  --detectors "stpg,stpg_dual";                                                                   Check "rev14 unseen2 relext"
Remove-Item Env:STPG_RELATION_EXT -ErrorAction SilentlyContinue

python scripts\analysis\rev14_report.py > results\v35\rev14_report.txt
Get-Content results\v35\rev14_report.txt
Write-Host "`nDONE: results\v35\rev14_report.txt"
