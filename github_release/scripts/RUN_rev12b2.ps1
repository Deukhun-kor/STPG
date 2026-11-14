# rev12 stage B2: the hardened / labeled victim runs stopped at the default agent-call cap (503 and 397 of 918 traces);
# rerun them with the cap raised. Completed traces are kept (checkpoint), only the remaining ones call the victim.
# 사용: powershell -ExecutionPolicy Bypass -File scripts\RUN_rev12b2.ps1 -Witness w3
param([string]$Witness = "w3")
$ErrorActionPreference = "Stop"
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:STPG_RESULTS_DIR = Join-Path $root "results"
$env:STPG_LLM_BACKEND = "vertex"
$env:STPG_WITNESS = $Witness
python scripts\s2_experiment.py --profile s4_main --out rev12_hardened --n-benign 90 --n-distractor 2 --victim-prompt hardened --max-agent-calls 5000 `
  --detectors "none,stpg,stpg_allow";                                                             Check "hardened victim"
python scripts\s2_experiment.py --profile s4_main --out rev12_labeled --n-benign 90 --n-distractor 2 --victim-prompt hardened --victim-labels --max-agent-calls 5000 `
  --detectors "none,stpg,stpg_allow";                                                             Check "labeled victim"
python scripts\analysis\rev12_report.py > results\rev12_report.txt
Get-Content results\rev12_report.txt | Select-Object -Last 60
