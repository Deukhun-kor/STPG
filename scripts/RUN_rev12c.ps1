# rev12 stage C (Round-1 revision, loop 3): the frozen-evaluation set. Run ONLY after stage B is complete and the kernel,
# resolver pattern, witness prompt, thresholds, and canonicalization are frozen; nothing is tuned after this run.
#   1) phrasings written by the second model family (Llama 4 Maverick), four domains including the new "procurement" domain
#   2) 12 structures x 4 domains x 5 reps = 240 traces, victim gemini-2.5-flash-lite, primary judge / witness
#   3) the same traces with Llama as the victim
# 사용: powershell -ExecutionPolicy Bypass -File scripts\RUN_rev12c.ps1 [-Witness w2|w3] [-Llama meta/llama-4-maverick-17b-128e-instruct-maas]
param([string]$Witness = "w2", [string]$Llama = "meta/llama-4-maverick-17b-128e-instruct-maas")
$ErrorActionPreference = "Stop"
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }
function Fresh($names) { foreach ($f in $names) { Remove-Item "results\$f.db","results\$f`_summary.json" -ErrorAction SilentlyContinue } }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:STPG_RESULTS_DIR = Join-Path $root "results"
$env:STPG_LLM_BACKEND = "vertex"
$env:STPG_WITNESS = $Witness
$GATES = "none,stpg,stpg_allow,stpg_tdo,stpg_tdo_allow,stpg_pdgonly,match_gate,attr_judge"

if (-not (Test-Path "results\rev12_unseen_phrasings.json")) { python scripts\gen_unseen_phrasings.py --model $Llama; Check "phrasings" }
python scripts\check_unseen_offline.py;                                                           Check "unseen offline"

Fresh @("rev12_unseen","rev12_unseen_lvictim")
python scripts\s2_experiment.py --profile s4_main --out rev12_unseen --robust unseen --reps 5 --n-distractor 2 `
  --detectors "$GATES,judge_gate,unit,window,stpg_grp_record,stpg_grp_session";                   Check "unseen"
python scripts\s2_experiment.py --profile s4_main --out rev12_unseen_lvictim --robust unseen --reps 5 --n-distractor 2 --model $Llama `
  --max-agent-calls 5000 --detectors "$GATES";                                                    Check "unseen llama victim"
python scripts\analysis\rev12_report.py --unseen
# 결과: results\rev12_unseen_phrasings.json, rev12_unseen.db, rev12_unseen_lvictim.db
