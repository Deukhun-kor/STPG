# rev12 stage E (pre-submission review of v7, item M1): kernel v3.5 = destination-grammar pre-check, whitespace is a word
# boundary. (1) offline checks, (2) re-derive every run-4 DB under v3.5 into results\v35 (the pre-check depends on the
# destination string only; check_v35_equivalence.py shows that no other decision changes except in set A), (3) re-run
# set A (degraded rules, all conditions, witness w3) and set F (surface forms + look-alikes + the three malformed forms)
# with the cached victim decisions, (4) report from results\v35.
# 사용: powershell -ExecutionPolicy Bypass -File scripts\RUN_rev12e.ps1   (프로젝트 루트, .venv 활성, Vertex 인증)
$ErrorActionPreference = "Stop"
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:STPG_RESULTS_DIR = Join-Path $root "results"
$env:STPG_LLM_BACKEND = "vertex"
$env:STPG_WITNESS = "w3"

# 1) offline: kernel regression (v3.5 must match v3.4 on every set except the malformed forms) and the exactness check
python scripts\test_gate_offline.py;        Check "offline v3.3 regression"
python scripts\test_rev12_offline.py;       Check "offline rev12"
python scripts\check_v35_equivalence.py     # exit 1 is expected: set A's space-written rules differ -> set A is re-run below

# 2) re-derive run 4 under v3.5 (copies results\rev12_* to results\v35\ and applies the pre-check; log: results\v35\rederive_log.json)
python scripts\analysis\rev12_v35_rederive.py;  Check "rederive"
$env:STPG_RESULTS_DIR = Join-Path $root "results\v35"

# 3a) set A, all conditions, w3, kernel v3.5 (victim decisions cached from rev11)
Copy-Item results\rev11_paraphrases.json results\v35\rev11_paraphrases.json -Force
Copy-Item results\rev11_rules_agent.db results\v35\rev12_rules_agent.db -Force
python scripts\s2_experiment.py --profile s4_main --out rev12_rules --robust rules --reps 10 --n-distractor 2 `
  --paraphrases results\v35\rev11_paraphrases.json `
  --detectors "none,stpg,stpg_allow,stpg_tdo,stpg_tdo_allow,stpg_pdgonly,match_gate,attr_judge,stpg_grp_record,stpg_grp_record_allow,stpg_grp_session,stpg_grp_session_allow"
Check "set A v3.5"

# 3b) set F with the three malformed forms (victim decisions cached from run 4)
Copy-Item results\rev12_confusable_agent.db results\v35\rev12_confusable_agent.db -Force
python scripts\s2_experiment.py --profile s4_main --out rev12_confusable --robust confusable --reps 10 --n-distractor 2 `
  --detectors "none,stpg,stpg_allow,stpg_tdo,stpg_tdo_allow,stpg_pdgonly,match_gate,attr_judge"
Check "set F v3.5"

# 4) report (every table of the revision) from results\v35
python scripts\analysis\rev12_report.py --unseen > results\v35\rev12_report.txt
Get-Content results\v35\rev12_report.txt | Select-Object -First 60
Write-Host "`nDONE: results\v35\rev12_report.txt, results\v35\rederive_log.json"
