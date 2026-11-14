# rev12 stage A (Round-1 revision, loop 1): offline checks, witness-prompt comparison on the notice / degraded-rule sets,
# second-model-family connectivity. Kernel v3.4 (full-path chain trust, destination canonicalization).
# 사용: powershell -ExecutionPolicy Bypass -File scripts\RUN_rev12a.ps1   (프로젝트 루트, .venv 활성, Vertex 인증, 결제 연결)
$ErrorActionPreference = "Stop"
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:STPG_RESULTS_DIR = Join-Path $root "results"
$env:STPG_LLM_BACKEND = "vertex"
$env:STPG_WITNESS = "w2"

# 0) offline kernel checks (no model calls): v3.3 challenge regression + rev12 sets
python scripts\test_gate_offline.py;  Check "offline v3.3 regression"
python scripts\test_rev12_offline.py; Check "offline rev12"

# 1) E. descriptive notices (R2-2) under the primary witness prompt w2: 3 domains x 10 reps x 5 phrasings = 150 benign traces
foreach ($f in "rev12_notice_w2") { Remove-Item "results\$f.db","results\$f`_summary.json" -ErrorAction SilentlyContinue }
python scripts\s2_experiment.py --profile s4_main --out rev12_notice_w2 --robust notice --reps 10 --n-distractor 2 `
  --detectors none,stpg,stpg_allow,match_gate,attr_judge
Check "notice w2"

# 2) the same traces under the revised witness prompt w3 (victim decisions reused)
$env:STPG_WITNESS = "w3"
foreach ($f in "rev12_notice_w3") { Remove-Item "results\$f.db","results\$f`_summary.json" -ErrorAction SilentlyContinue }
Copy-Item results\rev12_notice_w2_agent.db results\rev12_notice_w3_agent.db -Force
python scripts\s2_experiment.py --profile s4_main --out rev12_notice_w3 --robust notice --reps 10 --n-distractor 2 `
  --detectors stpg,stpg_allow
Check "notice w3"

# 3) degraded approved rules (set A of rev11) under w3, kernel v3.4 (victim decisions from rev11): does w3 break implicit rules?
foreach ($f in "rev12_rules_w3") { Remove-Item "results\$f.db","results\$f`_summary.json" -ErrorAction SilentlyContinue }
Copy-Item results\rev11_rules_agent.db results\rev12_rules_w3_agent.db -Force
python scripts\s2_experiment.py --profile s4_main --out rev12_rules_w3 --robust rules --reps 10 --n-distractor 2 `
  --detectors stpg,stpg_allow
Check "rules w3"
$env:STPG_WITNESS = "w2"

# 4) second model family connectivity (Vertex AI MaaS, OpenAI-compatible). Requires: pip install openai google-auth,
#    and the Llama 4 Maverick (MaaS) license accepted in Vertex AI Model Garden for this project (region us-east5).
python scripts\test_llama.py
Check "llama connectivity"

python scripts\analysis\rev12_stage_a.py
# 결과: results\rev12_notice_w2.db, rev12_notice_w3.db, rev12_rules_w3.db (+ *_summary.json, *_agent.db)
