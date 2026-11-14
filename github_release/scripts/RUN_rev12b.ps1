# rev12 stage B (Round-1 revision, loop 2): recompute every reported run on kernel v3.4, add the grouping ablation,
# the two-hop chain / confusable / scale / latency / laundering sets, the hardened and labeled victim prompts, and the
# second model family (Llama 4 Maverick via Vertex AI MaaS) as judge / witness / attribution judge and as victim.
# The witness prompt used for every run below is fixed by $WITNESS (chosen from stage A; do not change afterwards).
# 사용: powershell -ExecutionPolicy Bypass -File scripts\RUN_rev12b.ps1 [-Witness w2|w3] [-Llama meta/llama-4-maverick-17b-128e-instruct-maas]
param([string]$Witness = "w2", [string]$Llama = "meta/llama-4-maverick-17b-128e-instruct-maas", [switch]$SkipLlama)
$ErrorActionPreference = "Stop"
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }
function Fresh($names) { foreach ($f in $names) { Remove-Item "results\$f.db","results\$f`_summary.json" -ErrorAction SilentlyContinue } }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:STPG_RESULTS_DIR = Join-Path $root "results"
$env:STPG_LLM_BACKEND = "vertex"
$env:STPG_WITNESS = $Witness
$GATES = "none,stpg,stpg_allow,stpg_tdo,stpg_tdo_allow,stpg_pdgonly,match_gate,attr_judge"
$GRP   = "stpg_grp_record,stpg_grp_record_allow,stpg_grp_session,stpg_grp_session_allow"

python scripts\test_rev12_offline.py; Check "offline"

# ---- 1) recomputation on kernel v3.4 (victim decisions from the rev10 / rev11 caches; witness / judge calls are live) ----
Fresh @("rev12_main","rev12_holdout","rev12_rules","rev12_multi")
Copy-Item results\rev10_main_agent.db    results\rev12_main_agent.db    -Force
Copy-Item results\rev10_holdout_agent.db results\rev12_holdout_agent.db -Force
Copy-Item results\rev11_rules_agent.db   results\rev12_rules_agent.db   -Force
Copy-Item results\rev11_multi_agent.db   results\rev12_multi_agent.db   -Force
python scripts\s2_experiment.py --profile s4_main --out rev12_main --n-benign 90 --n-distractor 2 `
  --detectors "$GATES,judge_gate,unit,window,taint,$GRP";                                         Check "main v3.4"
python scripts\s2_experiment.py --profile s4_main --out rev12_holdout --holdout --reps 4 --n-distractor 2 `
  --detectors "$GATES,$GRP";                                                                      Check "holdout v3.4"
python scripts\s2_experiment.py --profile s4_main --out rev12_rules --robust rules --reps 10 --n-distractor 2 `
  --detectors "$GATES,$GRP";                                                                      Check "rules v3.4"
python scripts\s2_experiment.py --profile s4_main --out rev12_multi --robust multi --reps 10 --n-distractor 2 `
  --detectors "$GATES,taint,judge_gate,unit,window,$GRP";                                         Check "multi v3.4"

# ---- 2) new sets (new victim decisions) ----
Fresh @("rev12_chain2","rev12_confusable","rev12_scale","rev12_launder")
python scripts\s2_experiment.py --profile s4_main --out rev12_chain2 --robust chain2 --reps 10 --n-distractor 2 `
  --detectors "$GATES,$GRP";                                                                      Check "chain2"
python scripts\s2_experiment.py --profile s4_main --out rev12_confusable --robust confusable --reps 10 --n-distractor 2 `
  --detectors "$GATES";                                                                           Check "confusable"
python scripts\s2_experiment.py --profile s4_main --out rev12_scale --robust scale --reps 5 --n-distractor 2 --max-agent-calls 5000 `
  --detectors "none,stpg,stpg_allow,judge_gate,unit,window,$GRP";                                 Check "scale"
python scripts\s2_experiment.py --profile s4_main --out rev12_launder --robust launder --reps 10 --n-distractor 2 `
  --detectors "none,stpg,stpg_allow,stpg_inherit,stpg_pdgonly,match_gate,attr_judge";             Check "launder"

# ---- 3) latency (R1-6): warm run with two passes (pass 2 = witness / embedding caches warm), then a cold run ----
Fresh @("rev12_latency","rev12_latency_cold")
python scripts\s2_experiment.py --profile s4_main --out rev12_latency --robust latency --reps 10 --n-distractor 2 `
  --detectors "stpg,stpg_pdgonly,match_gate,attr_judge,judge_gate" --passes 2;                    Check "latency warm"
Copy-Item results\rev12_latency_agent.db results\rev12_latency_cold_agent.db -Force
python scripts\s2_experiment.py --profile s4_main --out rev12_latency_cold --robust latency --reps 10 --n-distractor 2 `
  --detectors "stpg,attr_judge,judge_gate" --cold;                                                Check "latency cold"

# ---- 4) victim prompt variants (R1-1): same traces as the main run, new victim decisions ----
Fresh @("rev12_hardened","rev12_labeled")
python scripts\s2_experiment.py --profile s4_main --out rev12_hardened --n-benign 90 --n-distractor 2 --victim-prompt hardened `
  --detectors "none,stpg,stpg_allow";                                                             Check "hardened victim"
python scripts\s2_experiment.py --profile s4_main --out rev12_labeled --n-benign 90 --n-distractor 2 --victim-prompt hardened --victim-labels `
  --detectors "stpg,none,stpg_allow";                                                             Check "labeled victim"

# ---- 5) second model family (R3): Llama as judge / witness / attribution judge, and as victim ----
if (-not $SkipLlama) {
  Fresh @("rev12_main_ljudge","rev12_holdout_ljudge","rev12_lvictim")
  Copy-Item results\rev10_main_agent.db    results\rev12_main_ljudge_agent.db    -Force
  Copy-Item results\rev10_holdout_agent.db results\rev12_holdout_ljudge_agent.db -Force
  python scripts\s2_experiment.py --profile s4_main --out rev12_main_ljudge --n-benign 90 --n-distractor 2 --judge-model $Llama `
    --detectors "stpg,stpg_allow,attr_judge,judge_gate";                                          Check "llama judge main"
  python scripts\s2_experiment.py --profile s4_main --out rev12_holdout_ljudge --holdout --reps 4 --n-distractor 2 --judge-model $Llama `
    --detectors "stpg,attr_judge";                                                                Check "llama judge holdout"
  python scripts\s2_experiment.py --profile s4_main --out rev12_lvictim --model $Llama --n-benign 90 --n-distractor 2 --max-agent-calls 5000 `
    --detectors "$GATES";                                                                         Check "llama victim"
}
python scripts\analysis\rev12_report.py
# 결과: results\rev12_*.db (+ *_summary.json, *_agent.db). 이 단계가 끝나면 커널·프롬프트·임계값은 동결되며 RUN_rev12c.ps1 (unseen set) 로 넘어간다.
