# S0 로컬 모의 실험 실행 (Windows PowerShell)
# 사용: powershell -ExecutionPolicy Bypass -File scripts\run_s0.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path ".venv")) { python -m venv .venv }
.\.venv\Scripts\Activate.ps1
pip install --quiet -r requirements.txt

# Windows 로컬 디스크는 SQLite 잠금을 지원하므로 결과를 results\ 에 둔다
$env:STPG_RESULTS_DIR = Join-Path $root "results"
New-Item -ItemType Directory -Force -Path $env:STPG_RESULTS_DIR | Out-Null

Write-Host "== 무결성 테스트 ==" -ForegroundColor Cyan
python tests\test_pipeline.py

Write-Host "`n== 본 모의 실험 (s0_mock) ==" -ForegroundColor Cyan
python -c "import sys; sys.path.insert(0,'.'); from stpg.runner.experiment import run_experiment; run_experiment('s0_mock','s0_full')"

Write-Host "`n== 절제 실험 ==" -ForegroundColor Cyan
python -c "import sys; sys.path.insert(0,'.'); from stpg.runner.ablation import run_ablation; print(run_ablation('s0_mock','s0_ablation'))"

Write-Host "`n== 결과 보고 ==" -ForegroundColor Cyan
python scripts\report.py (Join-Path $env:STPG_RESULTS_DIR "s0_full.db")
