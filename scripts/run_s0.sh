#!/usr/bin/env bash
# S0 로컬 모의 실험 실행 (Linux/Mac/WSL)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install --quiet -r requirements.txt
export STPG_RESULTS_DIR="${STPG_RESULTS_DIR:-$ROOT/results}"
mkdir -p "$STPG_RESULTS_DIR"
echo "== 무결성 테스트 =="; python tests/test_pipeline.py
echo "== 본 모의 실험 =="; python -c "import sys;sys.path.insert(0,'.');from stpg.runner.experiment import run_experiment;run_experiment('s0_mock','s0_full')"
echo "== 절제 실험 =="; python -c "import sys;sys.path.insert(0,'.');from stpg.runner.ablation import run_ablation;print(run_ablation('s0_mock','s0_ablation'))"
echo "== 결과 보고 =="; python scripts/report.py "$STPG_RESULTS_DIR/s0_full.db"
