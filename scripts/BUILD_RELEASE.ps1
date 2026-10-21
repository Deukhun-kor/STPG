# Assemble github_release\ from the working tree (run from C:\paper\Applied_Code_202610).
$ErrorActionPreference = "Stop"
$dst = "github_release"
New-Item -ItemType Directory -Force -Path $dst, "$dst\results", "$dst\paper\figs", "$dst\scripts" | Out-Null
robocopy stpg "$dst\stpg" /E /XD __pycache__ | Out-Null
robocopy tests "$dst\tests" /E /XD __pycache__ | Out-Null
robocopy scripts "$dst\scripts" /E /XD __pycache__ analysis | Out-Null
robocopy scripts\analysis "$dst\scripts\analysis" /E /XD __pycache__ | Out-Null
Copy-Item results\rev10_*.db, results\rev10_*_summary.json, results\rev11*.db, results\rev11*_summary.json, results\rev11_paraphrases.json, results\rev3_metadata_features.csv "$dst\results\" -Force
Copy-Item paper_v6\main.tex, paper_v6\refs.bib, paper_v6\fig_*.tex "$dst\paper\" -Force
Copy-Item paper_v6\figs\*.pdf "$dst\paper\figs\" -Force
Copy-Item requirements.txt, requirements-lock.txt, requirements-cloud.txt, Dockerfile, PROJECT_STRUCTURE.txt "$dst\" -Force
Copy-Item review_package\VERSION_MANIFEST_v6.txt "$dst\VERSION_MANIFEST.txt" -Force
Write-Host "github_release assembled. Next: add LICENSE, review README.md, then run github_release\GIT_PUBLISH.ps1"
