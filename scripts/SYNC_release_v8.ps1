# Sync the v8 (kernel v3.5) changes into github_release\ (run from C:\paper\Applied_Code_202610 after RUN_rev12e.ps1 finished).
$ErrorActionPreference = "Stop"
$dst = "github_release"
robocopy stpg "$dst\stpg" /E /XD __pycache__ | Out-Null
robocopy scripts "$dst\scripts" /E /XD __pycache__ | Out-Null
New-Item -ItemType Directory -Force -Path "$dst\results\v35", "$dst\paper\figs" | Out-Null
Copy-Item results\v35\*.db, results\v35\*_summary.json, results\v35\rederive_log.json, results\v35\rev12_report.txt "$dst\results\v35\" -Force
Remove-Item "$dst\results\v35\*_agent.db" -ErrorAction SilentlyContinue      # victim caches are already in results\ (rev11_rules_agent.db, rev12_confusable_agent.db)
Copy-Item paper_v8\main.tex, paper_v8\refs.bib, paper_v8\fig_*.tex "$dst\paper\" -Force
Copy-Item paper_v8\figs\*.pdf "$dst\paper\figs\" -Force
Copy-Item paper_v8\README.md "$dst\README.md" -Force
Copy-Item requirements.txt, requirements-lock.txt, requirements-cloud.txt, Dockerfile, PROJECT_STRUCTURE.txt "$dst\" -Force
python scripts\build_review_package_v8.py
Write-Host "synced. Next (in github_release): git add -A; git commit -m 'STPG v8: kernel v3.5 (identifier contract), run 5 re-derivation, sets A/F re-run'; git push; git tag -a v8-revision1 -m 'Tables of the revised manuscript (run 5)'; git push origin v8-revision1"
