# Sync the v9 (Round-2 revision, run 6 witness agreement) changes into github_release\ (run from C:\paper\Applied_Code_202610 after RUN_rev13.ps1 finished).
$ErrorActionPreference = "Stop"
$dst = "github_release"
robocopy stpg "$dst\stpg" /E /XD __pycache__ | Out-Null
robocopy scripts "$dst\scripts" /E /XD __pycache__ | Out-Null
New-Item -ItemType Directory -Force -Path "$dst\results\v35", "$dst\paper\figs" | Out-Null
Copy-Item results\v35\rev13_*.db, results\v35\rev13_*_summary.json, results\v35\rev13_report.txt "$dst\results\v35\" -Force
Copy-Item results\v35\rev14_*.db, results\v35\rev14_*_summary.json, results\v35\rev14_report.txt, results\v35\rev14_freeze.json, results\v35\rev14_unseen2_phrasings.json, results\v35\rev14_phrasings_lock.json, results\v35\rev14_phrasings_review.txt "$dst\results\v35\" -Force
Remove-Item "$dst\results\v35\rev13_*_agent.db" -ErrorAction SilentlyContinue      # victim caches are copies of the run-5 caches already in results\v35
Remove-Item "$dst\results\v35\rev14_unseen2_relext_agent.db" -ErrorAction SilentlyContinue   # copy of rev14_unseen2_agent.db (kept)
Remove-Item "$dst\results\v35\rev14_gen_debug_*.json" -ErrorAction SilentlyContinue
Copy-Item paper_v9\main.tex, paper_v9\supplementary.tex, paper_v9\refs.bib, paper_v9\fig*.tex "$dst\paper\" -Force
Copy-Item paper_v9\figs\*.pdf "$dst\paper\figs\" -Force
Copy-Item paper_v9\README.md "$dst\README.md" -Force
Copy-Item requirements.txt, requirements-lock.txt, requirements-cloud.txt, Dockerfile, PROJECT_STRUCTURE.txt "$dst\" -Force -ErrorAction SilentlyContinue
python scripts\build_review_package_v9.py
Write-Host "synced. Next (in github_release): git add -A; git commit -m 'STPG v9: run 6 witness agreement and run 7 second held-out set (Round-2 revision)'; git push; git tag -a v9-revision2 -m 'Round-2 revision: runs 6 and 7 added'; git push origin v9-revision2"
