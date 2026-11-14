"""Rebuild review_package/STPG_review_package_v6.zip from the working tree and refresh its SHA-256 manifest.

Usage (from C:\paper\Applied_Code_202610):  python scripts\build_review_package.py
The file list is taken from the existing zip; every listed file is re-read from disk, so edit the
source files (paper_v6/*.tex, scripts/analysis/*.py, results/*.db, ...) and run this script.
To add a file, append its repo-relative path to EXTRA below.
"""
import zipfile, hashlib, io, os, datetime
SRC = "review_package/STPG_review_package_v6.zip"
MAN = "review_package/VERSION_MANIFEST_v6.txt"
EXTRA = ["paper_v6/fig1_threat.tex","paper_v6/fig2_overview.tex","paper_v6/fig3_kernel.tex","stpg/datagen/robust.py","scripts/gen_paraphrases.py","scripts/test_robust_offline.py","scripts/RUN_rev11.ps1","scripts/RUN_rev11b.ps1","scripts/analysis/rev_robust.py","scripts/analysis/fig_robust.py","scripts/analysis/fig_judgeswap.py","paper_v6/figs/fig_robust.pdf","paper_v6/figs/fig_judgeswap.pdf","results/rev11_paraphrases.json"] + [f"results/{f}{s}" for f in ("rev11_rules","rev11_multi","rev11b_main_fjudge","rev11b_holdout_fjudge","rev11b_flash") for s in (".db","_summary.json","_agent.db")]  # e.g. "paper_v6/figs/fig_new.pdf"
zin = zipfile.ZipFile(SRC)
DROP = {"paper_v6/fig_threat.tex","paper_v6/fig_overview.tex","paper_v6/fig_kernel.tex"}
names = [n for n in zin.namelist() if not n.endswith("/") and n != "VERSION_MANIFEST_v6.txt" and n not in DROP] + EXTRA
files = {}
for n in dict.fromkeys(names):
    if os.path.exists(n):
        files[n] = open(n, "rb").read()
    else:
        files[n] = zin.read(n); print("kept from old zip (missing on disk):", n)
head = open(MAN, encoding="utf-8").read().split("SHA-256 manifest:")[0]
head = head.replace(head.splitlines()[0], head.splitlines()[0].split(" — built")[0] + " — built " + datetime.date.today().isoformat())
man = head + "SHA-256 manifest:\n" + "".join(f"{hashlib.sha256(files[n]).hexdigest()}  {n}\n" for n in sorted(files))
files["VERSION_MANIFEST_v6.txt"] = man.encode("utf-8")
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    for n in sorted(files): z.writestr(n, files[n])
open(SRC, "wb").write(buf.getvalue()); open(MAN, "w", encoding="utf-8").write(man)
if os.path.isdir("github_release"): open("github_release/VERSION_MANIFEST.txt", "w", encoding="utf-8").write(man)
print(f"rebuilt {SRC}: {len(files)} files, {len(buf.getvalue())//1024} KB")
