"""Build review_package/STPG_review_package_v9.zip (Round-1 revision, final) from github_release/ plus the paper_v9 files, and
write the SHA-256 manifest review_package/VERSION_MANIFEST_v9.txt (also copied to github_release/VERSION_MANIFEST.txt).
Usage (from C:\\paper\\Applied_Code_202610):  python scripts\\build_review_package_v9.py"""
import zipfile, hashlib, os, datetime, io
SRC = "github_release"; OUT = "review_package/STPG_review_package_v9.zip"; MAN = "review_package/VERSION_MANIFEST_v9.txt"
SKIP = {"GIT_PUBLISH.ps1", "VERSION_MANIFEST.txt"}
files = {}
for root, dirs, fs in os.walk(SRC):
    dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git")]
    for f in fs:
        if f in SKIP or f.endswith(".pyc"): continue
        p = os.path.join(root, f); files[os.path.relpath(p, SRC).replace(os.sep, "/")] = open(p, "rb").read()
for f in ("STPG_v9_MDPI_template_preview.pdf", "STPG_v9_highlighted.pdf", "STPG_v9_supplementary.pdf", "response_to_reviewers_r2.pdf", "cover_letter_revision2.pdf"):
    p = os.path.join("paper_v9", f)
    if os.path.exists(p): files["paper/" + f] = open(p, "rb").read()
head = (f"STPG review package v9 (Round-2 revision) — built {datetime.date.today().isoformat()}\n"
        "Kernel v3.5, witness prompt w3, unchanged from revision 1 (run 5, results/v35/). Round 2 adds run 6 = witness agreement (stpg_dual,\n"
        "second witness Llama 4 Maverick under the same prompt): results/v35/rev13_{notice,unseen,main,holdout}.db, rev13_report.txt, and run 7 = second held-out set H2\n"
        "(results/v35/rev14_unseen2.db, rev14_unseen2_relext.db, rev14_freeze.json, rev14_unseen2_phrasings.json, rev14_phrasings_lock.json, rev14_report.txt).\n"
        "Contents: stpg/ (gateway, generators, backend), scripts/ (runner, RUN_rev12*.ps1, RUN_rev13.ps1, RUN_rev14.ps1, freeze/gen/review scripts of run 7, offline checks incl. test_rev14_offline.py, analysis/),\n"
        "results/ (rev10-rev14 databases, results/v35 re-derived databases, cached victim decisions, model-written phrasings),\n"
        "paper/ (main.tex, figures, clean and highlighted PDFs, response to reviewers), tests/.\n\n")
man = head + "SHA-256 manifest:\n" + "".join(f"{hashlib.sha256(files[n]).hexdigest()}  {n}\n" for n in sorted(files))
files["VERSION_MANIFEST_v9.txt"] = man.encode("utf-8")
os.makedirs("review_package", exist_ok=True)
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    for n in sorted(files): z.writestr(n, files[n])
open(OUT, "wb").write(buf.getvalue()); open(MAN, "w", encoding="utf-8").write(man)
open(os.path.join(SRC, "VERSION_MANIFEST.txt"), "w", encoding="utf-8").write(man)
print(f"built {OUT}: {len(files)} files, {len(buf.getvalue())//1024//1024} MB")
