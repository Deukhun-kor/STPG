"""Build review_package/STPG_review_package_v8.zip (Round-1 revision, final) from github_release/ plus the paper_v8 files, and
write the SHA-256 manifest review_package/VERSION_MANIFEST_v8.txt (also copied to github_release/VERSION_MANIFEST.txt).
Usage (from C:\\paper\\Applied_Code_202610):  python scripts\\build_review_package_v8.py"""
import zipfile, hashlib, os, datetime, io
SRC = "github_release"; OUT = "review_package/STPG_review_package_v8.zip"; MAN = "review_package/VERSION_MANIFEST_v8.txt"
SKIP = {"GIT_PUBLISH.ps1", "VERSION_MANIFEST.txt"}
files = {}
for root, dirs, fs in os.walk(SRC):
    dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git")]
    for f in fs:
        if f in SKIP or f.endswith(".pyc"): continue
        p = os.path.join(root, f); files[os.path.relpath(p, SRC).replace(os.sep, "/")] = open(p, "rb").read()
for f in ("STPG_v8_MDPI_template_preview.pdf", "STPG_v8_highlighted.pdf", "STPG_v8_supplementary.pdf", "response_to_reviewers.pdf", "cover_letter_revision1.pdf"):
    p = os.path.join("paper_v8", f)
    if os.path.exists(p): files["paper/" + f] = open(p, "rb").read()
head = (f"STPG review package v8 (Round-1 revision, final) — built {datetime.date.today().isoformat()}\n"
        "Kernel v3.5 (identifier contract, malformed-destination pre-check), witness prompt w3; every table of the revised manuscript reports run 5\n"
        "(results/v35/: run-4 logs re-derived under v3.5 by scripts/analysis/rev12_v35_rederive.py, log rederive_log.json; sets A and F re-run).\n"
        "Contents: stpg/ (gateway, generators, backend), scripts/ (runner, RUN_rev12*.ps1, offline checks incl. check_v35_equivalence.py, analysis/),\n"
        "results/ (rev10-rev12 databases, results/v35 re-derived databases, cached victim decisions, model-written phrasings),\n"
        "paper/ (main.tex, figures, clean and highlighted PDFs, response to reviewers), tests/.\n\n")
man = head + "SHA-256 manifest:\n" + "".join(f"{hashlib.sha256(files[n]).hexdigest()}  {n}\n" for n in sorted(files))
files["VERSION_MANIFEST_v8.txt"] = man.encode("utf-8")
os.makedirs("review_package", exist_ok=True)
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    for n in sorted(files): z.writestr(n, files[n])
open(OUT, "wb").write(buf.getvalue()); open(MAN, "w", encoding="utf-8").write(man)
open(os.path.join(SRC, "VERSION_MANIFEST.txt"), "w", encoding="utf-8").write(man)
print(f"built {OUT}: {len(files)} files, {len(buf.getvalue())//1024//1024} MB")
