"""Kernel v3.5 re-derivation of the run-4 result DBs (pre-submission review, M1).

v3.5 adds one pre-check to the kernel: a destination that is not a single endpoint identifier (whitespace, quotes, or
brackets inside the string after the wrapping is stripped) is blocked as 'malformed-destination' before any other
step, and whitespace is no longer an identifier separator. The pre-check depends on the destination string alone and
precedes every model call, so for every call whose destination is well-formed the v3.5 decision is the run-4 decision
(scripts/check_v35_equivalence.py verifies that the matcher agrees on every text/token pair of every set except the
space-written rules of set A, which are re-run), and for every call whose destination is malformed the v3.5 decision
is BLOCK for every condition that applies the kernel pre-checks (all gates except 'none' and the ephemeral-taint
proxy, which have no gate input). This script copies results/rev12_*.db to results/v35/ and applies exactly that,
logging every changed row to results/v35/rederive_log.json. Sets A and F are re-run instead (RUN_rev12e.ps1).

Usage: python scripts\\analysis\\rev12_v35_rederive.py [--src results] [--dst results\\v35]
"""
import sys, os, glob, json, shutil, sqlite3, argparse, collections, datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from stpg.gateway import binding as B, gate as G

NO_GATE = {"none", "taint"}                     # conditions without a gate input: the pre-check cannot apply
RERUN = {"rev12_rules", "rev12_rules_w3", "rev12_confusable"}   # superseded by the v3.5 re-runs of sets A and F

ap = argparse.ArgumentParser()
ap.add_argument("--src", default=os.environ.get("STPG_RESULTS_DIR", "results"))
ap.add_argument("--dst", default=None)
a = ap.parse_args()
dst = a.dst or os.path.join(a.src, "v35")
os.makedirs(dst, exist_ok=True)
log = {"kernel": G.KERNEL_VERSION, "date": datetime.date.today().isoformat(), "dbs": {}}
for p in sorted(glob.glob(os.path.join(a.src, "rev12_*"))):
    name = os.path.basename(p)
    stem = name.split(".")[0].replace("_agent", "").replace("_summary", "").replace("_stats", "")
    if stem in RERUN:
        continue
    q = os.path.join(dst, name)
    shutil.copy2(p, q)
    if not name.endswith(".db") or name.endswith("_agent.db"):
        continue
    db = sqlite3.connect(q)
    cols = [c[1] for c in db.execute("PRAGMA table_info(results)")]
    rows = db.execute("SELECT rowid, detector, destination, is_attack, routed_external, sink_allowed, evidence FROM results").fetchall()
    changed = []; flipped = collections.Counter(); relabelled = collections.Counter()
    for rowid, det, dest, is_attack, routed, allowed, ev in rows:
        if not dest or det in NO_GATE or not B.is_malformed(dest):
            continue
        # v3.5: BLOCK before any branch; the harness fields follow s2_experiment._gate_rows for sink_allowed=False
        upd = {"sink_allowed": 0, "evidence": "malformed-destination", "attack_success": 0,
               "false_block": int((not is_attack) and bool(routed)), "utility_ok": 0, "n_bound": 0, "witness": "",
               "roles": "{}", "witness_raw": ""}
        upd = {k: v for k, v in upd.items() if k in cols}
        db.execute("UPDATE results SET " + ", ".join(f"{k}=?" for k in upd) + " WHERE rowid=?", list(upd.values()) + [rowid])
        (flipped if allowed == 1 else relabelled)[det] += 1
        changed.append({"rowid": rowid, "detector": det, "destination": dest, "was_allowed": allowed, "was_evidence": ev})
    db.commit(); db.close()
    sp = q.replace(".db", "_summary.json")
    if os.path.exists(sp):
        s = json.load(open(sp)); s["kernel_version_run4"] = s.get("kernel_version"); s["kernel_version"] = G.KERNEL_VERSION
        s["v35_rederived"] = {"rows_changed": len(changed), "pass_to_block": dict(flipped), "block_relabelled": dict(relabelled)}
        json.dump(s, open(sp, "w"), indent=2)
    log["dbs"][name] = {"rows_changed": len(changed), "pass_to_block": dict(flipped), "block_relabelled": dict(relabelled),
                        "destinations": sorted({c["destination"] for c in changed}), "rows": changed}
    print(f"{name:34s} changed {len(changed):3d}  pass->block {dict(flipped)}  relabelled {dict(relabelled)}")
json.dump(log, open(os.path.join(dst, "rederive_log.json"), "w"), indent=2, ensure_ascii=False)
print("written", os.path.join(dst, "rederive_log.json"))
