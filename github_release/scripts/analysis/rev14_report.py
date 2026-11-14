"""rev14 report (Round 2, run 7): second held-out set H2. STPG, witness agreement (stpg_dual) and the extended resolver
(stpg under STPG_RELATION_EXT=1, from rev14_unseen2_relext.db) on the same previously unseen formulations, nothing adapted.
Usage: STPG_RESULTS_DIR=results/v35 python scripts/analysis/rev14_report.py"""
import sqlite3, os, json, collections, sys, hashlib
R = os.environ.get("STPG_RESULTS_DIR", "results")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from stpg import config as C
from stpg.datagen.unseen2 import build_unseen2_specs, STRUCTURES, POLICY

def load(db, relabel=None):
    p = os.path.join(R, db)
    if not os.path.exists(p): print(f"(missing {db})"); return []
    c = sqlite3.connect(p); c.row_factory = sqlite3.Row
    rows = [dict(r) for r in c.execute("SELECT * FROM results")]
    if relabel:
        for r in rows: r["detector"] = relabel.get(r["detector"], r["detector"])
    return rows
def summary(db):
    p = os.path.join(R, db.replace(".db", "_summary.json")); return json.load(open(p)) if os.path.exists(p) else {}
def hdr(t): print("\n" + "=" * 8 + " " + t + " " + "=" * 8)

rs = load("rev14_unseen2.db") + [r for r in load("rev14_unseen2_relext.db", {"stpg": "stpg+relext", "stpg_dual": "stpg_dual+relext"}) if r["detector"].endswith("+relext")]
DETS = [d for d in ["stpg", "stpg_dual", "stpg+relext", "stpg_dual+relext"] if any(r["detector"] == d for r in rs)]
exp = {}
for sp in build_unseen2_specs(C.load_profile("s4_main"), reps=5):
    for d_, e_ in sp.expected.items(): exp[sp.run_id + "#cf:" + d_] = e_
E = lambda r: exp.get(r["run_id"], "block")

hdr("H2 second held-out set (run 7): decisions as specified / counterfactual calls")
print(f"{'structure':22s}{'specified':>10s}" + "".join(f"{d:>18s}" for d in DETS))
ok = collections.Counter(); tot = collections.Counter()
for s_ in STRUCTURES:
    line = f"{s_:22s}{','.join(f'{k}:{v}' for k, v in POLICY[s_].items()):>10s}"
    for d in DETS:
        sub = [r for r in rs if r["detector"] == d and r["cf"] and r["structure"] == s_]
        c = sum(((r["sink_allowed"] == 1) == (E(r) == "pass")) for r in sub); ok[d] += c; tot[d] += len(sub)
        line += f"{(str(c) + '/' + str(len(sub))) if sub else '-':>18s}"
    print(line)
print(f"{'all':32s}" + "".join(f"{str(ok[d]) + '/' + str(tot[d]):>18s}" for d in DETS))

hdr("H2: the two directions of error")
for d in DETS:
    sub = [r for r in rs if r["detector"] == d and r["cf"]]
    fb = collections.Counter(r["structure"] for r in sub if E(r) == "pass" and r["sink_allowed"] != 1)
    fa = collections.Counter(r["structure"] for r in sub if E(r) == "block" and r["sink_allowed"] == 1)
    print(f"  {d:18s} false blocks {sum(fb.values()):3d} {dict(fb)} | false authorizations {sum(fa.values()):3d} {dict(fa)}")

hdr("H2: semantic criterion (v01-v05) and relation resolution (v06-v12) separately")
for d in DETS:
    for name, group in (("semantic", STRUCTURES[:5]), ("relation", STRUCTURES[5:])):
        sub = [r for r in rs if r["detector"] == d and r["cf"] and r["structure"] in group]
        c = sum(((r["sink_allowed"] == 1) == (E(r) == "pass")) for r in sub)
        print(f"  {d:18s} {name:9s} {c}/{len(sub)}")

hdr("H2: actual victim calls decided as specified / routed external calls")
for d in DETS:
    sub = [r for r in rs if r["detector"] == d and not r["cf"] and r["routed_external"]]
    c = sum(((r["sink_allowed"] == 1) == (exp.get(r["run_id"].split("#")[0] + "#cf:" + r["destination"], "block") == "pass")) for r in sub)
    print(f"  {d:18s} {c}/{len(sub)}")

hdr("H2: second-witness evaluations (logical, before cache) / API requests / disagreements")
for db in ("rev14_unseen2.db", "rev14_unseen2_relext.db"):
    s = summary(db).get("per_condition", {})
    for det in ("stpg_dual",):
        if det in s:
            print(f"  {db:26s} {det}: evaluations {s[det].get('witness2_evals')} API requests {s[det].get('witness2_calls')} disagreements {s[det].get('witness2_disagree')}")
    cf2 = [r for r in load(db) if r["detector"] == "stpg_dual"]
    if cf2:
        print(f"  {db:26s} rows with a second-witness verdict: counterfactual {sum('|2|' in (r['witness'] or '') for r in cf2 if r['cf'])}, actual {sum('|2|' in (r['witness'] or '') for r in cf2 if not r['cf'])}")

hdr("provenance of the run")
for db in ("rev14_unseen2.db", "rev14_unseen2_relext.db"):
    s = summary(db)
    if s: print(f"  {db}: kernel {s.get('kernel_version')} witness {s.get('witness_version')} relation_ext {s.get('relation_ext')} second_witness {s.get('second_witness')} freeze {str(s.get('rev14_freeze_sha'))[:16]} phrasings {str(s.get('rev14_phrasings_sha'))[:16]}")
for f in ("rev14_freeze.json", "rev14_phrasings_lock.json", "rev14_unseen2_phrasings.json"):
    p = os.path.join(R, f)
    if os.path.exists(p): print(f"  {f}: sha256 {hashlib.sha256(open(p, 'rb').read()).hexdigest()[:16]}")
