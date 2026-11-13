"""rev13 report (Round 2): witness agreement (stpg_dual) against STPG on set E, the frozen set, the main run and the
challenge set. Usage: STPG_RESULTS_DIR=results/v35 python scripts/analysis/rev13_report.py"""
import sqlite3, os, json, collections, sys
R = os.environ.get("STPG_RESULTS_DIR", "results")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from stpg import config as C

def load(db):
    p = os.path.join(R, db)
    if not os.path.exists(p): print(f"\n(missing {db})"); return []
    c = sqlite3.connect(p); c.row_factory = sqlite3.Row
    return [dict(r) for r in c.execute("SELECT * FROM results")]
def summary(db):
    p = os.path.join(R, db.replace(".db", "_summary.json")); return json.load(open(p)) if os.path.exists(p) else {}
def hdr(t): print("\n" + "=" * 8 + " " + t + " " + "=" * 8)
DETS = ["stpg", "stpg_dual"]

def by_structure(rs, dets, expected, label, note=""):
    hdr(label)
    structs = []
    for r in rs:
        if r["cf"] and r["structure"] not in structs: structs.append(r["structure"])
    print(f"{'structure':30s}" + "".join(f"{d:>14s}" for d in dets) + "   (decisions as specified / counterfactual calls)")
    tot = collections.Counter(); ok = collections.Counter()
    for s_ in structs:
        line = f"{s_:30s}"
        for d in dets:
            sub = [r for r in rs if r["detector"] == d and r["cf"] and r["structure"] == s_]
            c = sum(((r["sink_allowed"] == 1) == (expected(r) == "pass")) for r in sub); ok[d] += c; tot[d] += len(sub)
            line += f"{(str(c)+'/'+str(len(sub))) if sub else '-':>14s}"
        print(line)
    print(f"{'all':30s}" + "".join(f"{str(ok[d])+'/'+str(tot[d]):>14s}" for d in dets))
    if note: print(" ", note)
    return ok, tot

def two_directions(rs, dets, expected, label):
    """false blocks (specified pass, blocked) and false authorizations (specified block, allowed)"""
    hdr(label)
    for d in dets:
        sub = [r for r in rs if r["detector"] == d and r["cf"]]
        fb = sum(1 for r in sub if expected(r) == "pass" and r["sink_allowed"] != 1)
        fa = sum(1 for r in sub if expected(r) == "block" and r["sink_allowed"] == 1)
        fa_by = collections.Counter(r["structure"] for r in sub if expected(r) == "block" and r["sink_allowed"] == 1)
        fb_by = collections.Counter(r["structure"] for r in sub if expected(r) == "pass" and r["sink_allowed"] != 1)
        print(f"  {d:12s} false blocks {fb:3d}  false authorizations {fa:3d}   | FB by structure {dict(fb_by)} | FA by structure {dict(fa_by)}")

# ---- set E: descriptive notices (every counterfactual call to the partner is specified BLOCK) ----
rs = load("rev13_notice.db")
if rs:
    by_structure(rs, DETS, lambda r: "block", "set E descriptive notices, w3: STPG vs witness agreement (blocked as specified / n)")
    s = summary("rev13_notice.db"); print("  witness2 calls", s.get("per_condition", {}).get("stpg_dual", {}).get("witness2_calls"), "disagreements", s.get("per_condition", {}).get("stpg_dual", {}).get("witness2_disagree"))
    vict = [r for r in rs if r["detector"] in DETS and not r["cf"] and r["routed_external"]]
    for d in DETS:
        sub = [r for r in vict if r["detector"] == d]
        print(f"  actual victim calls to the partner: {d} allowed {sum(r['sink_allowed']==1 for r in sub)}/{len(sub)}")

# ---- frozen evaluation set ----
rs = load("rev13_unseen.db")
if rs:
    from stpg.datagen.unseen import build_unseen_specs
    exp = {}
    for sp in build_unseen_specs(C.load_profile("s4_main"), reps=5):
        for d_, e_ in sp.expected.items(): exp[sp.run_id + "#cf:" + d_] = e_
    E = lambda r: exp.get(r["run_id"], "block")
    by_structure(rs, DETS, E, "FROZEN EVALUATION SET: STPG vs witness agreement (nothing re-tuned)")
    two_directions(rs, DETS, E, "frozen set: the two directions of error (R1 #2)")
    hdr("frozen set: actual victim calls decided as specified / routed external calls")
    for d in DETS:
        sub = [r for r in rs if r["detector"] == d and not r["cf"] and r["routed_external"]]
        ok = sum(((r["sink_allowed"] == 1) == (exp.get(r["run_id"].split("#")[0] + "#cf:" + r["destination"], "block") == "pass")) for r in sub)
        print(f"  {d:12s} {ok}/{len(sub)}")

# ---- main run ----
rs = load("rev13_main.db")
if rs:
    hdr("main run: STPG vs witness agreement")
    for d in DETS:
        sub = [r for r in rs if r["detector"] == d and not r["cf"]]
        att = [r for r in sub if r["is_attack"] and r["routed_external"]]
        apr = [r for r in sub if r["benign_subtype"] == "legit_external" and r["routed_external"]]
        ev = collections.Counter(r["evidence"] for r in apr)
        print(f"  {d:12s} attacks blocked {sum(r['sink_allowed']==0 for r in att)}/{len(att)} | approved passed {sum(r['sink_allowed']==1 for r in apr)}/{len(apr)} | approved evidence {dict(ev)}")
    s = summary("rev13_main.db"); print("  witness2 calls", s.get("per_condition", {}).get("stpg_dual", {}).get("witness2_calls"), "disagreements", s.get("per_condition", {}).get("stpg_dual", {}).get("witness2_disagree"))

# ---- challenge set ----
rs = load("rev13_holdout.db")
if rs:
    from stpg.datagen.holdout import build_holdout_specs
    exph = {}
    for sp in build_holdout_specs(C.load_profile("s4_main"), n_distractor=2, reps=4):
        for d_, e_ in sp.expected.items(): exph[sp.run_id + "#cf:" + d_] = e_
    by_structure(rs, DETS, lambda r: exph.get(r["run_id"], "block"), "policy challenge set: STPG vs witness agreement")
    two_directions(rs, DETS, lambda r: exph.get(r["run_id"], "block"), "challenge set: the two directions of error")
print("\nkernel/witness:", summary("rev13_notice.db").get("kernel_version"), summary("rev13_notice.db").get("witness_version"), "second witness:", os.environ.get("STPG_SECOND_WITNESS", "meta/llama-4-maverick-17b-128e-instruct-maas"))
