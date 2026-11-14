"""rev12 stage A summary: descriptive notices (R2-2) under witness prompts w2 / w3, and the degraded-rule set under w3.
Usage: python scripts/analysis/rev12_stage_a.py   (reads results/rev12_notice_w2.db, rev12_notice_w3.db, rev12_rules_w3.db, rev11_rules.db)"""
import sqlite3, os, json, collections, sys
R = os.environ.get("STPG_RESULTS_DIR", "results")


def rows(db, where="1=1"):
    p = os.path.join(R, db)
    if not os.path.exists(p):
        print(f"(missing {db})"); return []
    c = sqlite3.connect(p); c.row_factory = sqlite3.Row
    return [dict(r) for r in c.execute(f"SELECT * FROM results WHERE {where}")]


def cell(rs, det, structure):
    sub = [r for r in rs if r["detector"] == det and r["structure"] == structure and r["cf"]]
    return f"{sum(r['sink_allowed'] == 1 for r in sub)}/{len(sub)}"


for db, dets in (("rev12_notice_w2.db", ["none", "stpg", "stpg_allow", "match_gate", "attr_judge"]), ("rev12_notice_w3.db", ["stpg", "stpg_allow"])):
    rs = rows(db)
    if not rs: continue
    print(f"\n=== {db}: counterfactual call to A with a trusted descriptive notice only; cell = allowed / n (false authorization) ===")
    structs = sorted({r["structure"] for r in rs})
    print(f"{'structure':24s}" + "".join(f"{d:>14s}" for d in dets))
    for st in structs:
        print(f"{st:24s}" + "".join(f"{cell(rs, d, st):>14s}" for d in dets))
    ev = collections.Counter((r["structure"], r["evidence"]) for r in rs if r["detector"] == "stpg" and r["cf"])
    print("  STPG branch:", dict(ev))
    act = collections.Counter((r["structure"], r["routed_external"]) for r in rs if r["detector"] == "none" and not r["cf"])
    if act: print("  victim routed externally on the notice alone:", {k: v for k, v in act.items() if k[1] == 1})

rs3 = rows("rev12_rules_w3.db"); rs2 = rows("rev11_rules.db")
if rs3:
    print("\n=== degraded approved rules (set A): STPG passed / n on the counterfactual call to A, w2 (rev11, kernel v3.3) vs w3 (kernel v3.4) ===")
    structs = sorted({r["structure"] for r in rs3})
    print(f"{'variant':24s}{'w2 stpg':>12s}{'w3 stpg':>12s}{'w2 allow':>12s}{'w3 allow':>12s}")
    for st in structs:
        print(f"{st:24s}{cell(rs2, 'stpg', st):>12s}{cell(rs3, 'stpg', st):>12s}{cell(rs2, 'stpg_allow', st):>12s}{cell(rs3, 'stpg_allow', st):>12s}")
    print("  w3 STPG branch:", dict(collections.Counter((r["structure"], r["evidence"]) for r in rs3 if r["detector"] == "stpg" and r["cf"])))
for f in ("rev12_notice_w2_summary.json", "rev12_notice_w3_summary.json", "rev12_rules_w3_summary.json"):
    p = os.path.join(R, f)
    if os.path.exists(p):
        j = json.load(open(p)); print(f, "kernel", j.get("kernel_version"), "witness", j.get("witness_version"), "judge", j.get("judge_model"))
