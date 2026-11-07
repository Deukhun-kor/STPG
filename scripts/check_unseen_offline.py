"""Read-only diagnostic of the frozen-evaluation phrasings (no tuning): builds the unseen specs from
results/rev12_unseen_phrasings.json and reports, per domain, how many LLM-written binding / sheet records the frozen
relation pattern M resolves, and the mock-witness decisions per structure. The counts are reported in the paper as is."""
import sys, os, re, collections, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stpg import config as C
from stpg.gateway import binding as B
from stpg.datagen.unseen import build_unseen_specs, load_phrasings, UNSEEN_DOMAINS, REF

P = load_phrasings()
print("phrasings model:", P.get("model"))
for dom in UNSEEN_DOMAINS:
    ph = P["domains"][dom]; L, K = REF[dom]
    sheets = [s.replace("{K}", K).replace("{A}", "PARTNER-EXT-123") for s in ph["sheets"]]
    binds = [t[1].replace("{L}", L).replace("{K}", K) for t in ph["attack_triples"]]
    addrs = [t[2].replace("{K}", K).replace("{SINK}", "SYNTH-AUDIT-SINK-0001") for t in ph["attack_triples"]]
    ok_s = sum(bool(B._values_of(K, [{"text": s}])) for s in sheets)
    ok_b = sum(bool(B._values_of(L, [{"text": b}])) for b in binds)
    ok_a = sum(bool(B._values_of(K, [{"text": a}])) for a in addrs)
    print(f"{dom:12s} sheets resolved {ok_s}/{len(sheets)} | binding records resolved {ok_b}/{len(binds)} | address records resolved {ok_a}/{len(addrs)}")
    for s in sheets: print("   sheet:", "OK " if B._values_of(K, [{"text": s}]) else "-- ", s)
    for b in binds:  print("   bind :", "OK " if B._values_of(L, [{"text": b}]) else "-- ", b)
    for a in addrs:  print("   addr :", "OK " if B._values_of(K, [{"text": a}]) else "-- ", a)
specs = build_unseen_specs(C.load_profile("s4_main"), reps=5, phrasings=P)
print(f"\n{len(specs)} traces, {sum(len(s.cf_destinations) for s in specs)} counterfactual calls, structures:",
      sorted(collections.Counter(s.structure for s in specs).items()))
try:
    from test_rev12_offline import gws, table
    print("\nmock-witness decisions (diagnostic only):")
    table(specs, ["stpg", "allow", "match"])
except Exception as e:
    print("mock table skipped:", e)
