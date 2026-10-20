import sqlite3, collections, sys
h=sqlite3.connect(sys.argv[1]); h.row_factory=sqlite3.Row
order=["mixed","mixed_order","crossref","value_poison","trusted_mention","untrusted_mention","missing_shard","missing_bg","missing_rule","offtask","same_record","untrusted_bundle","same_dest_both","ambiguous_key","deep_reference"]
tot=collections.Counter()
print("structure | lineage evaluations | verified target | raw-true rejected (unsupported) | negative (mapping/mention/prohibited/none)")
for s in order:
    c=collections.Counter()
    for r in h.execute("SELECT witness FROM results WHERE structure=? AND detector='stpg' AND cf!=''",(s,)):
        for x in filter(None, r[0].split(";")):
            lab=x.split(":")[-1]
            c["target" if lab=="target" else ("unsupported" if lab=="unsupported" else "neg")]+=1
    n=sum(c.values()); tot.update(c)
    print(f"{s:18s} {n:4d} {c['target']:4d} {c['unsupported']:4d} {c['neg']:4d}")
print("TOTAL", sum(tot.values()), dict(tot))
