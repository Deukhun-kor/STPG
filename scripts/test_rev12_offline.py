"""rev12 offline check (no model calls): kernel v3.4 on the new sets with a keyword mock scorer / witness.
Prints, per set and variant, the decision of each condition on the counterfactual destinations and compares with the
specification. Run: python scripts\\test_rev12_offline.py"""
import sys, os, re, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stpg import config as C
from stpg.datagen import robust2 as R2
from stpg.datagen.holdout import build_holdout_specs
from stpg.datagen.realistic import build_realistic_specs
from stpg.storage.sqlite_store import SqliteStore
from stpg.gateway.stpg import STPGGateway
from stpg.gateway import gate as G, binding as B
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from offline_common import KW, _ctx   # noqa: E402  (mock scorer / witness, ctx helper)


def run(sp, gw, dest, summarizer=None):
    store = SqliteStore(); store.reset()
    for r in sp.ingest_records:
        prov = gw.on_write({k: v for k, v in r.items() if k not in ("shard", "kind")},
                           _ctx(r["_writer"], r["_session"], sp.run_id, r["_origin"], r.get("_origin_ref")))
        if r.get("_drop_provenance"): prov = None
        store.write_record(r, prov)
    if getattr(sp, "launder", None):
        recs1, rd1 = gw.on_read(store.read_records(sp.domain), _ctx("sa-agent-ops", "s1", sp.run_id, "n/a"), store)
        note = {"record_id": sp.run_id + "-note", "domain": sp.domain, "hide_location": "ticket_body",
                "text": f"[{sp.domain}] handoff note (operations): " + summarizer(recs1)}
        nctx = _ctx("sa-agent-ops", "s2", sp.run_id, "/ops/internal"); nctx.read_min_trust = rd1.get("read_min_trust")
        store.write_record(note, gw.on_write(dict(note), nctx))
        if sp.launder == "compacted": store.delete_records(sp.launder_remove)
    recs = store.read_records(sp.domain)
    recs, fl = gw.on_read(recs, _ctx("sa-agent-ops", "trig", sp.run_id, "n/a"), store)
    ok, _, d = gw.on_sink("/route", {"destination": dest}, _ctx("sa-agent-ops", "trig", sp.run_id, "n/a"), recs, store, flag=fl)
    return ok, d["evidence"], d


def mock_summarizer(recs):
    """신뢰 에이전트의 요약을 흉내: 외부 목적지로의 전송 규칙이 있으면 그 문장을 한 줄로 다시 쓴다."""
    txt = " ".join(r["text"] for r in recs)
    m = re.search(r"(SYNTH-AUDIT-SINK-\d+|PARTNER-EXT-\d+)", txt)
    return f"finalized reports for this domain are forwarded to {m.group(1)}." if m else "no standing arrangement recorded."


cfg = C.load_profile("s4_main")
mk = lambda **kw: STPGGateway(KW(), 0.6, 1, **kw)
gws = {"stpg": mk(), "allow": mk(gate_mode="attributed-allow"), "tdo": mk(gate_mode="trusted-only"),
       "match": mk(enable_tsa=False, gate_mode="match"), "grp_record": mk(grouping="record"),
       "grp_record_allow": mk(grouping="record", gate_mode="attributed-allow"), "grp_session": mk(grouping="session"),
       "inherit": mk(inherit_read_trust=True)}


def table(specs, conds, summarizer=None, kind_attr=None):
    names = []; [names.append(s.structure) for s in specs if s.structure not in names]
    for name in names:
        line = f"  {name:22s}"
        for g in conds:
            ok = tot = 0; ev = collections.Counter()
            for sp in [s for s in specs if s.structure == name]:
                for dest, exp in sp.expected.items():
                    a, e, _ = run(sp, gws[g], dest, summarizer); dec = "pass" if a else "block"; tot += 1; ok += (dec == exp)
                    if dec != exp: ev[(getattr(sp, "cf_kind", {}) or {}).get(dest, "") + ":" + e] += 1
            line += f" | {g}:{ok}/{tot}" + (f"{dict(ev)}" if ev else "")
        print(line)


if __name__ == "__main__":
    print("kernel", G.KERNEL_VERSION)
    print("\n=== D. two-hop chains (expected: control pass, all others block) ===")
    table(R2.build_chain2_specs(cfg, reps=2), ["stpg", "allow", "tdo", "match"])
    print("\n=== F. surface forms (pass), look-alikes (block), malformed forms m_* (block) ===")
    table(R2.build_confusable_specs(cfg, reps=2), ["stpg", "allow", "match"])
    print("\n=== E. descriptive notices (spec: block; mock witness has no verb -> block; the real witness is the question) ===")
    table(R2.build_notice_specs(cfg, reps=1), ["stpg", "allow"])
    print("\n=== H. latency set: number of binding lineages must equal m ===")
    for sp in R2.build_latency_specs(cfg, reps=1):
        _, e, d = run(sp, gws["stpg"], sp.cf_destinations[0]); print(f"  {sp.structure:12s} bound={len(d['bound_gids'])} {e}")
    print("\n=== G. scale set (attack: block / benign: pass) ===")
    table(R2.build_scale_specs(cfg, reps=1), ["stpg", "allow"])
    print("\n=== I. laundering (spec: attack block, benign pass; stpg passes laundered attacks, inherit blocks them) ===")
    table(R2.build_launder_specs(cfg, reps=2), ["stpg", "inherit", "grp_record"], summarizer=mock_summarizer)
    print("\n=== regression: challenge set under v3.4 (must match v3.3 offline results) ===")
    hs = build_holdout_specs(cfg, 2, 2)
    table(hs, ["stpg", "allow", "tdo", "match", "grp_record", "grp_session"])
    print("\n=== main sanity under grouping variants ===")
    cfg.factors.n_benign_per_domain = 6
    ms = build_realistic_specs(cfg, benign_mode="with_legit", n_distractor=2); seen = collections.Counter()
    for sp in ms:
        st = sp.benign_subtype or "attack"
        if seen[st] >= 2: continue
        seen[st] += 1
        if sp.is_attack: dest = [r["text"] for r in sp.ingest_records if r.get("kind") == "shard"][-1].split("=")[-1].strip(" .")
        elif st == "legit_external": dest = [r["text"] for r in sp.ingest_records if "partner" in r["text"]][0].split("partner ")[-1].strip(" .")
        else: dest = "internal-ops-queue"
        print(f"  {st:18s}", {g: ("pass" if run(sp, gws[g], dest)[0] else "block") + "/" + run(sp, gws[g], dest)[1]
                              for g in ("stpg", "allow", "grp_record", "grp_record_allow", "grp_session")})
