"""v3.5 exactness check (no model calls). The v3.5 kernel differs from v3.4 in two places only: (i) a destination-grammar
pre-check that depends on the destination string alone and fires before any other step, and (ii) whitespace is no
longer an identifier separator in canon() and in the text matcher. For every record text of every evaluated set and
every identifier-shaped token that occurs in those texts, in the counterfactual destinations, or in the destinations
the victims actually issued (read from the run-4 result DBs), this script compares the v3.4 and v3.5 text matcher,
canonical form, and relation-pattern extraction. If every pair agrees for every well-formed destination, then every
run-4 decision on a well-formed destination is unchanged under v3.5 and only the malformed destinations change, which is
what scripts/analysis/rev12_v35_rederive.py applies. Run: python scripts\\check_v35_equivalence.py"""
import sys, os, re, glob, sqlite3, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stpg import config as C
from stpg.gateway import binding as B
from stpg.datagen import robust2 as R2
from stpg.datagen.robust import build_rule_variant_specs, build_multiconnector_specs, load_paraphrases
from stpg.datagen.holdout import build_holdout_specs
from stpg.datagen.realistic import build_realistic_specs
R = os.environ.get("STPG_RESULTS_DIR", "results")

# ---- v3.4 definitions (verbatim) ----
_SEP4 = r"[-_ ]+"
def canon4(t):
    t = (t or "").strip().strip("`\"'").strip()
    t = re.sub(r"\s*\([^()]*\)\s*$", "", t)
    t = t.rstrip(".,;:").strip().strip("`\"'")
    t = re.sub(_SEP4, "-", t.lower())
    return t.strip("-")
def tokbody4(tok):
    parts = [re.escape(p) for p in canon4(tok).split("-") if p]
    return _SEP4.join(parts) if parts else r"(?!x)x"
def mentions4(text, tok):
    return re.search(B._LB + tokbody4(tok) + B._RB, text or "", re.I) is not None
def values4(token, records):
    pat = re.compile(B._LB + r"[`\"']?" + tokbody4(token) + r"[`\"']?" + B._REL + B._TOK, re.I)
    return {canon4(m.group(1)) for r in records for m in pat.finditer(r.get("text", ""))}
def keys4(token, records):
    pat = re.compile(B._TOK + B._REL + r"[`\"']?" + tokbody4(token) + r"[`\"']?" + B._RB, re.I)
    return {canon4(m.group(1)) for r in records for m in pat.finditer(r.get("text", ""))}

_IDENT = re.compile(r"[A-Za-z0-9\.]*[0-9_\-][A-Za-z0-9_\-\.]*")

def tokens_of(texts, extra):
    toks = set(extra)
    for t in texts:
        toks.update(m.group(0).strip(".") for m in _IDENT.finditer(t))
    return {t for t in toks if t}

def check(name, specs, extra_dests):
    diff = collections.Counter(); n_pairs = 0; mal = 0
    for sp in specs:
        recs = [{"text": r["text"]} for r in sp.ingest_records]
        texts = [r["text"] for r in recs]
        dests = set(getattr(sp, "cf_destinations", []) or []) | set(extra_dests.get(sp.run_id, []))
        toks = tokens_of(texts, dests)
        for tok in toks:
            if B.is_malformed(tok):
                mal += 1; continue
            if canon4(tok) != B.canon(tok): diff["canon"] += 1
            for tx in texts:
                n_pairs += 1
                if mentions4(tx, tok) != B._mentions(tx, tok): diff["mentions"] += 1
            if values4(tok, recs) != {v for v in B._values_of(tok, recs)}: diff["values_of"] += 1
            if keys4(tok, recs) != {k for k, _ in B._keys_of(tok, recs)}: diff["keys_of"] += 1
    print(f"  {name:28s} traces={len(specs):4d} (text,token) pairs={n_pairs:7d} malformed tokens skipped={mal:3d} differences={dict(diff) or 'none'}")
    return diff

def actual_dests(dbs):
    out = collections.defaultdict(set)
    for db in dbs:
        p = os.path.join(R, db)
        if not os.path.exists(p): continue
        for rid, d in sqlite3.connect(p).execute("SELECT run_id, destination FROM results WHERE destination IS NOT NULL AND destination != ''"):
            out[rid.split("#")[0]].add(d)
    return out

cfg = C.load_profile("s4_main")
total = collections.Counter()
print("kernel", __import__("stpg.gateway.gate", fromlist=["KERNEL_VERSION"]).KERNEL_VERSION)
total += check("main (realistic)", build_realistic_specs(cfg, benign_mode="with_legit", n_distractor=2),
               actual_dests(["rev12_main.db", "rev12_hardened.db", "rev12_labeled.db", "rev12_lvictim.db", "rev12_main_ljudge.db"]))
total += check("challenge (holdout)", build_holdout_specs(cfg, n_distractor=2, reps=4), actual_dests(["rev12_holdout.db", "rev12_holdout_ljudge.db", "rev12_holdout_relext.db"]))
pp = os.path.join(R, "rev11_paraphrases.json")
pj = load_paraphrases(pp) if os.path.exists(pp) else {}
total += check("set A rules", build_rule_variant_specs(cfg, reps=10, n_distractor=2, paraphrases=pj.get("paraphrases", pj)), actual_dests(["rev12_rules.db", "rev12_rules_w3.db"]))
total += check("set B multi", build_multiconnector_specs(cfg, reps=10, n_distractor=2), actual_dests(["rev12_multi.db"]))
total += check("set D chain2", R2.build_chain2_specs(cfg, reps=10, n_distractor=2), actual_dests(["rev12_chain2.db"]))
total += check("set E notice", R2.build_notice_specs(cfg, reps=10, n_distractor=2), actual_dests(["rev12_notice_w2.db", "rev12_notice_w3.db"]))
total += check("set F confusable", R2.build_confusable_specs(cfg, reps=10, n_distractor=2), actual_dests(["rev12_confusable.db"]))
total += check("set G scale", R2.build_scale_specs(cfg, reps=5, n_distractor=2), actual_dests(["rev12_scale.db"]))
total += check("set H latency", R2.build_latency_specs(cfg, reps=10, n_distractor=2), actual_dests(["rev12_latency.db", "rev12_latency_cold.db"]))
total += check("set I launder", R2.build_launder_specs(cfg, reps=10, n_distractor=2), actual_dests(["rev12_launder.db"]))
try:
    from stpg.datagen.unseen import build_unseen_specs
    total += check("frozen set (unseen)", build_unseen_specs(cfg, reps=5, n_distractor=2), actual_dests(["rev12_unseen.db", "rev12_unseen_lvictim.db", "rev12_unseen_relext.db"]))
except FileNotFoundError as e:
    print("  frozen set skipped:", e)
# set I handoff notes written by the summarizer are in the agent DB
p = os.path.join(R, "rev12_launder_agent.db")
if os.path.exists(p):
    notes = [n for (n,) in sqlite3.connect(p).execute("SELECT note FROM summary")]
    d = collections.Counter(); toks = tokens_of(notes, [])
    for tok in toks:
        if B.is_malformed(tok): continue
        for tx in notes:
            if mentions4(tx, tok) != B._mentions(tx, tok): d["mentions"] += 1
    print(f"  {'set I handoff notes':28s} notes={len(notes):4d} differences={dict(d) or 'none'}"); total += d
print("TOTAL differences on well-formed tokens:", dict(total) or "none",
      "-> run-4 decisions on well-formed destinations are unchanged under v3.5" if not total else "-> RERUN REQUIRED for the sets with differences")
raise SystemExit(1 if total else 0)
