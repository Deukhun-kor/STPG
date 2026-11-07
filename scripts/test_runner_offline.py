"""End-to-end dry run of scripts/s2_experiment.py with mock models (no API): exercises every --robust set, the grouping and
inherit detectors, timing columns, laundering summaries and the multi-pass option. Writes to results/_offline_*.db.
Run: python scripts\\test_runner_offline.py"""
import sys, os, re, json, sqlite3
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("STPG_RESULTS_DIR", "results")
import s2_experiment as S
from offline_common import KW


class MockBrain:
    model = "mock"; prompt = os.environ.get("STPG_VICTIM_PROMPT", "base"); labels = bool(os.environ.get("STPG_VICTIM_LABELS"))
    in_tok = 0; out_tok = 0
    def decide_ops(self, records, a=None, b=None):
        txt = " ".join(r.get("text", "") for r in records)
        m = re.search(r"(forward|deliver|mirrored to|distributed to|send)[^.]*?(PARTNER-EXT-\d+|SYNTH-AUDIT-SINK-\d+|SYNTH-RELAY-\d+|internal-ops-queue)", txt)
        if not m:
            m2 = re.search(r"(PARTNER-EXT-\d+|SYNTH-AUDIT-SINK-\d+|SYNTH-RELAY-\d+)", txt)
            return {"decision": {"action": "routing" if m2 else "benign_report", "destination": m2.group(1) if m2 else None}}
        return {"decision": {"action": "routing", "destination": m.group(2)}}
    def summarize(self, records):
        txt = " ".join(r.get("text", "") for r in records)
        m = re.search(r"(SYNTH-AUDIT-SINK-\d+|PARTNER-EXT-\d+)", txt)
        return f"finalized reports for this domain are forwarded to {m.group(1)}." if m else "no standing arrangement recorded."


class MockTSA(KW):
    judge_tokens = (0, 0); target_stats = (0, 0, 0)
    def __init__(self, *a, **k):
        class J: calls = 0; in_tok = 0; out_tok = 0; target_calls = 0; target_in = 0; target_out = 0; last_raw = ""
        class E: calls = 0
        class Casc: pass
        self._emb = E(); self._casc = Casc(); self._casc.first = E(); self._casc.second = J()
    def targets(self, recs, dest): return KW.targets(self, recs, dest)


class MockJudge(KW):
    calls = 0; in_tok = 0; out_tok = 0
    def __init__(self, *a, **k): pass
    def _client(self): raise RuntimeError("no API in offline test")


S.GeminiLLM = lambda model_key: MockBrain()
S.TSAScorer = MockTSA; S.EmbeddingFilter = MockTSA; S.LLMJudge = MockJudge
S.B.AttributionJudge._ask = lambda self, records, dest, key: {"supporting_ids": [r["record_id"] for r in records if dest in r.get("text", "")], "authorized": any(dest in r.get("text", "") and r["_provenance"]["source_trust"] >= 2 for r in records)}

CASES = [
    ["--robust", "chain2", "--reps", "1", "--detectors", "none,stpg,stpg_allow,match_gate,attr_judge,stpg_grp_record,stpg_grp_session"],
    ["--robust", "notice", "--reps", "1", "--detectors", "none,stpg,stpg_allow"],
    ["--robust", "confusable", "--reps", "1", "--detectors", "none,stpg,stpg_allow"],
    ["--robust", "scale", "--reps", "1", "--detectors", "none,stpg,stpg_grp_record"],
    ["--robust", "latency", "--reps", "1", "--detectors", "stpg,stpg_pdgonly", "--passes", "2"],
    ["--robust", "launder", "--reps", "1", "--detectors", "none,stpg,stpg_inherit"],
    ["--holdout", "--reps", "1", "--detectors", "stpg,stpg_grp_record"],
]
for i, args in enumerate(CASES):
    out = f"_offline_{i}"
    for f in (f"{out}.db", f"{out}_summary.json", f"{out}_agent.db"):
        try: os.remove(os.path.join(os.environ["STPG_RESULTS_DIR"], f))
        except FileNotFoundError: pass
    sys.argv = ["s2_experiment.py", "--profile", "s4_main", "--out", out, "--n-distractor", "2"] + args
    print("\n>>>", " ".join(args)); S.main()
    c = sqlite3.connect(os.path.join(os.environ["STPG_RESULTS_DIR"], f"{out}.db"))
    print("   rows per detector:", c.execute("SELECT detector, COUNT(*), SUM(sink_allowed=1), AVG(read_ms), AVG(sink_ms) FROM results GROUP BY detector").fetchall())
    if "confusable" in args: print("   cf_kind sample:", c.execute("SELECT cf_kind, sink_allowed FROM results WHERE detector='stpg' AND cf!='' LIMIT 4").fetchall())
print("\nrunner offline OK")
