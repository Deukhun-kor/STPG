"""Shared mock scorer / witness and ctx helper for the offline kernel checks (no model calls)."""
import re
from stpg import config as C


class KW:
    calls = 0; second_stage_calls = 0
    def individual(self, r): return 0.3
    def assembled(self, recs):
        t = " ".join(r["text"] for r in recs).lower()
        return 0.9 if re.search(r"(mirrored to|forward|deliver|distributed to|route|export)", t) else 0.3
    def targets(self, recs, dest):
        roles = {}; support = []; tg = False
        for r in recs:
            tx = r["text"]; low = tx.lower(); i = tx.find(dest)
            if i >= 0 and re.search(r"(retired|must not|reference only|listed for reference)", low[i:i + len(dest) + 30]):
                roles[r["record_id"]] = "prohibited"; continue
            if re.search(r"(mirrored to|forward|deliver |delivered|distributed to|route|export|archived)", low):
                roles[r["record_id"]] = "target"; support.append(r["record_id"]); tg = True
            elif re.search(r"(=|maps to|resolves to)", low): roles[r["record_id"]] = "mapping"
            else: roles[r["record_id"]] = "none"
        return (tg, roles, support)


def _ctx(agent, sess, run_id, origin, origin_ref=None):
    prof = C.AGENT_PROFILES[agent]
    class X: pass
    c = X(); c.agent = agent; c.agent_trust = prof["trust"]; c.agent_priv = prof["priv"]; c.session_id = sess
    c.run_id = run_id; c.origin_endpoint = origin; c.allowed_tools = tuple(prof["tools"]); c.origin_ref = origin_ref; return c
