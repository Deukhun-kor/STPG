"""권한 분리 확인: 저권한(ingest) 신원이 특권 싱크 도구를 직접 호출하면 게이트웨이가 거부하는지(g=1 전제)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stpg import config as C
from stpg.mcp.server import ToolRouter, ToolContext
def ctx(agent):
    p=C.AGENT_PROFILES[agent]
    return ToolContext(agent=agent, agent_trust=p["trust"], agent_priv=p["priv"], session_id="s", run_id="r",
                       origin_endpoint="/ops/internal", allowed_tools=tuple(p["tools"]))
r=ToolRouter(store=None, backend=None, gateway=None)
for a in ["sa-agent-ingest","sa-agent-ops"]:
    for tool in ["write_record","read_records","call_backend_api"]:
        print(f"{a:16s} {tool:18s} -> {'ALLOW' if r._iam_check(tool, ctx(a)) else 'DENY (iam)'}")
print("cloud gateway: caller service-account e-mail -> SA_MAP -> profile; tool not in profile -> HTTP 403 'iam' (stpg/cloud/services.py)")
