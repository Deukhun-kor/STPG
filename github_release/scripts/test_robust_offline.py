"""rev11 robustness sets: offline kernel check with the keyword mock witness (no model calls).
Prints, per structure and condition, the gate decision distribution on the counterfactual destination."""
import sys, os, collections, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stpg import config as C
from stpg.gateway.stpg import STPGGateway
from stpg.datagen.robust import build_rule_variant_specs, build_multiconnector_specs, load_paraphrases
sys.argv=[sys.argv[0]]
import importlib.util
spec=importlib.util.spec_from_file_location("tgo", os.path.join(os.path.dirname(__file__), "test_gate_offline.py"))
# reuse KW / evaluate from test_gate_offline without running its main body: copy minimal pieces
src=open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_gate_offline.py"), encoding="utf-8").read().split("cfg=C.load_profile")[0]
ns={"__file__": os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_gate_offline.py")}; exec(src, ns); KW=ns["KW"]; evaluate=ns["evaluate"]
cfg=C.load_profile("s4_main")
gws={"stpg":STPGGateway(KW(),0.6,1,gate_mode="attributed"),"allow":STPGGateway(KW(),0.6,1,gate_mode="attributed-allow"),
     "tdo":STPGGateway(KW(),0.6,1,gate_mode="trusted-only"),"pdgonly":STPGGateway(KW(),0.6,1,enable_tsa=False,gate_mode="any-untrusted"),
     "match":STPGGateway(KW(),0.6,1,enable_tsa=False,gate_mode="match")}
pj=load_paraphrases(os.path.join(os.environ.get("STPG_RESULTS_DIR","results"),"rev11_paraphrases.json"))
for title,specs in [("rules",build_rule_variant_specs(cfg,reps=3,paraphrases=pj.get("paraphrases",pj))),("multi",build_multiconnector_specs(cfg,reps=3))]:
    print(f"=== {title}: {len(specs)} traces ===")
    names=[]; [names.append(s.structure) for s in specs if s.structure not in names]
    for name in names:
        line=f"{name:20s}"
        for g,gw in gws.items():
            ev=collections.Counter(); ok_n=0; n=0
            for sp in [s for s in specs if s.structure==name]:
                for dest in sp.cf_destinations:
                    ok,e=evaluate(sp,gw,dest); n+=1; ok_n+=int(ok); ev[e]+=1
            line+=f" | {g}: pass {ok_n}/{n} {dict(ev)}"
        print(line)
