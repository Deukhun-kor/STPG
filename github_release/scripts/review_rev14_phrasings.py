"""rev14 (run 7): review sheet of the H2 phrasings and their specified decisions, produced BEFORE the experiment runs.
Writes results/v35/rev14_phrasings_review.txt (every phrasing with the structures that use it and the specified decision,
plus lint flags for a human check) and results/v35/rev14_phrasings_lock.json (SHA-256 of the phrasings file). The runner
refuses --robust unseen2 unless the phrasings file matches the lock, so the file reviewed is the file evaluated.
If the review removes an item, edit the JSON (removal only, no rewording), then rerun this script to re-lock.
Usage: python scripts\\review_rev14_phrasings.py"""
import sys, os, json, re, hashlib, datetime, collections
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from stpg.datagen.unseen2 import load_phrasings2, build_unseen2_specs, POLICY, KEYS, PHRASINGS_FILE, STRUCTURES
from stpg import config as C
R = os.environ.get("STPG_RESULTS_DIR", "results")
PATH = os.path.join(R, PHRASINGS_FILE); LOCK = os.path.join(R, "rev14_phrasings_lock.json")
USED_BY = {"rules_direct": ["v01_explicit_rule", "v05_rule_plus_mention"], "arrangements": ["v02_arrangement"],
           "notices": ["v03_notice"], "function_notices": ["v04_function_notice"], "mentions": ["v05_rule_plus_mention"],
           "rules_via_key": ["v06_key_trusted", "v07_key_untrusted", "v08_key_missing", "v09_key_conflict"],
           "sheets": ["v06_key_trusted", "v07_key_untrusted", "v09_key_conflict"],
           "attack_triples": ["v10_chain2_trusted", "v11_chain2_poisoned", "v12_attack_split"]}
SEND = re.compile(r"\b(send|sent|sends|forward|forwards|forwarded|deliver|delivers|delivered|route|routes|routed|mirror|mirrored|"
                  r"transmit|transmits|transmitted|dispatch|dispatched|export|exported|share|shared|go|goes|went|push|pushed|"
                  r"distribute|distributed|circulate|circulated|provide|provided|supply|supplied|submit|submitted|upload|uploaded|relay|relayed)\b", re.I)
IMPER = re.compile(r"^\s*\[[a-z]+\]\s*(?:[a-z ]*:\s*)?(send|forward|deliver|route|mirror|transmit|dispatch|export|push|distribute|submit)\b", re.I)


def lint(key, text):
    flags = []
    if key == "arrangements":
        if not SEND.search(text): flags.append("arrangement without a transfer verb (specified pass needs a commitment to send)")
        if IMPER.search(text): flags.append("arrangement written as an instruction (should be a statement of practice)")
    if key == "notices" and SEND.search(text): flags.append("descriptive notice contains a transfer verb (check that it commits no output)")
    if key == "function_notices":
        if re.search(r"\b(we|team|operations|ops)\b.*\b(send|forward|deliver|route)\b", text, re.I): flags.append("function notice names a transfer by the team")
        if not re.search(r"\b(handle|handles|own|owns|responsible|coordinates?|manage|manages|oversee|oversees|lead|leads|in charge|covers?)\b", text, re.I):
            flags.append("function notice without a function verb")
    if key == "rules_direct" and not SEND.search(text): flags.append("rule without a transfer verb")
    if key == "rules_via_key" and not SEND.search(text): flags.append("key rule without a transfer verb")
    if key == "mentions" and SEND.search(text): flags.append("mention contains a transfer verb")
    return flags


def main():
    P = load_phrasings2(PATH); lines = []; nflag = 0
    lines.append(f"rev14 H2 phrasings review | file {PATH} | model {P.get('model')} | freeze {P.get('freeze_sha', '')[:16]}")
    lines.append("Specified decisions (policy fixed before generation):")
    for s_ in STRUCTURES: lines.append(f"  {s_:22s} {POLICY[s_]}")
    for dom, ph in P["domains"].items():
        lines.append(f"\n=== {dom} ===")
        for key in KEYS:
            lines.append(f"-- {key} (used by {', '.join(USED_BY[key])}; specified: " +
                         ", ".join(f"{s_}={POLICY[s_]}" for s_ in USED_BY[key]) + ")")
            for i, item in enumerate(ph.get(key, [])):
                parts = item if isinstance(item, list) else [item]
                for j, t in enumerate(parts):
                    fl = lint(key, t) if key != "attack_triples" else []
                    nflag += len(fl)
                    lines.append(f"  [{i}{'.' + str(j) if key == 'attack_triples' else ''}] {t}" + ("".join("\n        !! " + f for f in fl)))
        rej = P.get("rejected", {}).get(dom, [])
        if rej:
            lines.append(f"-- rejected for reuse ({len(rej)}):")
            for k, it, why in rej: lines.append(f"  {k}: {it} | {why}")
    specs = build_unseen2_specs(C.load_profile("s4_main"), reps=5, phrasings=P)
    cnt = collections.Counter(s.structure for s in specs)
    lines.append(f"\n{len(specs)} traces, {sum(len(s.cf_destinations) for s in specs)} counterfactual calls, per structure: {dict(sorted(cnt.items()))}")
    lines.append(f"lint flags: {nflag} (each flag is a prompt for the human check, not an automatic removal)")
    txt = "\n".join(lines); open(os.path.join(R, "rev14_phrasings_review.txt"), "w", encoding="utf-8").write(txt); print(txt)
    lock = {"file": PHRASINGS_FILE, "sha256": hashlib.sha256(open(PATH, "rb").read()).hexdigest(),
            "locked_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"), "traces": len(specs),
            "counterfactual_calls": sum(len(s.cf_destinations) for s in specs)}
    json.dump(lock, open(LOCK, "w", encoding="utf-8"), indent=2); print("\nlock written:", LOCK, lock["sha256"][:16])


if __name__ == "__main__":
    main()
