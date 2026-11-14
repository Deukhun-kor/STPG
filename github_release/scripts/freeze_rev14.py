"""rev14 (run 7) freeze record. Run BEFORE scripts/gen_rev14_phrasings.py. Writes results/v35/rev14_freeze.json with the
SHA-256 of every file that decides a gate outcome (kernel, resolver incl. the extended pattern, witness prompt, gateway,
config, the H2 builder with its specified decisions, the generator and the runner) and the fixed settings (kernel and
witness versions, second-witness model, agreement rule, relation-extension flag). The generator and the runner refuse to
run if any hash differs from this record, so nothing is tuned after the phrasings are written.
Usage:  python scripts\\freeze_rev14.py            (write; refuses to overwrite an existing record)
        python scripts\\freeze_rev14.py --check    (verify; exit 1 on any difference)"""
import sys, os, json, hashlib, datetime, argparse
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
R = os.environ.get("STPG_RESULTS_DIR", "results")
FREEZE = os.path.join(R, "rev14_freeze.json")
FILES = ["stpg/gateway/gate.py", "stpg/gateway/binding.py", "stpg/gateway/stpg.py", "stpg/gateway/scoring.py",
         "stpg/gateway/baselines.py", "stpg/config.py", "stpg/datagen/unseen2.py", "stpg/datagen/unseen.py",
         "stpg/datagen/robust.py", "stpg/datagen/realistic.py", "stpg/datagen/generator.py",
         "scripts/gen_rev14_phrasings.py", "scripts/s2_experiment.py"]


def sha(path):
    return hashlib.sha256(open(os.path.join(ROOT, path), "rb").read()).hexdigest()


def current():
    from stpg.gateway import gate as G
    from stpg.gateway import scoring as S
    from stpg.datagen import unseen2 as U2
    ext_lines = [l.rstrip() for l in open(os.path.join(ROOT, "stpg/gateway/binding.py"), encoding="utf-8")
                 if "RELATION_EXT" in l or l.lstrip().startswith("_EXT")]
    return {"files": {f: sha(f) for f in FILES},
            "kernel_version": G.KERNEL_VERSION.replace("+relext", ""),
            "witness_version": getattr(S, "WITNESS_VERSION", os.environ.get("STPG_WITNESS", "w3")),
            "witness_prompt_env": os.environ.get("STPG_WITNESS", "w3"),
            "second_witness": os.environ.get("STPG_SECOND_WITNESS", "meta/llama-4-maverick-17b-128e-instruct-maas"),
            "agreement_rule": "a trusted lineage authorizes the destination only if the primary witness and the second witness "
                              "both return a verdict that passes the support-path check (gate.apply_gate, witness2)",
            "relation_extension": "STPG_RELATION_EXT=1 selects the extended pattern frozen in binding.py (hash above)",
            "relation_extension_lines": ext_lines,
            "policy": U2.POLICY, "structures": U2.STRUCTURES, "phrasing_keys": U2.KEYS,
            "phrasings_file": U2.PHRASINGS_FILE}


def check(verbose=True):
    if not os.path.exists(FREEZE):
        print("no freeze record:", FREEZE); return False
    rec = json.load(open(FREEZE, encoding="utf-8")); now = current(); ok = True
    for f, h in rec["files"].items():
        if now["files"].get(f) != h:
            ok = False; print("  CHANGED since freeze:", f)
    for k in ("kernel_version", "witness_prompt_env", "second_witness", "policy", "structures", "phrasing_keys", "relation_extension_lines"):
        if rec.get(k) != now.get(k):
            ok = False; print("  CHANGED since freeze:", k)
    if verbose: print("freeze check:", "OK" if ok else "FAILED", "| frozen at", rec.get("frozen_at"))
    return ok


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--check", action="store_true"); a = ap.parse_args()
    if a.check:
        raise SystemExit(0 if check() else 1)
    if os.path.exists(FREEZE):
        phr = os.path.join(R, current()["phrasings_file"])
        if os.path.exists(phr):
            print("freeze record exists and phrasings were already written, not overwritten:", FREEZE); raise SystemExit(0 if check() else 1)
        print("freeze record exists but no phrasings were written yet: re-freezing (previous record superseded)")
    rec = current(); rec["frozen_at"] = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    os.makedirs(R, exist_ok=True)
    json.dump(rec, open(FREEZE, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print("frozen:", FREEZE); print(" kernel", rec["kernel_version"], "witness", rec["witness_prompt_env"], "second witness", rec["second_witness"])
    for f, h in rec["files"].items(): print(f"  {h[:16]}  {f}")


if __name__ == "__main__":
    main()
