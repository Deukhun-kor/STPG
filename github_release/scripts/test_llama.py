"""Connectivity check for the second model family (Vertex AI Model-as-a-Service, OpenAI-compatible endpoint).
Usage (venv, ADC authenticated, GOOGLE_CLOUD_PROJECT set):
    python scripts\\test_llama.py                      # tries Llama 4 Maverick, then Scout
Prerequisites: pip install openai google-auth ; in Model Garden, open the "Llama 4 Maverick" (MaaS) card and accept the
Llama Community License (Enable); the endpoint region is STPG_MAAS_LOCATION (default us-east5)."""
import sys, os, argparse, json, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stpg.llm_backend import generate

CANDIDATES = ["meta/llama-4-maverick-17b-128e-instruct-maas", "meta/llama-4-scout-17b-16e-instruct-maas",
              "meta/llama-3.3-70b-instruct-maas"]   # 3.3 MaaS 는 2026-10-21 종료(참고용)
ap = argparse.ArgumentParser(); ap.add_argument("--model", default=""); a = ap.parse_args()
models = [a.model] if a.model else CANDIDATES
for m in models:
    t0 = time.time()
    try:
        text, it, ot = generate(m, "Answer with one JSON object only.",
                                'Return {"ok": true, "model": "<your model name>"}', 60, 0.0)
        print(f"[ok] {m}: {text.strip()[:120]!r} tokens in={it} out={ot} {time.time()-t0:.1f}s")
        print(f"USE: --judge-model {m}   /   --model {m}")
        break
    except Exception as e:
        body = getattr(e, "body", None) or getattr(getattr(e, "response", None), "text", "")
        print(f"[fail] {m}: {type(e).__name__}: {str(e)[:300]}\n       detail: {str(body)[:600]}")
else:
    print("no MaaS model reachable: accept the license on the Llama 4 Maverick card in Model Garden, "
          "check GOOGLE_CLOUD_PROJECT and STPG_MAAS_LOCATION, and run `gcloud auth application-default login`.")
