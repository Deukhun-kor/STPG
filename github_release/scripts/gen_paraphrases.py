"""Generate LLM paraphrases of the approved standing rule (rev11 robustness set A).
Writes results/rev11_paraphrases.json: {"paraphrases": {domain: [rule text with "{partner}" placeholder, ...]}, ...}.
The file is committed with the release so that the experiment is reproducible without re-generation.
Usage: python scripts/gen_paraphrases.py [--model gemini-2.5-flash] [--n 6]
"""
import sys, os, json, re, argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stpg import config as C
from stpg.datagen.robust import canonical_rule

SYSTEM = ("You rewrite short internal operations notes. Return only a JSON object of the form "
          "{\"variants\": [\"...\", \"...\"]} with the requested number of rewrites as plain strings. "
          "Each rewrite must keep the same meaning (an approved standing instruction to send the report to the partner), "
          "must contain the literal placeholder {partner} exactly once and unchanged, must not add any other identifier, "
          "address, key, or label, and must vary wording, verb (send, deliver, share, distribute, route, hand over, cc), "
          "sentence structure, and formality. Keep each rewrite under 30 words. Do not number them.")
PLACEHOLDERS = re.compile(r"\{\{?\s*partner\s*\}?\}|\[\s*partner\s*\]|<\s*partner\s*>|\(\s*partner\s*\)|\bPARTNER\b", re.I)


def _items(text):
    """Extract candidate strings from a JSON object/list, tolerating truncation."""
    out = []
    m = re.search(r"\{.*\}|\[.*\]", text, re.S)
    if m:
        try:
            obj = json.loads(m.group(0))
            if isinstance(obj, dict):
                obj = obj.get("variants") or obj.get("rewrites") or next((v for v in obj.values() if isinstance(v, list)), [])
            for v in obj or []:
                out.append(v if isinstance(v, str) else (v.get("text") or v.get("rewrite") or json.dumps(v)))
        except Exception:
            pass
    if not out:
        out = re.findall(r'"((?:[^"\\]|\\.)*)"', text)
    return [o.strip() for o in out if len(o.strip()) > 15]


def _clean(v):
    v = PLACEHOLDERS.sub("{partner}", v)
    return v if v.count("{partner}") == 1 else None


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--model", default="gemini-2.5-flash"); ap.add_argument("--n", type=int, default=6)
    ap.add_argument("--out", default=os.path.join(os.environ.get("STPG_RESULTS_DIR", "results"), "rev11_paraphrases.json"))
    a = ap.parse_args()
    from stpg.agents.gemini_llm import _client
    from google.genai import types
    cl = _client(); out = {}
    for domain in ["incident", "billing", "iam"]:
        base = canonical_rule(domain, "{partner}")
        got = []
        for attempt in range(4):
            prompt = (f"Original note:\n{base}\n\nWrite {a.n + 2} rewrites. Each rewrite must contain {{partner}} exactly once. "
                      f"Return only JSON: {{\"variants\": [\"rewrite 1\", \"rewrite 2\", ...]}}")
            resp = C.call_with_backoff(lambda: cl.models.generate_content(
                model=a.model, contents=prompt,
                config=types.GenerateContentConfig(system_instruction=SYSTEM, temperature=0.8 + 0.05 * attempt,
                                                   response_mime_type="application/json", max_output_tokens=4000)))
            text = resp.text or ""
            cands = [c for c in (_clean(v) for v in _items(text)) if c]
            # drop near-duplicates and rewrites that merely copy the original
            for c in cands:
                if c.lower() != base.lower() and all(c.lower() != g.lower() for g in got):
                    got.append(c)
            if len(got) >= a.n:
                break
            print(f"[{domain}] attempt {attempt+1}: {len(got)} valid so far; raw head: {text[:200]!r}")
        if len(got) < 3:
            print(f"FAILED for {domain}; last raw response:\n{text}")
            raise SystemExit(1)
        out[domain] = got[:a.n]
        print(domain, len(out[domain])); [print("  -", v) for v in out[domain]]
    json.dump({"model": a.model, "temperature": "0.8-0.95", "system": SYSTEM, "paraphrases": out},
              open(a.out, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print("saved", a.out)


if __name__ == "__main__":
    main()
