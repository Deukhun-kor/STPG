# STPG: Spatio-Temporal Provenance Guard

Repository: https://github.com/Deukhun-kor/STPG

Code, data generators, evaluated traces, and analysis scripts for the paper
Spatio-Temporal Provenance Guard: Detecting Privilege Escalation Attacks that Exploit Spatio-Temporal Data Loss in Multi-Agent MCP Environments (Deuk-Hun Kim, Jin Kwak; submitted to MDPI Applied Sciences).

STPG is an MCP-gateway defense with three modules: PPT (Persistent Provenance Tagging, on write), TSA (Temporal Shard Assembly, on read), and PDG (Privilege-Delta Gate, on sink). The gate binds the destination of the actual routing call to the lineages that name it, asks a destination-conditioned LLM witness whether a binding lineage targets that destination, verifies the verdict against a deterministic support path, and applies one decision kernel (pass on a trusted directive, block on an untrusted one, block by default).

## Version
- Kernel `v3.3`, witness prompt `w2` (see `VERSION_MANIFEST.txt` for SHA-256 hashes of every file that produced the tables of the paper).
- Experiments reported in the paper: `results/rev10_main.db`, `results/rev10_holdout.db` (main run, policy challenge set), `results/rev11_rules.db`, `results/rev11_multi.db` (robustness sets A and B), `results/rev11b_main_fjudge.db`, `results/rev11b_holdout_fjudge.db` (judge-model swap), `results/rev11b_flash.db` (second victim, reasoning mode disabled) and the matching `*_summary.json`; `results/rev11_paraphrases.json` holds the LLM-written rule paraphrases. `results/rev10_flash.db` is superseded by `rev11b_flash.db` (its victim outputs were truncated by the model's reasoning mode) and is kept only for the record.

## Layout
```
stpg/                 gateway (gate.py = decision kernel, binding.py = resolver, scoring.py = TSA scorer + witness, baselines.py = comparison adapters),
                      datagen (realistic.py = main-run generator, holdout.py = policy challenge set), storage, agents, config.py
scripts/              s2_experiment.py (runner), RUN_rev10.ps1 (exact commands used), test_gate_offline.py (kernel check without model calls),
                      analysis/ (table and figure regeneration; see analysis/README_analysis_v5.txt)
results/              rev10_*.db (per-trace results incl. binding lineages, witness roles, raw witness output, branch), rev10_*_agent.db (cached victim decisions)
paper/                main.tex, refs.bib, figures
tests/                unit tests
```

## Reproducing the tables
1. Python 3.11+, `pip install -r requirements.txt`; Google Cloud project with Vertex AI (gemini-2.5-flash-lite, gemini-2.5-flash, text-embedding-005) and `STPG_LLM_BACKEND=vertex`, `GOOGLE_CLOUD_PROJECT` set.
2. `python scripts/test_gate_offline.py` checks the kernel on the challenge structures with a mock witness (no model calls).
3. `scripts/RUN_rev10.ps1` reruns the main experiments and `scripts/RUN_rev11.ps1` / `RUN_rev11b.ps1` the robustness sets and the judge-model / second-victim runs; victim decisions are served from the cached `*_agent.db`, so only the judge, witness, and embedding calls are made.
4. `scripts/analysis/*.py` regenerate every table and figure from the `.db` files (commands in `scripts/analysis/README_analysis_v5.txt`).

## Safety note
All attack content is synthetic and non-destructive: destinations are placeholder identifiers, the sink is a mock that records call arguments, and no data leaves the testbed. The generators satisfy a property (no single record names both an action and an external target), not a weaponizable recipe.

## Citation
Kim, D.-H.; Kwak, J. Spatio-Temporal Provenance Guard: Detecting Privilege Escalation Attacks that Exploit Spatio-Temporal Data Loss in Multi-Agent MCP Environments. Applied Sciences (under review), 2026.

## License
MIT License (see `LICENSE`).
