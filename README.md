# STPG: Spatio-Temporal Provenance Guard

Repository: https://github.com/Deukhun-kor/STPG

Code, data generators, evaluated traces, and analysis scripts for the paper
Spatio-Temporal Provenance Guard: Detecting Privilege Escalation Attacks that Exploit Spatio-Temporal Data Loss in Multi-Agent MCP Environments (Deuk-Hun Kim, Jin Kwak; MDPI Applied Sciences, under review, revision 1).

STPG is an MCP-gateway defense with three modules: PPT (Persistent Provenance Tagging, on write), TSA (Temporal Shard Assembly, on read), and PDG (Privilege-Delta Gate, on sink). The gate binds the destination of the actual routing call to the lineages that name it, asks a destination-conditioned LLM witness whether a binding lineage targets that destination, verifies the verdict against a deterministic support path, and applies one decision kernel (pass on a trusted directive, block on an untrusted one, block by default).

## Version
- Revision 1, final (tag `v8-revision1`): kernel `v3.5` = v3.4 plus the identifier contract (whitespace is a word boundary, never an identifier separator; a destination that is not a single identifier is blocked as `malformed-destination` before any branch), witness prompt `w3`. Every table of the revised paper reports run 5 = the run-4 logs re-derived under v3.5 (`results/v35/`, built by `scripts/analysis/rev12_v35_rederive.py`, changed rows listed in `results/v35/rederive_log.json`; the pre-check depends on the destination string only, and `scripts/check_v35_equivalence.py` verifies that the v3.4 and v3.5 matchers agree on every record/identifier pair of every set except the six space-written rules of set A) plus re-runs of set A (`results/v35/rev12_rules.db`, all conditions, w3) and set F (`results/v35/rev12_confusable.db`, with three malformed forms). Run script: `scripts/RUN_rev12e.ps1`; report: `STPG_RESULTS_DIR=results/v35 python scripts/analysis/rev12_report.py --unseen`. See `VERSION_MANIFEST.txt` for SHA-256 hashes.
- Revision 1, first version (intermediate, not tagged; superseded by `v8-revision1`): kernel `v3.4` (full-path chain trust, destination canonicalization, grouping as a parameter), witness prompt `w3`; run 4 (`results/rev12_*`).
- Run-4 databases: `rev12_main.db`, `rev12_holdout.db` (main run, challenge set, incl. the grouping ablations), `rev12_rules.db`, `rev12_multi.db` (sets A, B), `rev12_chain2.db` (D), `rev12_notice_w2.db` / `rev12_notice_w3.db` / `rev12_rules_w3.db` (E and the prompt comparison), `rev12_confusable.db` (F), `rev12_scale.db` (G), `rev12_latency.db` / `rev12_latency_cold.db` (H), `rev12_launder.db` (I), `rev12_hardened.db` / `rev12_labeled.db` (victim prompts), `rev12_main_ljudge.db` / `rev12_holdout_ljudge.db` (Llama 4 Maverick as judge / witness), `rev12_lvictim.db` (Llama as victim), `rev12_unseen.db` / `rev12_unseen_lvictim.db` (frozen evaluation set), `rev12_unseen_relext.db` / `rev12_holdout_relext.db` (post-hoc extended pattern), `rev12_unseen_phrasings.json` (model-written phrasings). Run scripts: `scripts/RUN_rev12a.ps1` to `RUN_rev12d.ps1`; report: `scripts/analysis/rev12_report.py --unseen`.
- Submitted version (tag `v6-submission`): kernel `v3.3`, witness prompt `w2`. Experiments reported in the submitted version: `results/rev10_main.db`, `results/rev10_holdout.db` (main run, policy challenge set), `results/rev11_rules.db`, `results/rev11_multi.db` (robustness sets A and B), `results/rev11b_main_fjudge.db`, `results/rev11b_holdout_fjudge.db` (judge-model swap), `results/rev11b_flash.db` (second victim, reasoning mode disabled) and the matching `*_summary.json`; `results/rev11_paraphrases.json` holds the LLM-written rule paraphrases. `results/rev10_flash.db` is superseded by `rev11b_flash.db` (its victim outputs were truncated by the model's reasoning mode) and is kept only for the record.

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
1. Python 3.11+, `pip install -r requirements.txt` plus `openai google-auth` for the second model family; Google Cloud project with Vertex AI (gemini-2.5-flash-lite, text-embedding-005, and Llama 4 Maverick enabled in Model Garden, region us-east5) and `STPG_LLM_BACKEND=vertex`, `GOOGLE_CLOUD_PROJECT` set. `scripts/test_llama.py` checks the Llama endpoint.
2. `python scripts/test_gate_offline.py` and `python scripts/test_rev12_offline.py` check the kernel on the challenge structures and the revision sets with a mock witness (no model calls); `python scripts/test_runner_offline.py` dry-runs the experiment runner with mock models.
3. `scripts/RUN_rev10.ps1` reruns the main experiments and `scripts/RUN_rev11.ps1` / `RUN_rev11b.ps1` the robustness sets and the judge-model / second-victim runs; victim decisions are served from the cached `*_agent.db`, so only the judge, witness, and embedding calls are made.
4. `scripts/analysis/*.py` regenerate every table and figure from the `.db` files (commands in `scripts/analysis/README_analysis_v5.txt`).

## Safety note
All attack content is synthetic and non-destructive: destinations are placeholder identifiers, the sink is a mock that records call arguments, and no data leaves the testbed. The generators satisfy a property (no single record names both an action and an external target), not a weaponizable recipe.

## Citation
Kim, D.-H.; Kwak, J. Spatio-Temporal Provenance Guard: Detecting Privilege Escalation Attacks that Exploit Spatio-Temporal Data Loss in Multi-Agent MCP Environments. Applied Sciences (under review), 2026.

## License
MIT License (see `LICENSE`).
