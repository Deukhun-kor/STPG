Analysis scripts for paper v5 (rev10 experiments; kernel v3.3, witness w2-5a435d39-mot200). Run from a folder containing the rev10 databases.
  rev_main_defense.py       <rev10_main.db>      main-run defense/detection tables (Tables 9, 12, 13 inputs)
  rev_holdout.py            <rev10_holdout.db>   policy challenge set: conformance per condition, STPG branch counts, misses, actual-call correctness (Table 11, Figure 4 inputs)
  rev_witness_semantics.py  <rev10_holdout.db>   witness verdict vs kernel verification per structure (Table 10)
  rev_cluster_stats.py      (reads rev10_main.db) both-class family bootstrap AUROC CIs and paired dAUROC, per-domain false blocks, internal routing breakdown, FPR<=5% raw counts
  rev_metadata_joint.py     <metadata_features.csv>  LODO per-fold AUROC, balanced LOFO, permutation (Table 7)
  rev_metadata_length.py    length-only / no-length LOFO diagnosis and tree importances (Table 7, last rows)
  fig_holdout.py            <rev10_holdout.db> <out_prefix>  conformance matrix figure (figs/fig_holdout.pdf)
Seeds: numpy seed 11 (cluster bootstrap), per-domain seed sum(ord(domain)) for the LOFO benign quarter.

[v6 update 2026-10-20]
- fig_scores.py / fig_holdout.py: color versions (blue attack, orange approved rule; Blues conformance matrix with totals row).
- prf.py: precision / recall / F1 of the gate over the 719 external calls (Table 10) and of the detection scorers at the a priori and FPR<=5% points (Table 15). Usage: python prf.py results/rev10_main.db
- fig_roc.py <main.db> <out>: ROC curves, both benign sets (Figure 7).
- fig_factors.py <main.db> results/rev10_attack_factors.csv <out>: AUROC by k, d, hiding location (Figure 8); the CSV maps attack run_id -> factors (regenerated from stpg.datagen.generator._rid).
- fig_witness.py <holdout.db> <out>: witness verdicts vs. kernel verification per structure (Figure 4).

[v6 robustness update 2026-10-21]
- fig_robust.py results/rev11_rules.db results/rev11_multi.db <out>: robustness sets A and B, calls passed / allowed per variant and condition (Figure 9; Table 16 visualized).
- fig_judgeswap.py results/rev10_main.db results/rev11b_main_fjudge.db <out>: read-level E* histograms of STPG's assembled lineages under the primary (flash-lite) and swapped (flash) judge (Figure 10).
- rev_robust.py: text tables for sets A, B, C and the second victim (Section 7.8 inputs); lives in scripts/analysis of the code repository.
