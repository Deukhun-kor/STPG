Analysis scripts for paper v4 (rev7 experiments). Run from a folder containing the rev7 databases.
  rev_main_defense.py      <rev7_main.db>      main-run defense/detection tables (Tables 9, 11, 12 inputs)
  rev_holdout.py           <rev7_holdout.db>   policy challenge set: conformance per condition, STPG branch counts, misses, witness roles, actual-call correctness (Table 10, Figure 4 inputs)
  rev_cluster_stats.py     (reads rev7_main.db) both-class family bootstrap AUROC CIs and paired dAUROC, per-domain false blocks, internal routing breakdown, FPR<=5% raw counts (Tables 9, 11, 12)
  rev_metadata_joint.py    <metadata_features.csv>  LODO per-fold AUROC, balanced LOFO, permutation (Table 7)
  rev_metadata_length.py   length-only / no-length LOFO diagnosis and tree importances (Table 7, last rows)
  fig_holdout.py           <rev7_holdout.db> <out_prefix>  conformance matrix figure (figs/fig_holdout.pdf)
Seeds: numpy seed 11 (cluster bootstrap), per-domain seed sum(ord(domain)) for the LOFO benign quarter.
