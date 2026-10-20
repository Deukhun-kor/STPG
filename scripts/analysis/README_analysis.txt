Analysis scripts (run from repo root; numpy/scipy; rev_metadata_joint.py needs scikit-learn and pandas)
  python scripts/analysis/rev_main_defense.py results/rev5_main.db      # Table 7 (defense), cross-tab, off-task, detection summary
  python scripts/analysis/rev_holdout.py results/rev5_holdout.db        # Table 8 (hold-out counterfactual + actual)
  python scripts/analysis/rev_detection_stats.py results/rev5_main.db   # Table 9 trace-bootstrap CIs, DeLong, by-domain, threshold sweep
  python scripts/analysis/rev_cluster_stats.py results/rev5_main.db     # Table 9 cluster CIs, paired cluster dAUROC, McNemar
  python scripts/analysis/rev_operating_points.py results/rev5_main.db  # Table 10 a priori + FPR<=5%
  python scripts/analysis/rev_lodo_calibration.py results/rev5_main.db  # Table 10 transfer thresholds
  python scripts/rev_metadata_probe.py && python scripts/analysis/rev_metadata_joint.py results/rev3_metadata_features.csv   # Table 6
  python scripts/check_identity_gate.py                                 # Section 3.1 identity check
  python scripts/test_gate_offline.py                                   # policy branch test with a mock scorer
