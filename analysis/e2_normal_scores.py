#!/usr/bin/env python3
"""Summarize class counts and normal-flow score ranges per partition from the E2 prediction export.

The prediction export (e2_predictions.csv, about 149 MB) is not stored in the manuscript folder.
Usage: python3 analysis/e2_normal_scores.py /path/to/e2_predictions.csv
Output: experimental_results/e2_normal_score_summary.csv
"""
import os, sys
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src = sys.argv[1]
p = pd.read_csv(src, dtype={"partition": "category", "session_id": "category", "variant": "category"})
rows = []
for (part, var), g in p.groupby(["partition", "variant"], observed=True):
    nrm = g[g.ground_truth == 0].predict_proba
    atk = g[g.ground_truth == 1].predict_proba
    rows.append(dict(partition=part, variant=var, flows=len(g), normal_flows=len(nrm), attack_flows=len(atk),
                     threshold=float(g.threshold.iloc[0]),
                     normal_score_min=nrm.min(), normal_score_median=nrm.median(), normal_score_max=nrm.max(),
                     attack_score_p01=atk.quantile(0.01), attack_score_median=atk.median(),
                     normal_flagged=int((g[g.ground_truth == 0].predict_label == 1).sum())))
out = pd.DataFrame(rows)
out.to_csv(os.path.join(ROOT, "experimental_results", "e2_normal_score_summary.csv"), index=False, float_format="%.6f")
print(out.to_string())
