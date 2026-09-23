#!/usr/bin/env python3
"""Score distribution of the frozen retrained RF-21 (seed 42) by scenario: Development calibration versus Test.

Only the five Development calibration sessions are shown for Development, because the ten training sessions are
in-sample for the model. The prediction export (e2_predictions.csv, about 149 MB) is not stored in the manuscript folder.
Usage : python3 analysis/e2_score_figure.py /path/to/e2_predictions.csv
Output: figures/e2_scores_seed42.pdf and generated/e2_scores_seed42_summary.csv
"""
import os, sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
p = pd.read_csv(sys.argv[1], usecols=["partition", "session_id", "variant", "threshold", "predict_proba"],
                dtype={"partition": "category", "session_id": "category", "variant": "category"})
p = p[(p.variant == "V3_RF21_seed42") & (p.partition.isin(["dev_cal", "test"]))].copy()
thr = float(p.threshold.iloc[0])
p["scenario"] = p.session_id.astype(str).str.extract(r"E1_(?:DEV|TEST)_([A-Z]+)_")[0].str.lower()
p["period"] = np.where(p.partition.astype(str) == "test", "Test", "Dev. calibration")
order = ["normal", "scan", "brute", "dos", "exploit"]
labels = {"normal": "Normal", "scan": "Scan", "brute": "Brute force", "dos": "SYN flood", "exploit": "Exploit"}
rows = []
plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
                     "font.size": 8, "axes.linewidth": 0.6})
fig, ax = plt.subplots(figsize=(3.45, 2.5))
pos, ticks, ticklab = 0, [], []
for sc in order:
    for per, col in [("Dev. calibration", "#9dbfe9"), ("Test", "#2a78d6")]:
        v = p[(p.scenario == sc) & (p.period == per)].predict_proba.values
        if len(v):
            rows.append(dict(scenario=sc, period=per, flows=len(v), min=v.min(), median=np.median(v), max=v.max(),
                             share_above_threshold=float((v >= thr).mean())))
            ax.boxplot([v], positions=[pos], widths=0.6, whis=(0, 100), patch_artist=True, showfliers=False,
                       boxprops=dict(facecolor=col, edgecolor="#0b0b0b", lw=0.6), medianprops=dict(color="#0b0b0b", lw=1),
                       whiskerprops=dict(lw=0.6), capprops=dict(lw=0.6))
            ax.text(pos, 1.035, f"{len(v):,}", ha="center", va="bottom", fontsize=5.5, color="#52514e", rotation=90)
        pos += 0.8
    ticks.append(pos - 1.2); ticklab.append(labels[sc]); pos += 0.6
ax.axhline(thr, color="#eb6834", lw=1, ls=(0, (3, 2)))
ax.text(-0.45, thr + 0.03, f"frozen threshold {thr:.2f}", ha="left", va="bottom", fontsize=7, color="#52514e")
ax.set_xticks(ticks); ax.set_xticklabels(ticklab)
ax.set_ylabel("RF-21 attack score (seed 42)")
ax.set_ylim(-0.02, 1.22); ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
for sp in ["top", "right"]:
    ax.spines[sp].set_visible(False)
ax.plot([], [], "s", color="#9dbfe9", label="Dev. calibration"); ax.plot([], [], "s", color="#2a78d6", label="Test")
ax.legend(frameon=False, fontsize=7, loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=2)
fig.tight_layout(pad=0.3)
fig.savefig(os.path.join(ROOT, "figures", "e2_scores_seed42.pdf"))
pd.DataFrame(rows).to_csv(os.path.join(ROOT, "generated", "e2_scores_seed42_summary.csv"), index=False, float_format="%.6f")
print(pd.DataFrame(rows).to_string())
