#!/usr/bin/env python3
"""Per-scenario and per-session summary of E2 Test scores (frozen seed-42 RF-21 and the source RF-21).

The prediction export (e2_predictions.csv, about 149 MB) is not stored in the manuscript folder.
Usage : python3 analysis/e2_scenario_table.py /path/to/e2_predictions.csv
Output: generated/e2_scenario_rows.tex, generated/e2_scenario_summary.csv, generated/e2_session_summary.csv
"""
import os, sys
import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
p = pd.read_csv(sys.argv[1], usecols=["partition", "session_id", "variant", "threshold", "predict_proba", "ground_truth"],
                dtype={"partition": "category", "session_id": "category", "variant": "category"})
p = p[p.partition == "test"].copy()
p["scenario"] = p.session_id.astype(str).str.extract(r"E1_TEST_([A-Z]+)_")[0].str.lower()


def auc(neg, pos):
    """Mann-Whitney AUC: probability that a random positive outscores a random negative (ties count one half)."""
    s = pd.Series(np.concatenate([neg, pos])).rank(method="average").values
    r = s[len(neg):].sum()
    return (r - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


order = ["normal", "scan", "brute", "dos", "exploit"]
names = {"normal": "Normal", "scan": "TCP scan", "brute": "SSH brute force", "dos": "SYN flood", "exploit": "Exploit probing"}
v3 = p[p.variant == "V3_RF21_seed42"]
v1 = p[p.variant == "V1_source_direct"]
thr = float(v3.threshold.iloc[0])
rows, lines = [], []
for sc in order:
    a = v3[v3.scenario == sc].predict_proba.values
    b = v1[v1.scenario == sc].predict_proba.values
    r = dict(scenario=sc, sessions=v3[v3.scenario == sc].session_id.nunique(), flows=len(a), min=a.min(),
             median=float(np.median(a)), max=a.max(), flagged=int((a >= thr).sum()))
    if sc != "normal":
        r["auc_seed42"] = auc(v3[v3.scenario == "normal"].predict_proba.values, a)
        r["auc_source"] = auc(v1[v1.scenario == "normal"].predict_proba.values, b)
    rows.append(r)
    fmt = lambda x: f"{x:.3f}".replace("0.", ".", 1) if x < 1 else "1.000"
    au = "--" if sc == "normal" else fmt(r["auc_seed42"])
    as_ = "--" if sc == "normal" else fmt(r["auc_source"])
    lines.append(f"{names[sc]} & {r['sessions']} & {r['flows']:,} & {fmt(r['min'])} & {fmt(r['median'])} & {fmt(r['max'])} "
                 f"& {r['flagged']:,}/{r['flows']:,} & {au} & {as_} \\\\")
os.makedirs(os.path.join(ROOT, "generated"), exist_ok=True)
open(os.path.join(ROOT, "generated", "e2_scenario_rows.tex"), "w").write("\n".join(lines) + "\n")
pd.DataFrame(rows).to_csv(os.path.join(ROOT, "generated", "e2_scenario_summary.csv"), index=False, float_format="%.6f")
ses = v3.groupby("session_id", observed=True).predict_proba.agg(["size", "min", "median", "max"])
ses["flagged"] = v3.assign(f=v3.predict_proba >= thr).groupby("session_id", observed=True).f.sum()
ses.to_csv(os.path.join(ROOT, "generated", "e2_session_summary.csv"), float_format="%.6f")
print(pd.DataFrame(rows).to_string()); print(ses.to_string())
