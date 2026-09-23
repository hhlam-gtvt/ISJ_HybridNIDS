#!/usr/bin/env python3
"""Inter-rater agreement for the blinded E5 ratings.

Reads experimental_results/e5/ratings_20260922/e5_blinded_ratings.csv (two reviewers,
210 outputs, four 1-5 criteria) and prints, per criterion, the linear-weighted Cohen
kappa, a 95% percentile interval from a bootstrap over the 30 incidents (case_ref),
exact agreement, and each reviewer's mean. Seed 20260923, 1000 replicates.

    python3 analysis/e5_agreement.py
"""
import numpy as np
import pandas as pd

PATH = "experimental_results/e5/ratings_20260922/e5_blinded_ratings.csv"
CRIT = ["factual_correctness_1_5", "evidence_traceability_1_5",
        "actionability_1_5", "workload_1_5_lower_better"]
K = 5


def kappa_linear(a, b):
    a = np.asarray(a, int) - 1
    b = np.asarray(b, int) - 1
    o = np.zeros((K, K))
    np.add.at(o, (a, b), 1)
    o /= o.sum()
    e = np.outer(o.sum(1), o.sum(0))
    i, j = np.indices((K, K))
    w = np.abs(i - j) / (K - 1)
    return 1 - (w * o).sum() / (w * e).sum()


df = pd.read_csv(PATH)
wide = df.pivot_table(index=["blind_id", "case_ref"], columns="reviewer_id", values=CRIT).reset_index()
cases = wide["case_ref"].unique()
rng = np.random.default_rng(20260923)
boot = [rng.choice(cases, len(cases), replace=True) for _ in range(1000)]
groups = {c: wide[wide["case_ref"] == c] for c in cases}
print(f"outputs={len(wide)} incidents={len(cases)}")
for c in CRIT:
    r1, r2 = wide[(c, "R1")], wide[(c, "R2")]
    ks = []
    for s in boot:
        d = pd.concat([groups[x] for x in s])
        ks.append(kappa_linear(d[(c, "R1")], d[(c, "R2")]))
    lo, hi = np.percentile(ks, [2.5, 97.5])
    print(f"{c}: kappa={kappa_linear(r1, r2):.3f} CI=[{lo:.3f},{hi:.3f}] "
          f"exact={np.mean(r1 == r2):.3f} mean_R1={r1.mean():.2f} mean_R2={r2.mean():.2f}")

# Consistency of each reviewer on identical outputs: groups of byte-identical outputs of the
# same case, the share of groups scored identically, and the mean within-group score range
# against randomly regrouped scores of the same reviewer (seed 20260923, 2,000 draws).
import hashlib
df["_h"] = df["generated_output"].astype(str).map(lambda s: hashlib.sha256(s.encode()).hexdigest())
rng2 = np.random.default_rng(20260923)
same_total = cells = 0
for rv in ["R1", "R2"]:
    s = df[df["reviewer_id"] == rv]
    groups = [g for _, g in s.groupby(["case_ref", "_h"]) if len(g) >= 2]
    sizes = sorted({len(g) for g in groups})
    for c in CRIT:
        same = sum(g[c].nunique() == 1 for g in groups)
        same_total += same
        cells += len(groups)
        obs = np.mean([g[c].max() - g[c].min() for g in groups])
        vals = s[c].to_numpy()
        sims = []
        for _ in range(2000):
            perm = rng2.permutation(vals)
            k = 0
            rs = []
            for g in groups:
                seg = perm[k:k + len(g)]
                k += len(g)
                rs.append(seg.max() - seg.min())
            sims.append(np.mean(rs))
        print(f"{rv} {c}: groups={len(groups)} sizes={sizes} identical_scores={same} "
              f"mean_range={obs:.2f} random_mean_range={np.mean(sims):.2f}")
print(f"groups scored identically: {same_total} of {cells}")
