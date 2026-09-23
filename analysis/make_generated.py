#!/usr/bin/env python3
"""Regenerate the E3, E5, E6 and E7 table fragments and the E6 stage-latency figure.

Inputs : experimental_results/{e3,e5,e6,e7}/ (copied verbatim from the experiment owners' deliveries)
Outputs: generated/*.tex (table bodies read into main.tex with \\input) and
         figures/e6_stage_latency.pdf, plus generated/summary.json with every number used in the prose.
Usage  : python3 analysis/make_generated.py   (run from the manuscript root)
Requires Python 3.10+, pandas, numpy, matplotlib. No randomness except the seeded bootstrap.
"""
import json, math, os, re, hashlib
from math import comb
import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ER = os.path.join(ROOT, "experimental_results")
GEN = os.path.join(ROOT, "generated")
os.makedirs(GEN, exist_ok=True)
os.makedirs(os.path.join(ROOT, "figures"), exist_ok=True)
S = {}  # summary of every number quoted in prose


def binom_cdf(k, n, p):
    return sum(comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(0, k + 1))


def clopper_pearson(x, n, alpha=0.05):
    """Exact two-sided interval by bisection on the binomial tail (no scipy needed)."""
    if n == 0:
        return (float("nan"), float("nan"))

    def solve(f, lo=0.0, hi=1.0):
        for _ in range(200):
            mid = (lo + hi) / 2
            if f(mid):
                hi = mid
            else:
                lo = mid
        return (lo + hi) / 2

    lower = 0.0 if x == 0 else solve(lambda p: 1 - binom_cdf(x - 1, n, p) >= alpha / 2)
    upper = 1.0 if x == n else solve(lambda p: binom_cdf(x, n, p) <= alpha / 2)
    return (lower, upper)


def mcnemar_exact(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(comb(n, i) for i in range(0, k + 1)) / 2 ** n)


def f3(x):
    return f"{x:.3f}".replace("0.", ".", 1) if x < 1 else f"{x:.2f}"


def ci(lo, hi):
    return f"[{f3(lo)}, {f3(hi)}]"


# ---------------------------------------------------------------- E2 (Test partition, frozen variants)
e2m = pd.read_csv(os.path.join(ER, "e2_v21_metrics.csv"))
e2t = e2m[e2m.partition == "test"].set_index("variant")
e2names = [("V1_source_direct", "Source RF-21, inherited threshold"), ("V1_inverted", "Source score, inverted"),
           ("V2a_platt_devcal", "Platt on inverted score"), ("V2b_isotonic_devcal", "Isotonic on inverted score"),
           ("V3_RF21_seed42", "Retrained RF-21, seed 42"), ("V4_noTTL_seed42", "Retrained without IP-TTL, seed 42")]
e2rows, e2s = [], {}
for key, name in e2names:
    r = e2t.loc[key]
    tp, fp, fn, tn = int(r.tp), int(r.fp), int(r.fn), int(r.tn)
    assert tp + fp + fn + tn == int(r.n_flows) == 203677
    f1 = 2 * tp / (2 * tp + fp + fn); spe = tn / (tn + fp); rec = tp / (tp + fn); ba = (rec + spe) / 2
    assert abs(f1 - r.f1) < 1e-4 and abs(spe - r.specificity) < 1e-4 and abs(ba - r.balanced_accuracy) < 1e-4
    e2s[key] = dict(tp=tp, fp=fp, fn=fn, tn=tn, f1=f1, spec=spe, balacc=ba, auc=float(r.roc_auc),
                    brier=float(r.brier), ece=float(r.ece), threshold=float(r.threshold))
    e2rows.append(f"{name} & {r.threshold:.4g} & {tp:,} & {fp:,} & {fn:,} & {tn:,} & {f1:.4f} & {spe:.4f} & {ba:.4f} & {r.roc_auc:.4f} \\\\"
                  .replace("0.", ".").replace(" 1.0000", " 1.0000"))
S["e2_test"] = e2s
open(os.path.join(GEN, "e2_adaptation_rows.tex"), "w").write("\n".join(e2rows) + "\n")

# ---------------------------------------------------------------- E3
m = pd.read_csv(os.path.join(ER, "e3", "e3_event_matches.csv"))
strategies = [("S1", "S1", "Suricata only"), ("S2", "S2", "RF only"), ("S3", "S3_W60", "Correlated AND ($W{=}60$ s)"),
              ("S4", "S4", "Permissive OR"), ("S5", "S5", "Weighted evidence$^{\\ast}$"), ("S6", "S6", "Evidence-aware trigger")]
rng = np.random.default_rng(20260921)
rows = []
e3 = {}
for src in ["primary", "supplementary"]:
    d = m[m.source == src].sort_values("session_id").reset_index(drop=True)
    y = d.gt_label.values
    att = np.where(y == 1)[0]
    nor = np.where(y == 0)[0]
    s1_correct = (d["S1"].values == y)
    for key, col, name in strategies:
        p = d[col].values
        tp = int(((p == 1) & (y == 1)).sum()); fp = int(((p == 1) & (y == 0)).sum())
        fn = int(((p == 0) & (y == 1)).sum()); tn = int(((p == 0) & (y == 0)).sum())
        rec = tp / (tp + fn); spe = tn / (tn + fp); ba = (rec + spe) / 2
        rlo, rhi = clopper_pearson(tp, tp + fn); slo, shi = clopper_pearson(tn, tn + fp)
        # stratified session bootstrap of balanced accuracy (12 attack + 3 normal draws)
        bas = []
        for _ in range(10000):
            ia = rng.choice(att, len(att)); iN = rng.choice(nor, len(nor))
            r_ = (p[ia] == 1).mean(); s_ = (p[iN] == 0).mean(); bas.append((r_ + s_) / 2)
        blo, bhi = np.percentile(bas, [2.5, 97.5])
        xc = (p == y)
        b = int((s1_correct & ~xc).sum()); c = int((~s1_correct & xc).sum())
        pv = mcnemar_exact(b, c)
        e3[f"{src}_{key}"] = dict(TP=tp, FP=fp, FN=fn, TN=tn, recall=rec, recall_ci=[rlo, rhi], spec=spe, spec_ci=[slo, shi],
                                 balacc=ba, balacc_boot_ci=[float(blo), float(bhi)], mcnemar_b=b, mcnemar_c=c, mcnemar_p=pv)
        mc = "--" if key == "S1" else f"{b}/{c}, {pv:.3f}".replace("0.", ".", 1)
        rows.append((src, name, tp, fp, fn, tn, f"{f3(rec)} {ci(rlo, rhi)}", f"{f3(spe)} {ci(slo, shi)}",
                     f"{f3(ba)}", mc))
    # window sensitivity for the correlated AND
    for w in [10, 30, 60, 120]:
        col = "S3_W60" if w == 60 else f"S3_W{w}"
        p = d[col].values
        e3[f"{src}_S3_W{w}"] = dict(TP=int(((p == 1) & (y == 1)).sum()), FP=int(((p == 1) & (y == 0)).sum()))
    e3[f"{src}_tiers"] = d.groupby(["routing_tier_W60", "gt_label"]).size().unstack(fill_value=0).to_dict()
    e3[f"{src}_alerts_total"] = int(d.supp_alerts.sum() if src == "supplementary" else d.primary_alerts.sum())
    e3[f"{src}_flows_total"] = int(d.total_flows.sum()); e3[f"{src}_rfpos_total"] = int(d.rf_positive_flows.sum())
S["e3"] = e3
with open(os.path.join(GEN, "e3_fusion_rows.tex"), "w") as f:
    for src in ["primary", "supplementary"]:
        label = ("Primary source: frozen E1 EVE, Suricata 8.0.4" if src == "primary"
                 else "Supplementary source: offline replay, Suricata 7.0.3 with a different ruleset (diagnostic only)")
        f.write(f"\\multicolumn{{9}}{{@{{}}l}}{{\\emph{{{label}}}}} \\\\\n")
        for r in [x for x in rows if x[0] == src]:
            f.write(" & ".join(str(v) for v in r[1:]) + " \\\\\n")
        if src == "primary":
            f.write("\\midrule\n")

# provenance-blind versus evidence-aware queue assignment (exploratory, post hoc policy)
rq = pd.read_csv(os.path.join(ER, "e3", "E3_RQ3_LAM_SELF_REFERENCE_COMPARISON.csv"), encoding="utf-8-sig")
rt = {}
for src in ["primary", "supplementary"]:
    d = rq[rq.source == src]
    rt[src] = dict(n=int(len(d)), blind=d.provenance_blind_route.value_counts().to_dict(),
                   aware=d.evidence_aware_route.value_counts().to_dict(), changed=int(d.route_label_changed.sum()),
                   blind_exact=int(d.blind_exact_self_reference_match.sum()), aware_exact=int(d.aware_exact_self_reference_match.sum()),
                   blind_perm=int(d.blind_permissible_self_reference_match.sum()), aware_perm=int(d.aware_permissible_self_reference_match.sum()),
                   independent_reference=d.independent_reference.unique().tolist())
S["e3_routing"] = rt

# ---------------------------------------------------------------- E5
e5m = pd.read_csv(os.path.join(ER, "e5", "e5_automatic_metrics.csv"))
out = [json.loads(l) for l in open(os.path.join(ER, "e5", "e5_model_outputs.jsonl"), encoding="utf-8")]
od = pd.DataFrame(out)


def norm_ev(ev):
    s = json.dumps(ev, sort_keys=True, ensure_ascii=False)
    s = re.sub(r"\d{4}-\d{2}-\d{2}T[\d:.+]+Z?", "T", s)
    s = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "IP", s)
    return hashlib.md5(s.encode()).hexdigest()


cases = od.drop_duplicates("case_ref")
e5 = dict(cases=int(e5m.case_ref.nunique()), outputs=int(len(e5m)),
          distinct_profiles=int(cases.observed_evidence.apply(norm_ev).nunique()),
          alert_count_cases=e5m.drop_duplicates("case_ref").observed_alert_count.value_counts().sort_index().to_dict(),
          modes={})
names = {"deterministic_only": "Deterministic template", "always_llm": "Always-on model", "selective_llm": "Selective model"}
e5rows = []
for mode in ["deterministic_only", "always_llm", "selective_llm"]:
    d = e5m[e5m["mode"] == mode]
    L = d[d.llm_invoked]
    vc = d.output_validation.value_counts()
    rec = dict(outputs=int(len(d)), cases=int(d.case_ref.nunique()), reps=int(d.repetition.max()), llm_calls=int(d.llm_invoked.sum()),
               valid=int(vc.get("SCHEMA_VALID_NOT_FACT_CHECKED", 0)), invalid_structure=int(vc.get("INVALID_STRUCTURE", 0)),
               invalid_evidence=int(vc.get("INVALID_EVIDENCE_FIELD", 0)),
               invalid_among_llm=int((L.output_validation != "SCHEMA_VALID_NOT_FACT_CHECKED").sum()),
               lat_p50=float(L.latency_seconds.median()) if len(L) else None,
               lat_p95=float(L.latency_seconds.quantile(0.95)) if len(L) else None,
               tok_med=float(L.completion_tokens.median()) if len(L) else None,
               human_ratings=int((d.factual_correctness != "NOT_ASSESSED").sum()))
    e5["modes"][mode] = rec
    lat = "--" if rec["lat_p50"] is None else f"{rec['lat_p50']:.2f} / {rec['lat_p95']:.2f}"
    tok = "--" if rec["tok_med"] is None else f"{rec['tok_med']:.1f}"
    e5rows.append(f"{names[mode]} & {rec['cases']} & {rec['reps']} & {rec['outputs']} & {rec['llm_calls']} & {rec['valid']} & "
                  f"{rec['invalid_structure']} & {rec['invalid_evidence']} & {lat} & {tok} \\\\")
S["e5"] = e5
open(os.path.join(GEN, "e5_rows.tex"), "w").write("\n".join(e5rows) + "\n")

# ---------------------------------------------------------------- E6
E6 = os.path.join(ER, "e6")
thr = pd.read_csv(os.path.join(E6, "E6_SUPPLEMENT_THROUGHPUT_v547.csv")).set_index("rate")
fx = pd.read_csv(os.path.join(E6, "E6_SUPPLEMENT_FLOW_EXPIRATION_v547.csv"))
t09 = pd.read_csv(os.path.join(E6, "E6_T09_RESPONSE_LATENCY.csv"))
t08 = pd.read_csv(os.path.join(E6, "E6_T08_PACKET_PLANE.csv"))
t11 = pd.read_csv(os.path.join(E6, "E6_T11_RATE_SUMMARY.csv")).set_index("rate")
t07 = pd.read_csv(os.path.join(E6, "E6_T07_RESOURCES.csv"))
t10 = pd.read_csv(os.path.join(E6, "E6_T10_QUEUE_DEPTH.csv"))
t02 = pd.read_csv(os.path.join(E6, "E6_T02_PHASE_A_SUMMARY.csv")).set_index("rate")
e6 = {}
rowsA, rowsB = [], []
for r in ["0.5x", "1.0x", "2.0x"]:
    t = thr.loc[r]
    fe = fx[(fx.rate == r) & (fx.stage == "flow_expiration_delay_ms")].iloc[0]
    q = t09[(t09.rate == r)].set_index("stage")
    res = t07[t07.rate == r]; qd = t10[t10.rate == r]
    # independent route for resources and queue: recompute from per-run tables
    rec = dict(runs=int(t.n_measured), replay_s=float(t.mean_replay_s), pps=float(t.mean_packet_throughput_pps),
               min_ratio=float(t.min_achieved_rate_ratio), sender_drop=float(t.sender_drop_ratio),
               cap_drop=float(t.capture_drop_ratio), suri_drop=float(t.suricata_drop_ratio),
               flows_a=float(t.phase_a_mean_flows), flows_b=float(t.phase_b_mean_flows),
               det_p50=float(t.detector_total_p50_ms), det_p99=float(t.detector_total_p99_ms),
               fe_p50=float(fe.p50_ms) / 1000, fe_p95=float(fe.p95_ms) / 1000, fe_n=int(fe.n_flows),
               llm_p50=float(t.llm_wait_p50_ms_completed_only) / 1000, llm_p95=float(t.llm_wait_p95_ms_completed_only) / 1000,
               e2e_p50=float(t.e2e_flow_to_audit_p50_ms_completed_only) / 1000, e2e_p95=float(t.e2e_flow_to_audit_p95_ms_completed_only) / 1000,
               completion=float(t.downstream_completion_ratio), completed_events=int(q.loc["e2e_flow_to_audit", "n_events"]),
               q_peak=(int(t.queue_peak_min), int(t.queue_peak_max)), q_stop=(int(t.queue_active_at_stop_min), int(t.queue_active_at_stop_max)),
               q_peak_recomputed=(int(qd.peak_depth.min()), int(qd.peak_depth.max())), drained=bool(t.queue_drained_all_runs),
               cpu_mean=float(t.cpu_mean_pct_avg), cpu_peak=float(t.cpu_peak_pct_max), ram_mean_gb=float(t.ram_mean_mb_avg) / 1024,
               cpu_mean_recomputed=float(res.cpu_mean_pct.mean()), ram_mean_recomputed_gb=float(res.ram_mean_mb.mean()) / 1024,
               max_sustainable=str(t11.loc[r, "max_sustainable"]),
               live_after_replay_share=1 - float(t02.loc[r, "flows_before_replay_end"]) / float(t02.loc[r, "total_live_flows"]),
               completed_per_run=int(q.loc["e2e_flow_to_audit", "n_events"]) / int(t.n_measured))
    e6[r] = rec
    rowsA.append(f"{r} & {rec['runs']} & {rec['pps']:.0f} & {rec['min_ratio']:.4f} & {round(rec['sender_drop']*50622)}/{rec['cap_drop']:.0f}/{rec['suri_drop']:.0f} & "
                 f"{rec['flows_a']:,.0f} / {rec['flows_b']:,.0f} & {rec['live_after_replay_share']*100:.1f}\\% & {rec['det_p50']:.1f} / {rec['det_p99']:.1f} & "
                 f"{rec['fe_p50']:.1f} / {rec['fe_p95']:.1f} & {rec['cpu_mean']:.1f} / {rec['cpu_peak']:.1f} & {rec['ram_mean_gb']:.1f} \\\\")
    rowsB.append(f"{r} & {rec['flows_a']:,.0f} & {rec['completed_per_run']:.1f} & {rec['completion']*100:.1f}\\% & {rec['q_peak'][0]:,}--{rec['q_peak'][1]:,} & "
                 f"{rec['q_stop'][0]:,}--{rec['q_stop'][1]:,} & {rec['llm_p50']:.1f} / {rec['llm_p95']:.1f} & "
                 f"{rec['e2e_p50']:.1f} / {rec['e2e_p95']:.1f} & Not established \\\\")
pp = t08[t08.packet_plane_pass == "PASS"]
fin = t08[t08.rate_tested == "PP_98.88x_FINAL"].iloc[0]
e6["packet_plane"] = dict(final_rate="98.88x", final_runs=int(fin.n_meas), final_ratio=float(fin.achieved_rate_ratio),
                          ratio_96=float(t08[t08.rate_tested == "PP_96.0x"].achieved_rate_ratio.iloc[0]),
                          ratio_98=float(t08[t08.rate_tested == "PP_98.0x"].achieved_rate_ratio.iloc[0]),
                          ratio_99=float(t08[t08.rate_tested == "PP_99.0x"].achieved_rate_ratio.iloc[0]),
                          replay_99=float(t11.loc["PP_99.0x", "mean_replay_s"]), replay_100=float(t11.loc["PP_100.0x", "mean_replay_s"]),
                          suri_ratio_100=float(t11.loc["PP_100.0x", "max_suri_ratio"]))
t01 = pd.read_csv(os.path.join(E6, "E6_T01_RUN_INDEX.csv"))
pp_runs = t01[(t01.rate_label == "PP_98.88x_FINAL") & (t01.is_warmup.astype(str).str.lower().isin(["false", "0"]))]
pp_pps = float((pp_runs.sent / pp_runs.replay_s).mean())
e6["packet_plane"]["pps_mean_of_runs"] = pp_pps
e6["packet_plane"]["n_runs_t01"] = int(len(pp_runs))
rowsA.append(f"98.88x$^{{\\dagger}}$ & {e6['packet_plane']['final_runs']} & {pp_pps:,.0f} & "
             f"{e6['packet_plane']['final_ratio']:.4f} & {round(float(t11.loc['PP_98.88x_FINAL','max_sender_ratio'])*50622)}/{float(t11.loc['PP_98.88x_FINAL','max_cap_ratio']):.0f}/{float(t11.loc['PP_98.88x_FINAL','max_suri_ratio']):.0f} & "
             f"0 / {float(t11.loc['PP_98.88x_FINAL','mean_b_flows']):,.0f} & -- & -- & -- & -- & -- \\\\")
S["e6"] = e6
open(os.path.join(GEN, "e6_packet_rows.tex"), "w").write("\n".join(rowsA) + "\n")
open(os.path.join(GEN, "e6_response_rows.tex"), "w").write("\n".join(rowsB) + "\n")

# E6 stage-latency figure at the 1.0x reference load (completed events only for downstream stages)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
q = t09[t09.rate == "1.0x"].set_index("stage")
fe1 = fx[(fx.rate == "1.0x") & (fx.stage == "flow_expiration_delay_ms")].iloc[0]
stages = [("Flow expiration (live path)", pd.Series({"p50_ms": fe1.p50_ms, "p95_ms": fe1.p95_ms})),
          ("Feature extraction", q.loc["feature_extraction"]), ("RF prediction", q.loc["rf_predict"]),
          ("NIDS normalization", q.loc["nids_normalization"]), ("Elasticsearch indexing", q.loc["es_indexing"]),
          ("Index confirmation to queue", q.loc["es_confirmed_to_queue"]), ("Policy evaluation", q.loc["policy_eval"]),
          ("LLM wait", q.loc["llm_wait"]), ("Audit completion", q.loc["audit_completion"]),
          ("Flow to audit, end to end", q.loc["e2e_flow_to_audit"])]
plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
                     "font.size": 8, "axes.linewidth": 0.6})
fig, ax = plt.subplots(figsize=(3.45, 2.6))
ink, blue = "#0b0b0b", "#2a78d6"
n = len(stages)
for i, (lab, row) in enumerate(stages):
    yv = n - 1 - i
    p50, p95 = float(row["p50_ms"]), float(row["p95_ms"])
    ax.plot([p50, p95], [yv, yv], color=blue, lw=2, solid_capstyle="round", alpha=0.45)
    ax.plot([p50], [yv], "o", ms=5, color=blue, mec="white", mew=0.8, zorder=3)
    ax.plot([p95], [yv], "|", ms=7, color=blue, mew=1.4, zorder=3)
ax.axhline(0.5, color="#8a8984", lw=0.6, ls=(0, (2, 2)))
ax.set_yticks(range(n))
ax.set_yticklabels([s_[0] for s_ in stages][::-1], color=ink)
ax.set_xscale("log")
ax.set_xlim(5e-3, 1e6)
ax.set_xticks([1e-2, 1e0, 1e2, 1e4, 1e6])
ax.set_xticklabels(["10 \u00b5s", "1 ms", "100 ms", "10 s", "1000 s"])
ax.minorticks_off()
ax.set_xlabel("Latency at 1.0x load (log scale)", color=ink)
ax.grid(axis="x", color="#d9d8d4", lw=0.5)
ax.set_axisbelow(True)
for sp in ["top", "right"]:
    ax.spines[sp].set_visible(False)
ax.tick_params(colors="#52514e", length=2)
fig.tight_layout(pad=0.3)
fig.savefig(os.path.join(ROOT, "figures", "e6_stage_latency.pdf"))
fig.savefig(os.path.join(GEN, "e6_stage_latency_preview.png"), dpi=200)

# ---------------------------------------------------------------- E7
E7 = os.path.join(ER, "e7")
inc = pd.read_csv(os.path.join(E7, "e7_lam_incidents.csv"))
snap = pd.read_csv(os.path.join(E7, "e7_lam_minute_snapshots.csv"))
man = json.load(open(os.path.join(E7, "observer_manifest.json")))
rep = [json.loads(l) for l in open(os.path.join(E7, "e7_replay_manifest.jsonl"))]
rts = pd.to_datetime([r["replay_timestamp"] for r in rep], utc=True)
src_sessions = sorted({re.sub(r"_f?\d+$", "", r["source_es_id"]) for r in rep})
e7 = dict(observed_hours=man["elapsed_hours"], samples=man["observation_count"], observer_errors=man["observer_errors"],
          replayed=len(rep), distinct_source=len({r["source_es_id"] for r in rep}), distinct_target=len({r["target_es_id"] for r in rep}),
          created=sum(r["write_result"] == "created" for r in rep), replay_span_min=float((rts.max() - rts.min()).total_seconds() / 60),
          incidents=int(len(inc)), category=inc.category.value_counts().to_dict(), severity=inc.severity.value_counts().to_dict(),
          execution=inc.execution_status.value_counts().to_dict(), approval=inc.approval_status.fillna("EMPTY").value_counts().to_dict(),
          llm=inc.llm_status.value_counts().to_dict(), provenance=inc.provenance.value_counts().to_dict(),
          cpu_mean=float(snap.host_cpu_percent.dropna().mean()), cpu_n=int(snap.host_cpu_percent.notna().sum()), cpu_min=float(snap.host_cpu_percent.min()),
          cpu_max=float(snap.host_cpu_percent.max()), queue_active_max=int(snap.queue_active.max()),
          queue_dead_max=int(snap.queue_dead.max()), control_audit_max=int(snap.control_audit_total.max()),
          source_ids_example=rep[0]["source_es_id"])
S["e7"] = e7

json.dump(S, open(os.path.join(GEN, "summary.json"), "w"), indent=1, default=lambda o: o if not isinstance(o, (np.integer, np.floating)) else o.item())
print(json.dumps({k: (v if k != "e3" else "...") for k, v in S.items()}, indent=1, default=str)[:6000])
