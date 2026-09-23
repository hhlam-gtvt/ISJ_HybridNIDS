#!/usr/bin/env python3
"""Recompute the supplementary E6 replay figures from the per-incident traces.

    python3 analysis/e6_supplementary_check.py
"""
import glob
import pandas as pd

BASE = "experimental_results/e6/supplementary_v552_20260923/E6_2R_MEASURED/"
for run in sorted(glob.glob(BASE + "*/")):
    t = pd.read_csv(run + "e6_response_trace.csv")
    q = pd.read_csv(run + "e6_queue_insert_events.csv")
    r = pd.read_csv(run + "e6_llm_routing_events.csv")
    done = pd.to_numeric(t["t_queue_done"], errors="coerce")
    llm = r[r["route"] == "LLM_RESERVED"]
    print(run.split("/")[-2],
          f"incidents={t['es_id'].nunique()} flows={t['e6_member_count'].sum()}",
          f"done={(t['queue_completed_status'] == 'DONE').sum()}",
          f"quarantined_normal={(t['trace_outcome'].str.startswith('QUARANTINED')).sum()}",
          f"model_calls={int(pd.to_numeric(t['model_http_attempts'], errors='coerce').sum())}",
          f"call_s={[round(x / 1000, 1) for x in llm['duration_ms']]}",
          f"last_done_after_last_insert_s={done.max() - q['t_queue_inserted'].max():.1f}")
