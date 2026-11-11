#!/usr/bin/env python3
"""Launcher for unchanged E6 v552 wrapper. Off arm replaces ONLY the choose_llm decision.
This is a laboratory ablation, not the originally frozen implementation.
"""
import os, pathlib, runpy, sys
BASE = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / "e6_integration"))
sys.path.insert(0, str(BASE))
mode = os.environ.get("E6_AB_FORCE_LLM_OFF")
if mode not in {"0", "1"}:
    raise SystemExit("STOP: E6_AB_FORCE_LLM_OFF must be 0 or 1")
if mode == "1":
    import e6_incident_gate as gate
    def llm_disabled(connect, event, decision, analysis_mode, *, now=None):
        # Preserve the original gate's grouped-incident integrity preconditions.
        if event.raw.get("e6.incident_id") != str(event.es_id):
            raise RuntimeError("E6 AB off arm received ungrouped queue work")
        if int(event.raw.get("e6.member_count") or 0) < 1:
            raise RuntimeError("E6 AB off arm has no flow members")
        # Intentionally no LLM reservation in this intervention arm.
        # The unchanged wrapper's denied path runs Static RAG.
        gate.ensure_schema(connect)
        return False, "AB_LLM_OFF_STATIC_RAG"
    gate.choose_llm = llm_disabled
wrapper = BASE / "e6_integration/e6_trace_wrapper_lam_v552.py"
if not wrapper.is_file():
    raise SystemExit("STOP: missing frozen E6 v552 wrapper")
runpy.run_path(str(wrapper), run_name="__main__")
