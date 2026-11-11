"""Recompute the figures that the revised manuscript reports for the four post-review experiments.

Inputs (read-only), all under experimental_results/reviewer_revision/new_experiments/:
  01_Suricata_60_runs/per_session_results.csv, experiment_manifest.json
  02_E6_V2/e6_v2_4arm_kpi_summary.csv, audit_v2_fixed_partition/audit_v2.json
  03_E8_SOAR/e8_original_runtime_gap_audit.json, e8_high_path_isolated_test_report.json
  04_Security/security_review_isolated_test_report.json
Output: experimental_results/reviewer_revision/revision_evidence_summary.json.
The inputs are summary exports of the experiment workstation. This script checks that the
manuscript's tables follow from them; it does not rerun Suricata, the queue or the prototypes.
Standard library only.
"""
import csv, hashlib, json, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NEW = os.path.join(ROOT, "experimental_results", "reviewer_revision", "new_experiments")
OUT = os.path.join(ROOT, "experimental_results", "reviewer_revision", "revision_evidence_summary.json")
p = lambda *a: os.path.join(NEW, *a)
sha = lambda f: hashlib.sha256(open(f, "rb").read()).hexdigest()

# --- 1. Suricata engine-by-checksum replay (Table X of the revised manuscript)
rows = list(csv.DictReader(open(p("01_Suricata_60_runs", "per_session_results.csv"), newline="")))
man = json.load(open(p("01_Suricata_60_runs", "experiment_manifest.json")))
sessions = sorted({r["session"] for r in rows}); engines = sorted({r["engine"] for r in rows})
modes = sorted({r["checksum"] for r in rows})
assert len(rows) == 60 and len(sessions) == 15 and engines == ["7.0.3", "8.0.4"] and modes == ["all", "none"]
alerts = {(r["session"], r["engine"], r["checksum"]): int(r["alert_events"]) for r in rows}
assert len(alerts) == 60
cells = {}
for e in engines:
    for c in modes:
        v = [alerts[(s, e, c)] for s in sessions]
        cells[f"{e}/{c}"] = {"alerts": sum(v), "sessions_with_alerts": sum(x > 0 for x in v)}
suricata = {
    "runs": len(rows),
    "runs_valid_eve": sum(r["valid_eve"] == "True" for r in rows),
    "runs_exit_code_0": sum(r["exit_code"] == "0" for r in rows),
    "cells": cells,
    "sessions_with_any_alert": {s: [alerts[(s, e, c)] for e in engines for c in modes]
                                for s in sessions if any(alerts[(s, e, c)] for e in engines for c in modes)},
    "cell_order": [f"{e}/{c}" for e in engines for c in modes],
    "engine_pairs_differing": sum(alerts[(s, "7.0.3", c)] != alerts[(s, "8.0.4", c)] for s in sessions for c in modes),
    "engine_pairs": len(sessions) * len(modes),
    "checksum_pairs_differing": sum(alerts[(s, e, "all")] != alerts[(s, e, "none")] for s in sessions for e in engines),
    "checksum_pairs": len(sessions) * len(engines),
    "rules_loaded": sorted({v["rule_counts"]["loaded"] for v in man["preflight_results"].values()}),
    "rule_file_sha256": sorted({v["file_sha256"] for v in man["rules"].values()}),
    "ruleset_effect_tested": man["ruleset_effect_tested"],
    "results_csv_sha256_matches_manifest": sha(p("01_Suricata_60_runs", "per_session_results.csv")) == man["results_csv_sha256"],
    "distinct_pcap_sha256": len({r["pcap_sha256"] for r in rows}),
}
# the 15 captures are the E1 Test captures of the original release
e1 = open(os.path.join(ROOT, "experimental_results", "e1_pcap_sha256.txt"), encoding="utf8").read()
suricata["pcap_hashes_found_in_e1_manifest"] = sum(h in e1 for h in man["pcap_hashes"].values())

# --- 2. E6 V2 four-arm replay (Table XVIII)
kpi = list(csv.DictReader(open(p("02_E6_V2", "e6_v2_4arm_kpi_summary.csv"), newline="")))
aud = json.load(open(p("02_E6_V2", "audit_v2_fixed_partition", "audit_v2.json")))
s3 = lambda ms: round(float(ms) / 1000.0, 3)
e6 = {r["arm"]: {"flows": int(r["member_flows"]), "jobs_done": int(r["jobs_done"]), "jobs_total": int(r["jobs_total"]),
                 "quarantine_jobs": int(r["normal_quarantine_jobs"]), "quarantine_flows": int(r["normal_quarantine_flows"]),
                 "wait_p95_s": s3(r["queue_wait_p95_ms"]), "worker_p95_s": s3(r["worker_to_done_p95_ms"]),
                 "queue_to_done_p95_s": s3(r["queue_to_done_p95_ms"]), "llm_http": int(r["http_attempts_trace"])} for r in kpi}
e6_partition = {k: {"same_partition": v["same_partition"], "changed_peer_set_count": v["changed_peer_set_count"],
                    "groups": [v["group_count_A"], v["group_count_B"]]} for k, v in aud["comparison"].items()}

# --- 3. Original responder against the specification, and the isolated HIGH-gate prototype
gap = json.load(open(p("03_E8_SOAR", "e8_original_runtime_gap_audit.json")))
hp = json.load(open(p("03_E8_SOAR", "e8_high_path_isolated_test_report.json")))
spec_sha = sha(os.path.join(ROOT, "analysis", "policy_property_check.py"))
e8 = {
    "domain_size": gap["test"]["domain_size"],
    "spec_route_counts": gap["test"]["spec_repaired_route_counts"],
    "original_high_candidates": gap["test"]["original_soar_exploit_high_candidates"],
    "gap_cases": gap["test"]["gap_cases_original_soar_high_vs_spec_not_containment"],
    "original_soar_sha256": gap["source_files"]["soar_sha256"],
    "spec_sha256_matches_repository_script": gap["source_files"]["spec_sha256"] == spec_sha == hp["frozen_spec_sha256"],
    "prototype_cases": hp["spec_cases"], "prototype_mismatches": hp["candidate_vs_spec_mismatches"],
    "prototype_status_counts": hp["high_path_status_counts"],
    "prototype_external_execution_calls": hp["high_path_external_execution_calls"],
}

# --- 4. Isolated security-control tests
sec = json.load(open(p("04_Security", "security_review_isolated_test_report.json")))
security = {"tests": len(sec["tests"]), "passed": sum(bool(t["pass"]) for t in sec["tests"])}

res = {"suricata_replay": suricata, "e6_v2": e6, "e6_v2_partition": e6_partition, "e8_gap_and_prototype": e8,
       "security_tests": security}
json.dump(res, open(OUT, "w", encoding="utf8"), indent=2, sort_keys=True)
print(json.dumps({"suricata_cells": cells, "pairs": [suricata["engine_pairs_differing"], suricata["checksum_pairs_differing"]],
                  "e6": {k: [v["jobs_done"], v["wait_p95_s"], v["worker_p95_s"], v["queue_to_done_p95_s"], v["llm_http"]] for k, v in e6.items()},
                  "gap": e8["gap_cases"], "prototype_mismatches": e8["prototype_mismatches"], "security": security}, indent=1))
