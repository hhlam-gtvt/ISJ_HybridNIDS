"""E8c: table rows of the specification-runtime differential test (added in revision).

Reads experimental_results/e8c_spec_runtime/spec_runtime_differential.json, written by
analysis/spec_runtime_differential.py, and writes generated/e8c_rows.tex and
generated/e8c_summary.json. No number is typed by hand: every cell is read from the JSON.
The differential script itself needs the archived runtime files (identified by SHA-256 in
the JSON), which are not part of this repository; this script needs only the JSON.
"""
import json, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "experimental_results", "e8c_spec_runtime", "spec_runtime_differential.json")
GEN = os.path.join(ROOT, "generated")
d = json.load(open(SRC, encoding="utf8"))
f = lambda n: f"{n:,}"

t1a, t1b, t3c = d["T1"]["T1a"], d["T1"]["T1b"], d["T3"]["T3c"]
m1a, m1b, m3c = (t["monotonicity"]["pending_as_3"] for t in (t1a, t1b, t3c))
c1a = t1a["variants"]["primary"]["containment_precondition"]
c1b = t1b["variants"]["primary"]["containment_precondition"]
c3c = t3c["variants"]["primary"]["containment_precondition"]
fav = t3c["variants"]["primary"]["favourable_completion"]
swp = t3c["variants"]["primary"]["sweep_provenance_and_quality"]
adv = d["T3"]["advisory_independence"]
t1c = d["T1"]["T1c"]

# evidence-field edges of the responder: the only specification field it reads is the whitelist
wl_edges = m3c["edges_by_field"]["whitelist_state"]
wl_viol = m3c["violations_by_field"].get("whitelist_state", 0)
assert m1a["violations"] == 0 and m1b["violations"] == 0 and wl_viol == 0
assert c3c["issued_without_reading_provenance_or_quality"] == c3c["containment_class_outcomes"]

rows = [
    ("E4 path, classifier first", t1a["domain_size"], m1a["edges_checked"], m1a["violations"],
     c1a["strict_outcomes"], c1a["strict_violations"]),
    ("E4 path, quality label supplied", t1b["domain_size"], m1b["edges_checked"], m1b["violations"],
     c1b["strict_outcomes"], c1b["strict_violations"]),
    # responder: block playbooks executed (dry run) without an approval request; it reads neither
    # provenance nor quality, so each of them is issued without corroboration and high quality
    ("Responder, queue to decision", t3c["domain_size"], wl_edges, wl_viol,
     c3c["of_which_executed_without_human_approval"], c3c["of_which_executed_without_human_approval"]),
]
os.makedirs(GEN, exist_ok=True)
with open(os.path.join(GEN, "e8c_rows.tex"), "w", encoding="utf8") as o:
    for name, n, e, v, c, p in rows:
        o.write(f"{name} & {f(n)} & {f(e)} & {f(v)} & {f(c)} & {f(p)} \\\\\n")
summary = {
    "responder_inputs": t3c["domain_size"],
    "responder_control_flag_edges_violations": m3c["violations"],
    "responder_containment_class_outcomes": c3c["containment_class_outcomes"],
    "responder_executed_without_human_approval_dry_run": c3c["of_which_executed_without_human_approval"],
    "responder_pending_approval_requests": t3c["outcome_counts"]["PENDING_APPROVAL_BLOCK"] + t3c["outcome_counts"]["PENDING_APPROVAL_RATE_LIMIT"],
    "runner_composed_path_exceptions": t1a["totality"]["exceptions"],
    "responder_exceptions": t3c["totality"]["exceptions"],
    "responder_comparable_inputs": fav["runtime_inputs"] - fav["inputs_not_comparable"],
    "responder_more_permissive_than_most_permissive_spec_input": fav["inputs_permissive_for_some_completion"],
    "responder_inputs_exceeding_spec_for_some_provenance_quality": swp["inputs_permissive_for_some_completion"],
    "responder_inputs_agreeing_for_every_provenance_quality": swp["inputs_agree_for_every_completion"],
    "advisory_text_replays": adv["inputs_replayed_with_adversarial_advisory_text"],
    "advisory_text_outcomes_changed": adv["outcomes_changed"],
    "runner_rows_with_simulated_effect": t1c["effect_requires_valid_approval"]["rows_with_external_effect"],
    "runner_effects_without_valid_approval": t1c["effect_requires_valid_approval"]["of_which_without_valid_approval"],
    "runner_outcome_row_inputs": t1c["domain_size"],
    "approval_calls": d["T3"]["T3d"]["calls"],
    "approval_executed_despite_whitelist_or_reject": d["T3"]["T3d"]["executed_despite_whitelist_or_reject"],
    "functions_entered": d["T3"]["line_coverage"]["functions_entered"],
    "functions_total": d["T3"]["line_coverage"]["functions_total"],
}
json.dump(summary, open(os.path.join(GEN, "e8c_summary.json"), "w", encoding="utf8"), indent=2)
for r in rows:
    print(r)
print(json.dumps(summary, indent=1))
