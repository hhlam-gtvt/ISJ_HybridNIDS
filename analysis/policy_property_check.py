"""Exhaustive check of the routing policy (Table IV) over a finite input domain.

Domain: provenance x quality x four safety fields, each safety field in
{clear, raised, missing, conflicting}. Two readings are checked:
  literal  : the five table rows plus the stated precedence, no completions;
  repaired : Monitor for low or missing quality moved above the analyst
             routes (R1), plus completions C1 and C2 for unmatched inputs.
Outputs JSON to experimental_results/v2_policy/policy_property_check.json.
"""
import itertools, json, os, sys

PROV = ["none", "rf_only", "sur_only", "both_uncorrelated", "correlated"]
QUAL = ["high", "low", "missing"]
SAFE_VALS = ["clear", "raised", "missing", "conflicting"]
SAFE = ["drift", "schema", "shared_address", "whitelist"]
AUTH = {"containment_proposal": 3, "analyst_triage": 2, "watchlist": 1,
        "monitor": 0, "safety_hold": 0}
PRECEDENCE = ["safety_hold", "containment_proposal", "analyst_triage",
              "watchlist", "monitor"]

def rows_matching(p, q, s):
    """Rows of Table IV whose conditions hold (literal reading)."""
    m = []
    if p == "correlated" and q == "high":
        m.append("containment_proposal")
    if p == "sur_only":
        m.append("analyst_triage")
    if p == "rf_only":
        m.append("watchlist")
    if any(v == "raised" for v in s):
        m.append("safety_hold")
    if q in ("low", "missing"):
        m.append("monitor")
    # text rule: missing or conflicting safety information resolves to hold
    if any(v in ("missing", "conflicting") for v in s):
        m.append("safety_hold")
    return sorted(set(m), key=PRECEDENCE.index)

def literal(p, q, s):
    m = rows_matching(p, q, s)
    return m[0] if m else None

REPAIRED_PRECEDENCE = ["safety_hold", "monitor", "containment_proposal",
                       "analyst_triage", "watchlist"]

def repaired(p, q, s):
    """Repair R1: the low-quality row (Monitor) precedes every analyst route.
    Completions: C1 no detector output -> monitor;
                 C2 both detectors, uncorrelated, high quality -> analyst triage."""
    m = rows_matching(p, q, s)
    if m:
        return sorted(m, key=REPAIRED_PRECEDENCE.index)[0]
    if p == "none":
        return "monitor"
    if p == "both_uncorrelated":
        return "analyst_triage"
    return None

# one-step degradations
PROV_DEG = {"correlated": ["both_uncorrelated"],
            "both_uncorrelated": ["rf_only", "sur_only"],
            "rf_only": ["none"], "sur_only": ["none"], "none": []}
QUAL_DEG = {"high": ["low", "missing"], "low": ["missing"], "missing": []}
SAFE_DEG = {"clear": ["raised", "missing", "conflicting"],
            "raised": [], "missing": [], "conflicting": []}

def neighbours(p, q, s):
    for p2 in PROV_DEG[p]:
        yield (p2, q, s)
    for q2 in QUAL_DEG[q]:
        yield (p, q2, s)
    for i, v in enumerate(s):
        for v2 in SAFE_DEG[v]:
            yield (p, q, s[:i] + (v2,) + s[i + 1:])

def check(policy, name):
    dom = list(itertools.product(PROV, QUAL, itertools.product(SAFE_VALS, repeat=4)))
    undefined, overlaps, viol_mono, viol_contain = [], 0, [], []
    for p, q, s in dom:
        if len(rows_matching(p, q, s)) > 1:
            overlaps += 1
        r = policy(p, q, s)
        if r is None:
            undefined.append((p, q, s)); continue
        if r == "containment_proposal" and not (
                p == "correlated" and q == "high" and all(v == "clear" for v in s)):
            viol_contain.append((p, q, s))
        for n in neighbours(p, q, s):
            r2 = policy(*n)
            if r2 is not None and AUTH[r2] > AUTH[r]:
                viol_mono.append({"from": [p, q, list(s)], "route": r,
                                  "to": [n[0], n[1], list(n[2])], "route_after": r2})
    # determinism: evaluate twice
    det = all(policy(p, q, s) == policy(p, q, s) for p, q, s in dom)
    routes = {}
    for p, q, s in dom:
        r = policy(p, q, s); routes[str(r)] = routes.get(str(r), 0) + 1
    und_prov = sorted({u[0] for u in undefined})
    mono_kinds = sorted({(v["from"][0], v["from"][1], v["route"], v["to"][0], v["route_after"])
                         for v in viol_mono})
    return {"reading": name, "domain_size": len(dom),
            "inputs_matching_more_than_one_row": overlaps,
            "undefined_inputs": len(undefined), "undefined_provenance_values": und_prov,
            "deterministic": det,
            "monotonicity_violations": len(viol_mono),
            "monotonicity_violation_kinds": [list(k) for k in mono_kinds],
            "containment_precondition_violations": len(viol_contain),
            "route_counts": routes}

if __name__ == "__main__":
    out = {"literal": check(literal, "literal"), "repaired": check(repaired, "repaired")}
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "experimental_results", "v2_policy", "policy_property_check.json")
    json.dump(out, open(path, "w"), indent=2)
    print(json.dumps(out, indent=1))
