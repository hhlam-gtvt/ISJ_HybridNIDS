"""E8b: Suricata-only comparator and cost sensitivity (added in revision).

Input (read-only): experimental_results/e3/e3_routing_inputs.csv, one row per
Test session and Suricata source (15 sessions x 2 sources) with the binary
session decisions of the E3 strategies.
Proxies for a binary containment proposal:
  blind          = S6      (any detector positive)
  aware          = S3_W60  (matched alert-flow pair within 60 s)
  suricata_only  = S1      (any eligible Suricata alert)
U = proposals on normal or scan sessions; M = high-impact sessions (brute
force, DoS, exploit) without a proposal; C = c_U*U + c_M*M with c_U = 1 and
r = c_M/c_U. The weights are hypothetical, not measured incident losses.
The two sources are paired views of the same 15 sessions, not 30 units.
"""
import csv, hashlib, json, os
from fractions import Fraction

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "experimental_results", "e3", "e3_routing_inputs.csv")
OUT = os.path.join(ROOT, "experimental_results", "v2_policy", "e8b_suricata_only_cost.json")
HIGH = {"brute_force", "dos", "exploit"}
PROXY = {"blind": "S6", "aware": "S3_W60", "suricata_only": "S1"}
RATIOS = [Fraction(0), Fraction(1, 4), Fraction(1, 2), Fraction(2, 3), Fraction(1),
          Fraction(2), Fraction(5), Fraction(10), Fraction(20)]

rows = list(csv.DictReader(open(SRC, newline="")))
res = {"input_sha256": hashlib.sha256(open(SRC, "rb").read()).hexdigest(), "sources": {}}
for src in ("primary", "supplementary"):
    R = [r for r in rows if r["source"] == src]
    assert len(R) == 15 and len({r["session_id"] for r in R}) == 15
    hi = [r for r in R if r["scenario"] in HIGH]
    lo = [r for r in R if r["scenario"] not in HIGH]
    assert len(hi) == 9 and len(lo) == 6
    out = {}
    for name, col in PROXY.items():
        U = sum(int(r[col]) for r in lo)
        M = sum(1 - int(r[col]) for r in hi)
        ref = sum(int(r[col]) == (r["scenario"] in HIGH) for r in R)
        out[name] = {"normal": sum(int(r[col]) for r in lo if r["scenario"] == "normal"),
                     "scan": sum(int(r[col]) for r in lo if r["scenario"] == "scan"),
                     "high_impact": 9 - M, "U": U, "M": M, "reference_agreement": ref,
                     "cost": {str(q): float(U + q * M) for q in RATIOS}}
    same = sum(r["S1"] == r["S3_W60"] for r in R)
    b, a = out["blind"], out["aware"]
    # blind and aware cost the same when U_b + r*M_b = U_a + r*M_a
    be = Fraction(b["U"] - a["U"], a["M"] - b["M"]) if a["M"] != b["M"] else None
    res["sources"][src] = {"policies": out, "aware_equals_suricata_only_sessions": same,
                           "break_even_r_blind_vs_aware": str(be)}
os.makedirs(os.path.dirname(OUT), exist_ok=True)
json.dump(res, open(OUT, "w"), indent=2)
for src, v in res["sources"].items():
    print(src, {k: (p["normal"], p["scan"], p["high_impact"], p["U"], p["M"],
                    p["reference_agreement"], p["cost"]["5"]) for k, p in v["policies"].items()},
          "identical:", v["aware_equals_suricata_only_sessions"], "/15",
          "break-even r:", v["break_even_r_blind_vs_aware"])
print("input sha256:", res["input_sha256"])
