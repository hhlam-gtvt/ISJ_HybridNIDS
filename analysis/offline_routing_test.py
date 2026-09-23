"""Offline routing test on detector-derived incidents (v2).

Inputs (read-only): E3 per-session detector outputs (primary and supplementary
Suricata sources) and the E7 detector-side ledger (89 cycles x 15 sessions).
Policies: provenance-blind (any detector positive -> containment proposal),
provenance-aware (repaired Table IV, from policy_property_check.py), and
all-to-analyst. Reference: the frozen E4 action matrix applied to the ground
truth scenario (containment for brute_force, dos, exploit; watchlist for scan;
no action for normal). Quality is taken as high because the E3 and E7 outputs
carry no extractor or drop flag; the drift flag is evaluated both ignored and
honoured.
"""
import csv, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from policy_property_check import repaired

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ER = os.path.join(ROOT, "experimental_results")
HIGH = {"brute_force", "brute", "dos", "exploit"}

def scen(sid):
    s = sid.upper()
    for k, v in [("NORMAL", "normal"), ("SCAN", "scan"), ("BRUTE", "brute_force"),
                 ("DOS", "dos"), ("EXPLOIT", "exploit")]:
        if k in s:
            return v
    raise ValueError(sid)

def prov(tier, rf_pos, sur_pos):
    if tier == "HYBRID_CORRELATED":
        return "correlated"
    if rf_pos and sur_pos:
        return "both_uncorrelated"
    if rf_pos:
        return "rf_only"
    if sur_pos:
        return "sur_only"
    return "none"

def route(policy, p, drift):
    if policy == "blind":
        return "containment_proposal" if p != "none" else "monitor"
    if policy == "analyst":
        return "analyst_triage"
    s = ("raised" if drift else "clear", "clear", "clear", "clear")
    return repaired(p, "high", s)

def outcomes(items, policy, drift):
    r = [(sc, route(policy, p, drift)) for sc, p in items]
    cont = lambda x: x == "containment_proposal"
    return {
        "n": len(r),
        "containment_on_normal": sum(cont(x) for sc, x in r if sc == "normal"),
        "containment_on_scan": sum(cont(x) for sc, x in r if sc == "scan"),
        "high_impact_contained": sum(cont(x) for sc, x in r if sc in HIGH),
        "high_impact_total": sum(sc in HIGH for sc, _ in r),
        "attacks_to_watchlist_or_monitor_only": sum(
            x in ("watchlist", "monitor") for sc, x in r if sc != "normal"),
        "attacks_held": sum(x == "safety_hold" for sc, x in r if sc != "normal"),
        "held_total": sum(x == "safety_hold" for _, x in r),
        "priority_queue_items": sum(cont(x) for _, x in r),
        "items_reaching_person": sum(x != "monitor" for _, x in r),
        "reference_agreement": sum(
            (cont(x) if sc in HIGH else not cont(x)) for sc, x in r),
    }

res = {}
rows = list(csv.DictReader(open(os.path.join(ER, "e3", "e3_event_matches.csv"))))
for src in ("primary", "supplementary"):
    items = []
    for x in rows:
        if x["source"] != src:
            continue
        alerts = int(x["primary_alerts"] if src == "primary" else x["supp_alerts"])
        items.append((scen(x["session_id"]),
                      prov(x["routing_tier_W60"], int(x["rf_positive_flows"]) > 0, alerts > 0)))
    res[f"E3_{src}"] = {"provenance_counts": {p: sum(i[1] == p for i in items) for p in set(i[1] for i in items)},
                        "by_policy": {pol + ("_drift" if d else ""): outcomes(items, pol, d)
                                      for pol in ("blind", "aware", "analyst") for d in (False, True)
                                      if not (pol != "aware" and d)}}

led = list(csv.DictReader(open(os.path.join(ER, "e7", "detector_side_run_20260921", "E7_REPLAY_LEDGER.csv"))))
items = [(scen(x["session_id"]),
          prov(x["provenance_tier"], int(x["rf_reference_positive"] or 0) > 0, int(x["suricata_alerts"] or 0) > 0))
         for x in led]
cycles = len({x["cycle"] for x in led})
res["E7_detector_side"] = {"cycles": cycles,
    "provenance_counts": {p: sum(i[1] == p for i in items) for p in set(i[1] for i in items)},
    "by_policy": {pol + ("_drift" if d else ""): outcomes(items, pol, d)
                  for pol in ("blind", "aware", "analyst") for d in (False, True)
                  if not (pol != "aware" and d)}}
# per-cycle stability of the aware route
per = {}
for x, it in zip(led, items):
    per.setdefault(x["session_id"], set()).add(route("aware", it[1], False))
res["E7_detector_side"]["sessions_with_route_change_across_cycles"] = sum(len(v) > 1 for v in per.values())
dr = list(csv.DictReader(open(os.path.join(ER, "e7", "detector_side_run_20260921", "E7_DRIFT_1MIN.csv"))))
res["E7_detector_side"]["drift_alarm_minutes"] = [sum(x["drift_alarm"] == "1" for x in dr), len(dr)]

out = os.path.join(ER, "v2_policy", "offline_routing_test.json")
json.dump(res, open(out, "w"), indent=2)
print(json.dumps(res, indent=1))
