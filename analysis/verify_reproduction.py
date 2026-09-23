#!/usr/bin/env python3
"""Re-run every self-contained analysis script in a clean copy and compare with the tracked outputs.

Usage (from the repository root):  python3 analysis/verify_reproduction.py

Checks
  1. analysis/make_generated.py      -> generated/*.tex, generated/summary.json  vs expected_outputs/generated/
  2. analysis/e5_agreement.py        -> stdout                                   vs expected_outputs/e5_agreement.txt
  3. analysis/e6_supplementary_check.py -> stdout                                vs expected_outputs/e6_supplementary_check.txt
  4. analysis/policy_property_check.py  -> experimental_results/v2_policy/policy_property_check.json (tracked)
  5. analysis/offline_routing_test.py   -> experimental_results/v2_policy/offline_routing_test.json  (tracked)
JSON files are compared after parsing, so key order does not matter, and numbers are compared
within a relative tolerance of 1e-9 so that last-digit differences between platforms do not fail the check. Exit status 0 means every check passed.
Figures (PDF/PNG) are regenerated but not compared byte for byte.
"""
import json, math, os, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXP = os.path.join(ROOT, "expected_outputs")
failures = []

def load_json(p):
    with open(p, encoding="utf8") as f:
        return json.load(f)

REL_TOL, ABS_TOL = 1e-9, 1e-12

def json_diff(a, b, path="", out=None):
    """Differences between two parsed JSON values; floats are equal within REL_TOL/ABS_TOL,
    which absorbs last-digit differences between platforms' math libraries."""
    out = [] if out is None else out
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append(f"{path}/{k}: missing on one side")
            else:
                json_diff(a[k], b[k], f"{path}/{k}", out)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{path}: length {len(a)} vs {len(b)}")
        for i, (x, y) in enumerate(zip(a, b)):
            json_diff(x, y, f"{path}[{i}]", out)
    elif isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool):
        if not math.isclose(a, b, rel_tol=REL_TOL, abs_tol=ABS_TOL):
            out.append(f"{path}: {a!r} vs {b!r}")
    elif a != b:
        out.append(f"{path}: {a!r} vs {b!r}")
    return out

def json_same(new, old, name):
    d = json_diff(load_json(new), load_json(old))
    for line in d[:10]:
        print("    " + line)
    if len(d) > 10:
        print(f"    ... {len(d) - 10} more")
    return not d

def check(name, ok):
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        failures.append(name)

with tempfile.TemporaryDirectory() as tmp:
    for d in ("analysis", "experimental_results"):
        shutil.copytree(os.path.join(ROOT, d), os.path.join(tmp, d),
                        ignore=shutil.ignore_patterns("__pycache__", ".DS_Store"))
    def run(script):
        r = subprocess.run([sys.executable, os.path.join("analysis", script)], cwd=tmp,
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stderr)
        return r

    r = run("make_generated.py")
    check("make_generated.py runs", r.returncode == 0)
    for f in sorted(os.listdir(os.path.join(EXP, "generated"))):
        new = os.path.join(tmp, "generated", f)
        old = os.path.join(EXP, "generated", f)
        if not os.path.exists(new):
            check(f"generated/{f} exists", False); continue
        if f.endswith(".json"):
            check(f"generated/{f}", json_same(new, old, f))
        else:
            check(f"generated/{f}", open(new, encoding="utf8").read() == open(old, encoding="utf8").read())

    for script, ref in (("e5_agreement.py", "e5_agreement.txt"),
                        ("e6_supplementary_check.py", "e6_supplementary_check.txt")):
        r = run(script)
        check(f"{script} output", r.returncode == 0 and r.stdout == open(os.path.join(EXP, ref), encoding="utf8").read())

    for script, out in (("policy_property_check.py", "policy_property_check.json"),
                        ("offline_routing_test.py", "offline_routing_test.json")):
        r = run(script)
        new = os.path.join(tmp, "experimental_results", "v2_policy", out)
        old = os.path.join(ROOT, "experimental_results", "v2_policy", out)
        check(f"{script} -> {out}", r.returncode == 0 and json_same(new, old, out))

print(f"\n{len(failures)} failure(s)")
sys.exit(1 if failures else 0)
