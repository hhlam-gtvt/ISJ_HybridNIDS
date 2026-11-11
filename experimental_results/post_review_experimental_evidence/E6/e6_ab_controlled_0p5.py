#!/usr/bin/env python3
"""E6 0.5x matched-input LLM ablation controller (grouping ON in both arms).

Uses frozen 4,577 flow archive, copies NO original files and does not run NIDS.
Calls E6_replay_laptop.run_one for one arm only. Explicit --run required for writes.
Do not run against a production ES endpoint or a forwarded localhost connection.
"""
from __future__ import annotations

import argparse, datetime as dt, hashlib, importlib.util, json, os
import pathlib, socket, sys

BASE = pathlib.Path(__file__).resolve().parents[2]
HERE = pathlib.Path(__file__).resolve().parent
RUNNER = BASE / "experimental_results/E6_replay_laptop.py"
FROZEN_WRAPPER = BASE / "e6_integration/e6_trace_wrapper_lam_v552.py"
FROZEN_GATE = BASE / "e6_integration/e6_incident_gate.py"
WORKER = HERE / "e6_ab_worker.py"
INPUT = BASE / "experimental_results/E6_2R_INPUT_PREP/e6_input_0p5.jsonl"
EXPECTED_SHA256 = "04820d36af3691482dfa92806a2eb5ae70b82e483b2f096732e8c18ad8c161fb"
EXPECTED_RUNNER = "cc358b7c5765d076e9f8392b28dde29ad70116087d0f779aa5bc29c2b95a17b1"
EXPECTED_WRAPPER = "8ce5f1403d438a21c12e98fe69fd37cc5e271a974344570caa37a4c6bab39046"
EXPECTED_GATE = "beb54179e79ee87e25f59c2721d4309017d1fe0ab2388bcca2011ae23ab749a0"

def sha256(p: pathlib.Path):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def match(p: pathlib.Path, digest: str):
    if not p.is_file() or sha256(p) != digest:
        raise RuntimeError(f"STOP: frozen source missing or changed: {p}")

def check_port_free(host="127.0.0.1", port=5507):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        if sock.connect_ex((host, port)) == 0:
            raise RuntimeError(f"STOP: API port {host}:{port} is already in use; another worker may be running")

def load_runner():
    spec = importlib.util.spec_from_file_location("e6_frozen_runner_for_ab", RUNNER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--arm", choices=("llm_off", "selective_llm"), required=True)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--preflight", action="store_true", help="Read and check only; do not start worker or index documents")
    operation.add_argument("--run", action="store_true", help="Start isolated 0p5 replay into NEW index and database")
    parser.add_argument("--drain-timeout", type=int, default=1800)
    args = parser.parse_args()
    if args.drain_timeout < 60:
        parser.error("drain timeout must be >= 60 seconds")

    for path, digest in ((INPUT,EXPECTED_SHA256),(RUNNER,EXPECTED_RUNNER),
                         (FROZEN_WRAPPER, EXPECTED_WRAPPER),(FROZEN_GATE, EXPECTED_GATE)):
        match(path, digest)
    if not WORKER.is_file():
        raise RuntimeError(f"Missing worker launcher: {WORKER}")
    mod = load_runner()
    rows, summary = mod.read_inputs("0p5")
    if len(rows) != 4577 or summary["alert_flows"] != 4577:
        raise RuntimeError("STOP: archive size differs from frozen dataset")
    mod.WRAPPER = WORKER
    mod.OUTPUT = HERE / "controlled_ab_runs" / args.arm
    os.environ["E6_AB_FORCE_LLM_OFF"] = ("1" if args.arm == "llm_off" else "0")
    check_port_free()
    # The original project's preflight requires local ES:9200 and local Ollama:11434,
    # checks the model, and imports the SOAR config without starting its worker.
    mod.project_preflight()
    record = {
        "arm": args.arm,
        "source_sha256": EXPECTED_SHA256,
        "frozen_runner_sha256": EXPECTED_RUNNER,
        "frozen_wrapper_sha256": EXPECTED_WRAPPER,
        "frozen_gate_sha256": EXPECTED_GATE,
        "ab_launcher_sha256": sha256(WORKER),
        "grouping": "ON - frozen E6 v552 grouping in BOTH arms",
        "llm": "OFF via gate interception; Static RAG fallback" if args.arm == "llm_off"
               else "frozen E6 selective LLM gate",
        "workload": "0p5 archived NIDS alert flows (not new traffic)",
        "docs": len(rows),
        "replay_basis": "original queue-created timestamp offsets",
        "safety": "DRY_RUN; NO real firewall enforcement; dedicated DB and ES index",
        "limits": "Two arms are not 2x2; this ablation does not verify original E6 integrated performance",
        "preflight_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    print(json.dumps(record,ensure_ascii=False,indent=2),flush=True)
    if args.preflight:
        print("AB_PREFLIGHT_PASS: no SOAR worker started; no Elasticsearch writes.",flush=True)
        return 0
    mod.OUTPUT.mkdir(parents=True, exist_ok=True)
    audit_path = mod.OUTPUT / ("ab_arm_start_" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json")
    audit_path.write_text(json.dumps(record,indent=2)+"\n",encoding="utf-8")
    mod.run_one("0p5", rows, summary, args.drain_timeout)
    print("AB_ARM_RUN_FINISHED:",args.arm,flush=True)
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("AB_STOP:",type(exc).__name__,str(exc),file=sys.stderr,flush=True)
        sys.exit(1)
