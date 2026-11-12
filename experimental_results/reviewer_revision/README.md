# Evidence added for the revision (November 2026)

Everything in this folder was produced after the reviews of the submitted manuscript. No data file of the `isj-submission-v1.0` release and no script other than `analysis/verify_reproduction.py` was changed.

| Folder | Content | Level |
|---|---|---|
| `historical_checks/E1/` | The 15 Suricata logs of the E1 Test sessions (Suricata 8.0.4, 51,960 rules loaded, none failed) and their audit | original logs |
| `historical_checks/E4/` | Function tests of the archived E4 runner: 320 combinations, 1,920 assertions, 24 diagnostic calls; 228 simulated approval and safety controls (216 denied, 12 simulated effects) | scripts, inputs and outputs |
| `historical_checks/E6/` | Exploratory grouped A/B replay of 4,577 alert flows: 13 and 16 jobs, 249.519 and 279.624 s, three DEAD jobs per arm | scripts, traces and logs |
| `new_experiments/01_Suricata_60_runs/` | Engine-by-checksum replay of the 15 Test captures (Suricata 7.0.3 and 8.0.4, checksum validation on and off, one rule file of 51,623 rules) | per-session results and manifest |
| `new_experiments/02_E6_V2/` | Four-arm replay (grouping on or off, model off or selective) on a fixed partition of 4,577 alert flows | KPI summary and partition audit |
| `new_experiments/03_E8_SOAR/` | Audit of the original responder against the checked specification, and the isolated HIGH-gate prototype test | reports |
| `new_experiments/04_Security/` | 30 isolated security-control tests on a separate, non-deployed branch | report |
| `revision_evidence_summary.json` | Figures of the revised manuscript recomputed from `new_experiments/` by `analysis/verify_revision_evidence.py` | generated |

`historical_checks/SHA256SUMS.txt` (61 entries) and `new_experiments/SHA256SUMS.txt` (7 entries) list the files as uploaded; both verify with `sha256sum -c` from inside their folder. `historical_checks/VERIFICATION_REPORT_20261111.txt` prints 60 verified entries because it was written before it was itself added to the manifest as the 61st entry; it is kept as uploaded.

The files under `new_experiments/` are summary exports. The 60 EVE output folders, the queue traces, the prototype and security-branch sources, and the original SQLite databases are kept on the experiment workstation and are not part of this repository. The captures used by the Suricata replay are the E1 Test captures, identified by the SHA-256 values in `experimental_results/e1_pcap_sha256.txt`.

None of these files shows end-to-end correctness of a deployed responder or a verified containment.
