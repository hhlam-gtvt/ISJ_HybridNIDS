# ISJ_HybridNIDS

Data and code for the manuscript

> Tang Quoc Cuong, Huynh Hoang Lam, Phan Van Tri, Nguyen An Khuong.
> *Provenance-Aware Post-Alert Routing for Hybrid Network Intrusion Detection under Domain Shift: A Checked Policy and a Laboratory Evaluation.*
> Submitted to the Journal of Science and Technology on Information Security (ISJ), 23 September 2026.

The study connects a passive Suricata and Random-Forest (RF) detector to a post-alert subsystem in which rules and human approval hold all response authority. It checks the routing policy as a finite function, compares provenance-blind, provenance-aware and all-to-analyst routing on detector-derived incidents, and reports a laboratory case study in eight experiments (E1 to E8).

**Release:** `isj-submission-v1.0`. Changes are listed in `CHANGELOG.md`; `NOTES_ON_MANUSCRIPT.md` states how three sentences of the submitted text relate to this release.

## What this release contains

This release contains the analysis code, the retained frozen settings, the exported results of E1 to E8, and selected run-level evidence. It does not contain raw packet captures, the E2 prediction export, or the historical artifacts listed in Section VIII of the manuscript. `REPRODUCIBILITY_MANIFEST.csv` maps every table, figure and statistical check to its script, inputs, output and output digest, and marks each item that is not public with the reason.

| Path | Content |
|---|---|
| `experimental_results/` (top level) | E1 corpus reports, session, event, ground-truth and checksum manifests; E2 freeze records, split definition, calibration parameters, model lineage and metrics |
| `experimental_results/e3/` | Design freeze, session decisions for both Suricata rule sources, McNemar tables, routing comparison |
| `experimental_results/e4/` | Policy freeze and action matrix, incident outcomes, failure recovery, action journal, SHA-256 manifest; `no_action_20260922/` holds the no-action replay |
| `experimental_results/e5/` | Locked protocol, model outputs, automatic metrics; `ratings_20260922/` holds the two blinded ratings, rubric, case mapping and agreement summary |
| `experimental_results/e6/` | Protocol freeze, hardware and clock records, result tables T01 to T11; `supplementary_v552_20260923/` holds the grouped replay (input manifests, per-incident traces, queue reports, worker logs) |
| `experimental_results/e7/` | Pilot replay manifest, incidents, observer snapshots and sampling ledger; `24h_run01/` the 24 h run; `detector_side_run_20260921/` the 89-cycle detector-side replay |
| `experimental_results/v2_policy/` | E8 outputs: exhaustive policy check and offline routing test |
| `experimental_results/overlap/` | Text-overlap report on the submitted PDF and the two earlier works |
| `analysis/` | Scripts that regenerate the tables, figures and statistics |
| `expected_outputs/` | Tracked outputs used by `analysis/verify_reproduction.py` |
| `docs/README_vi.md` | Earlier Vietnamese overview of the planned integration repository |

## Reproducing the results

Python 3.10 or later with the pinned packages:

    pip install -r requirements.txt
    python3 analysis/verify_reproduction.py

`verify_reproduction.py` reruns the five self-contained scripts below in a clean copy and compares their outputs with the tracked ones; it exits with status 0 only if every check passes. The same check runs on every push (`.github/workflows/reproduce.yml`).

| Command | Regenerates | Seed |
|---|---|---|
| `python3 analysis/policy_property_check.py` | Table V: totality, monotone authority and containment precondition over 3,840 inputs (standard library only) | none |
| `python3 analysis/offline_routing_test.py` | Table XVI and the E8 counts (standard library only) | none |
| `python3 analysis/make_generated.py` | Tables VIII, X, XIII, XIV, XV, Fig. 4 and the numbers quoted in the text (`generated/`, `figures/`) | 20260921 (session bootstrap) |
| `python3 analysis/e5_agreement.py` | E5 rating agreement: weighted kappa with bootstrap interval, exact agreement, within-reviewer consistency | 20260923 |
| `python3 analysis/e6_supplementary_check.py` | Incident counts, model calls and drain times of the grouped E6 replay | none |

The exact two-sided McNemar values of E8 follow from the discordant counts: 6 and 9 on the primary source (p = .607), 6 and 3 on the supplementary source (p = .508). Table IX and Fig. 2 need the E2 prediction export (about 149 MB), which is not public; `analysis/overlap_shingles.py` needs the three PDFs named in `experimental_results/overlap/README.md`.

The reported results were produced with Python 3.10.12, pandas 2.3.3, NumPy 2.2.6 and Matplotlib 3.10.9.

## Frozen settings

- E2: RF-21 feature schema, split definition and threshold freeze (`E2_*.json`); RF decision threshold .05.
- E3: correlation window W = 60 s (`e3/E3_DESIGN_FREEZE.json`).
- E4: action matrix and provenance-blind and provenance-aware rules (`e4/E4_RQ3_POLICY_FREEZE.json`).
- E6: replay protocol (`e6/E6_PROTOCOL_FREEZE_v2.json`).

## Notes on specific inputs

- The 60 pilot documents and the 288 documents of the 24 h E7 run come from the index `e6_response_test` (run `e6_response_1x`, alerts dated 2026-09-19). This was a separate 1x response test, not the frozen E6 index `e6-perf-final-v2`; it included the third exploit capture and flows with RF label 0 (see `experimental_results/e7/e7_replay_manifest.jsonl`).
- In the E5 files the label "E1 Test" names the test partition of the separate laboratory used for E5, not the 15 frozen E1 Test sessions.

## Integrity

`SHA256SUMS.txt` lists the digest of every file in the repository except itself. Verify with `sha256sum -c SHA256SUMS.txt` (Linux) or `shasum -a 256 -c SHA256SUMS.txt` (macOS).

## License

Code in `analysis/`: MIT (`LICENSE`). Data in `experimental_results/` and `expected_outputs/`: CC BY 4.0 (`LICENSE-DATA.md`). Please cite the manuscript in `CITATION.cff`.

## Contact

Corresponding authors: Phan Van Tri (phanvantri@actvn.edu.vn) and Nguyen An Khuong (nakhuong@hcmut.edu.vn). Data questions: Huynh Hoang Lam.
