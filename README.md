# ISJ_HybridNIDS

**Repository status:** Integration and release preparation. This README describes the intended combined repository and the evidence identified in the manuscript. Some paths and public artifacts may not yet be populated. Do not interpret a listed artifact as publicly available until its file, provenance, and release approval have been verified.

## Overview

This repository brings together two research components:

1. **Hybrid-NIDS (detector-side work):** network-traffic processing and intrusion detection using NFStream, a Random Forest detector, and Suricata.
2. **SOAR–ELK–LLM (post-alert work):** alert ingestion, incident orchestration, policy evaluation, selective LLM-assisted analysis, response execution with safety controls, auditing, and reporting.

The integrated workflow is intended to connect detector outputs to the post-alert pipeline through an explicit alert contract and Elasticsearch/Logstash interfaces. Combining source trees does **not** itself establish that the end-to-end integration or every experiment is reproducible; those claims depend on the linked tests and archived evidence.

```text
Laboratory traffic / replay
          |
          v
Hybrid-NIDS: NFStream + Random Forest / Suricata
          |
          v
Alert contract -> Logstash / Elasticsearch
          |
          v
SOAR orchestrator -> policy / rule engine -> RAG / LLM (when applicable)
          |
          v
Human approval / response controls -> action or no-action -> audit / PDF / dashboard
```

The diagram is a **conceptual integration view**, not a claim that every component or enforcement mode was active in every experimental run. Consult each experiment's frozen configuration and run evidence for the actual execution path.

## Research scope and publication relationship

This repository supports the integrated journal manuscript and its experiments **E1–E7**. According to the manuscript, the journal submission extends two earlier works accepted in 2026:

- **Detector-side work:** accepted at **VNICT 2026** and selected by the conference for journal extension. The manuscript states that, under this arrangement, the conference version will not be printed in the proceedings if the journal paper is accepted; its preprint is cited as **[15]**.
- **Post-alert work:** accepted at **FAIR 2026** and available as a preprint, cited as **[16]**.

The earlier works and the journal manuscript must remain distinguishable in the citation record. The manuscript describes the new contributions in **Section II**. Do not infer new contributions merely from the act of merging the two repositories. Full bibliographic details and links for [15] and [16] will be added after verification; camera-ready citations must be updated when available.

## Repository layout

The following is the **target layout** for the integrated release. The existing detector and response source trees should retain their original provenance and relevant Git history. Directories marked *planned* must not be presented as completed deliverables until populated and tested.

```text
hybrid-nids-soar-elk-llm/
├── README.md
├── LICENSE                       # Pending author/institutional licence decision
├── CITATION.cff                  # Planned: verified manuscript/preprint metadata
├── .gitignore
├── .env.example                  # Example values only; no secrets
├── requirements.txt              # Versioned, validated release environment
├── detector/
│   └── hybrid-nids/              # Cường's detector-side source and documentation
├── response/
│   └── soar-elk-llm/             # Lam's post-alert source and tests
├── integration/                  # Planned: verified alert schema and bridge
├── configs/                      # ELK and deployment configurations (sanitized)
├── experiments/
│   ├── e1/ ├── e2/ ├── e3/ ├── e4/
│   └── e5/ ├── e6/ └── e7/
├── analysis/
│   ├── make_generated.py
│   ├── e2_scenario_table.py
│   ├── e2_score_figure.py
│   ├── e5_agreement.py
│   ├── e6_supplementary_check.py
│   └── overlap_shingles.py
├── reproducibility/              # Planned: input/output/command manifests
├── docs/                         # Architecture, protocols, limitations, ethics
└── publication/                  # Verified publication metadata/declarations
```

The filenames under `analysis/` reflect scripts **named in the manuscript**. Their presence, exact command-line interfaces, inputs, and successful execution must be verified against the actual source before release. The detector/response/integration paths above are a proposed organization, not a statement that those folders already exist.

## Experimental evidence and status

| Experiment | Evidence described in the manuscript | Scope and qualifications |
| --- | --- | --- |
| **E1** | Session, ground-truth, event, and checksum manifests | Original PCAPs and logs require separate release review. |
| **E2** | Freeze records, model lineage, and metrics | The E2 prediction export (~149 MB) is stored with E2 models **outside the manuscript package**; dependent figures are not reproducible from that package alone. Historical grid/tie limitations must remain disclosed. |
| **E3** | Session decisions and routing comparison | Exact historical environment/ruleset reproducibility limitations must remain disclosed. |
| **E4** | Summary exports and no-action replay | Report no-action and enforcement behavior only for modes actually executed. |
| **E5** | Model outputs, automatic metrics, case mapping, and blinded reviewer ratings | Analyst utility must not be inferred from JSON/schema validity alone; retain the reviewer rubric and agreement evidence. |
| **E6** | Result tables, hardware and clock records, supplementary replay evidence | Preserve the frozen criteria, amendments, and raw run references; see the E6 status note below. |
| **E7** | Pilot observer outputs; verified 24 h-run summary and source documents; detector-side replay, incident, drift, and review ledgers | Endurance **replay** and post-run review do not constitute prospective new-traffic validation. |

### E6 status and interpretation

The current E6 record is **`E6_PARTIAL`**, with **`MAX_SUSTAINABLE = NOT_ESTABLISHED`** under the frozen criteria. The lower-rate supplementary search covered **0.25×, 0.125×, 0.0625×, and 0.03125×**; it did not establish a sustainable operating point in that tested range. The supplementary matched RF-inference cost-isolation campaign completed its six RF-ON/RF-OFF blocks at 0.5×, 1×, and 2×, with **one measured run per arm/rate**. Removing live RF inference did not restore complete live-flow coverage. These data do **not** conclusively identify whether NFStream flow expiration/observation-window behavior or flow emission accounts for the missing live flows, and do not establish repeated-run statistical stability.

**Phase A** measures live-emitted flows and their observed live-path timing. **Phase B** processes the completed capture offline and must not be described as complete live end-to-end coverage. Additional DoS/brute-force workload execution and fault-injection evidence must be described only to the extent independently verified in the archived runs. Do not relabel supplementary evidence as a preregistered result, or a `NOT_ESTABLISHED` criterion as `PASS`.

## Reproducing manuscript tables and figures

The manuscript identifies the following analysis scripts and outputs:

| Script | Manuscript output or check | Required qualification |
| --- | --- | --- |
| `analysis/make_generated.py` | Tables VII, IX, XII, XIII, XIV and Fig. 4 | Session-bootstrap seed **20260921**; stored bootstrap summary and input manifests required. |
| `analysis/e2_scenario_table.py` | Table VIII | Reads the separately stored E2 prediction export. |
| `analysis/e2_score_figure.py` | Fig. 2 | Reads the separately stored E2 prediction export. |
| `analysis/e5_agreement.py` | E5 reviewer agreement | Seed **20260923**; original blinded rating records and rubric required. |
| `analysis/e6_supplementary_check.py` | Supplementary E6 figures | Recomputes from per-incident traces; the input manifests, queue reports, routing events, and worker logs belong with the supplementary evidence. |
| `analysis/overlap_shingles.py` | Cross-document overlap audit | Rerun on the **final** PDF of all relevant works; a result from a draft build is not a final-release result. |

The manuscript reports that these scripts were run with **Python 3.10.12, pandas 2.3.3, NumPy 2.2.6, and Matplotlib 3.10.9**. Exact executable commands, working directories, input checksums, and expected outputs must be entered in `reproducibility/table_figure_manifest.csv` **after verifying each real script**. No unverified generic command is represented here as a successful reproduction procedure.

**Archive completeness:** The manuscript explicitly states that its package is **not yet a complete reproduction archive**; missing artifacts are described in **Section VIII**. Until those dependencies are supplied or access restrictions are documented, the public repository should not claim full reproducibility.

## Provenance and release boundaries

The reproducibility record should distinguish:

- **Historical/frozen experiments:** original protocol, environment, source version, inputs, raw outputs, and checksums; do not rewrite old artifacts.
- **Retrospective amendments:** dated explanations or analyses made after the original run, clearly labeled and linked to the frozen source.
- **Supplementary experiments:** separate runner versions, protocols, timestamps, raw runs, summary tables, and limitations.

Each table/figure release should be traceable through a manifest from the cited manuscript output to the specific input files, script, command, software environment, and checksums. Keep immutable source evidence outside Git when size, confidentiality, or institutional rules require it; link to its approved archive record instead of silently omitting it.

## Research ethics and data access

According to Section IX of the manuscript, traffic was generated in isolated laboratory systems operated by the authors; the E1 corpus was captured under institutional authorization, with no third-party or production traffic captured. Two E5 reviewers participated voluntarily and rated generated text concerning laboratory traffic; their personal information is not reported.

**Do not publish raw PCAPs, operational logs, IP addresses/payloads, credentials, private keys, or personally identifying reviewer records by default.** Packet captures and logs are releasable only after appropriate sanitization **and institutional review**. Public source code and approved aggregate tables may be hosted here; restricted evidence should remain in a controlled archive with a documented access process. Removing a file from a working tree does not remove it from Git history; check the full commit history before making a repository public.

The manuscript's publication declarations remain subject to author-confirmed records: CRediT contributions, funding, competing interests, institutional authorization for capture and controlled enforcement, and the ethics determination for the E5 reviewer study. Do not mark these declarations complete or publish confidential approval documents without authorization.

## Citation, licence, and archive identifier

- **Citation:** Add the verified journal manuscript details, its two preprint references, and a completed `CITATION.cff` when available. The VNICT selection arrangement should also be disclosed in the **editor cover letter/comments**, rather than assumed to be established by this README.
- **Licence:** To be selected by the rights holders after checking institutional obligations and third-party dependencies. The presence of a file named `LICENSE` in the target tree is **not** a licence grant until valid content is supplied.
- **Persistent identifier:** Assign an identifier to a fixed, reviewed release (for example, through an approved archival service) and record its version, commit, evidence manifest, and checksum. **No DOI is claimed at present.**

## Release checklist

- [ ] Confirm the actual merged source tree, authorship/provenance, and integration tests.
- [ ] Check every E1–E7 manifest against present and missing evidence; disclose limitations.
- [ ] Verify analysis scripts, their exact commands, and output-to-input manifest.
- [ ] Rerun the overlap audit on the final PDFs and record the actual result.
- [ ] Review all proposed public artifacts for sensitive data and institutional release permission.
- [ ] Confirm publication history, CRediT, funding, competing interests, and ethics/authorization statements.
- [ ] Set the licence and citation metadata; freeze a versioned release with archive ID and checksums.

**Contact and support:** Add author-approved project contact information before publication; do not publish private contact details or reviewer identities.
