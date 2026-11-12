# Changelog

## isj-revision-r2 (12 November 2026)
- Table and section numbers in `README.md` and `REPRODUCIBILITY_MANIFEST.csv` follow the revised manuscript (23 pages): fusion is Table XI, E5 is Table XIV, the E6 planes are Tables XV and XVI, offline routing and its cost table are Tables XIX and XX, and the specification-runtime differential test is reported in Section IV-E.
- `experimental_results/reviewer_revision/README.md`: the manifest of `historical_checks/` has 61 entries, not 60.
- `README.md` and `CITATION.cff` carry the revised title and the release name `isj-revision-r2`.
- `README.md` and `REPRODUCIBILITY_MANIFEST.csv`: four of the eight runtime files used by `analysis/spec_runtime_differential.py` are in this repository and four are not; the r1 entry below said that none was.
- `experimental_results/reviewer_revision/README.md`: note on the entry count printed in `historical_checks/VERIFICATION_REPORT_20261111.txt`.
- `NOTES_ON_MANUSCRIPT.md`: its table and section numbers are those of the submitted text.
- No data file or analysis script changed.

## isj-revision-r1 (November 2026)
Added for the revision requested by the journal; nothing in the `isj-submission-v1.0` release was changed.
- `analysis/e8b_suricata_only_cost.py` with its input `experimental_results/e3/e3_routing_inputs.csv` and output `experimental_results/v2_policy/e8b_suricata_only_cost.json`: Suricata-only comparator and cost sensitivity of the offline routing test (E8b).
- `analysis/spec_runtime_differential.py`, `analysis/e8c_rows.py` and `experimental_results/e8c_spec_runtime/`: differential test of the checked routing specification against the archived runtime code (E8c). The runtime files are identified by SHA-256 and are not part of the repository.
- `experimental_results/reviewer_revision/` reorganized: `historical_checks/` (E1 logs, E4 function tests, first grouped E6 replay) and `new_experiments/` (Suricata 60-run replay, E6 V2, responder audit and prototype, security tests), with a README. The duplicate folder `post_review_experimental_evidence/` was removed; its files are identical to `historical_checks/`.
- `analysis/verify_revision_evidence.py` recomputes the figures of the revised manuscript from `new_experiments/`.
- `analysis/verify_reproduction.py` now also checks the E8b output, the E8c table rows and the revision figures.

## isj-submission-v1.0 (24 September 2026)
- Added `LICENSE` (MIT, code) and `LICENSE-DATA.md` (CC BY 4.0, data).
- Added `REPRODUCIBILITY_MANIFEST.csv`: manuscript object, script, inputs, output, output digest, public status.
- Added `expected_outputs/` and `analysis/verify_reproduction.py`, which reruns the self-contained scripts in a clean copy and compares with the tracked outputs (JSON numbers within a relative tolerance of 1e-9, to absorb last-digit differences between platforms); `.github/workflows/reproduce.yml` runs it on every push.
- Added the text-overlap report on the submitted PDF (`experimental_results/overlap/`).
- Added `NOTES_ON_MANUSCRIPT.md`, which states the scope of three sentences of the submitted text.
- Regenerated `SHA256SUMS.txt` so that it covers every file in the repository, including `docs/README_vi.md` and nested checksum files.

## Initial data commit (23 September 2026, commit 85404bd)
- Exported results of E1 to E8, analysis scripts, frozen settings, README, requirements and citation file.
