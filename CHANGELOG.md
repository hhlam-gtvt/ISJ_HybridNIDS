# Changelog

## isj-submission-v1.0 (24 September 2026)
- Added `LICENSE` (MIT, code) and `LICENSE-DATA.md` (CC BY 4.0, data).
- Added `REPRODUCIBILITY_MANIFEST.csv`: manuscript object, script, inputs, output, output digest, public status.
- Added `expected_outputs/` and `analysis/verify_reproduction.py`, which reruns the self-contained scripts in a clean copy and compares with the tracked outputs (JSON numbers within a relative tolerance of 1e-9, to absorb last-digit differences between platforms); `.github/workflows/reproduce.yml` runs it on every push.
- Added the text-overlap report on the submitted PDF (`experimental_results/overlap/`).
- Added `NOTES_ON_MANUSCRIPT.md`, which states the scope of three sentences of the submitted text.
- Regenerated `SHA256SUMS.txt` so that it covers every file in the repository, including `docs/README_vi.md` and nested checksum files.

## Initial data commit (23 September 2026, commit 85404bd)
- Exported results of E1 to E8, analysis scripts, frozen settings, README, requirements and citation file.
