# Notes on the submitted manuscript

The manuscript was submitted to ISJ on 23 September 2026 and cannot be changed during review. These notes state precisely how the submitted text relates to this release. They clarify scope; they do not change any result.

1. **Scope of the release (Section IX-A).** The sentence "The data, code, and settings of this study are released in the repository" refers to what this release contains: the analysis code, the retained frozen settings, the exported results of E1 to E8, and selected run-level evidence. Raw packet captures, the E2 prediction export and several historical artifacts are not public. `REPRODUCIBILITY_MANIFEST.csv` lists every table, figure and statistical check with its script, inputs and output, and marks each item that is not public with the reason.

2. **Scope of "no tested difference was significant" (Abstract).** The sentence refers to the two paired routing comparisons of E8 (exact McNemar, discordant pairs 6 and 9, p = .61; 6 and 3, p = .51). It does not cover E3, where Suricata-only (S1) compared with S2, S4 and S6 on the primary source gives p = .035 (discordant pairs 3 and 12; Table X; `experimental_results/e3/e3_mcnemar_table.csv`). That result reflects class prevalence, as the manuscript states in Section VI-B.

3. **Artifacts listed as missing (Section VIII).** The list refers to the per-run traces of the frozen E6 protocol and to the raw archives of the supplementary E6 searches, that is the lower-rate and RF-off runs. The records of the grouped E6 replay reported in Section VI-E are a different run and are included (`experimental_results/e6/supplementary_v552_20260923/`). The status of each listed item is given in `REPRODUCIBILITY_MANIFEST.csv`.

4. **Text overlap (Section IX).** The shingle comparison was rerun on the submitted PDF and the two arXiv preprints; the report and input digests are in `experimental_results/overlap/`. Union overlap is 0.25% of the manuscript's distinct 8-word shingles. Besides affiliations, contact addresses, the acknowledgment and the restated finding, the matches include one 8-word description of the output checks, "a validator, a guardrail, and an output sanitizer".

5. **Release identifier.** The manuscript cites the repository URL. The release that accompanies the submitted manuscript is tagged `isj-submission-v1.0`; later changes, if any, will be tagged separately and recorded in `CHANGELOG.md`.
