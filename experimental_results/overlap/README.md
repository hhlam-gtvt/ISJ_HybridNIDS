# Text-overlap check

`overlap_report.txt` is the unedited output of

    python3 analysis/overlap_shingles.py ISJ_manuscript_submitted_2026-09-23.pdf arXiv2609.24393_VNICT2026.pdf arXiv2609.26316_FAIR2026.pdf

run on 24 September 2026 with pdftotext (poppler). Only the file names in the report were shortened; the PDFs are not redistributed here. SHA-256 of the inputs:

| File | SHA-256 |
|---|---|
| Submitted manuscript PDF (20 pages) | 9124528ce6591c3322cd6192cf266381b6f57c4c02ebb96cf83f37c00b44b50e |
| arXiv:2609.24393 (VNICT 2026 detector work) | 5068cb56ed867552ce77548befeb1d92ff850115875af37bfc106a2acc3d6271 |
| arXiv:2609.26316 (FAIR 2026 post-alert work) | 3d0d8be6ac7d0ca4e606acf9d9d952cab5c677fdc5ba6bdb047a118bc10fb403 |

Result: 32 of 16,167 distinct 8-word shingles of the manuscript (0.20%) also occur in arXiv:2609.24393, 40 (0.25%) in arXiv:2609.26316, and 40 (0.25%) in their union. Every match is listed in the report. They are affiliations, contact addresses and the acknowledgment, the restated finding that the earlier model "added more than half a minute per alert", and one 8-word description of the output checks ("a validator, a guardrail, and an output sanitizer").
