#!/usr/bin/env python3
"""Text overlap between this manuscript and the two conference papers.

Method: extract the text of each PDF with pdftotext, cut each document before its
reference list, lowercase and tokenise to words, build overlapping 8-word shingles,
and report the share of the manuscript's distinct shingles that also appear in a
conference paper. Usage:

    python3 analysis/overlap_shingles.py manuscript.pdf conf1.pdf conf2.pdf [...]

The script prints the per-paper and union shares and every matching shingle, so that
the matches can be inspected rather than trusted.
"""
import re
import subprocess
import sys

K = 8
CUTS = ("\nREFERENCES\n", "\nR EFERENCES\n", "\nTÀI LIỆU THAM KHẢO\n")


def body_text(pdf: str) -> str:
    text = subprocess.run(["pdftotext", pdf, "-"], capture_output=True, text=True).stdout
    for cut in CUTS:
        i = text.find(cut)
        if i > 0:
            return text[:i]
    return text


def shingles(text: str, k: int = K) -> set[str]:
    words = re.findall(r"[a-zà-ỹ0-9]+", text.lower().replace("­", ""))
    return {" ".join(words[i:i + k]) for i in range(max(0, len(words) - k + 1))}


def main(argv: list[str]) -> None:
    manuscript, others = argv[1], argv[2:]
    S = shingles(body_text(manuscript))
    union: set[str] = set()
    print(f"{manuscript}: {len(S)} distinct {K}-word shingles")
    for pdf in others:
        T = shingles(body_text(pdf))
        union |= T
        n = len(S & T)
        print(f"  overlap with {pdf}: {n} ({100 * n / len(S):.2f}%)")
    hits = sorted(S & union)
    print(f"union overlap: {len(hits)} ({100 * len(hits) / len(S):.2f}%)")
    for h in hits:
        print("   ", h)


if __name__ == "__main__":
    main(sys.argv)
