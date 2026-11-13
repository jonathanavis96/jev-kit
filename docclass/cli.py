#!/usr/bin/env python3
"""python3 -m docclass.cli --taxonomy <t.json> <file.pdf>

Classify each page of a TEXT-LAYER PDF against a taxonomy.

Text layer only, deliberately. `pdftotext` returns empty text for a scan, and
this tool reports that page as `needs_review` with the reason saying so, rather
than sending an empty string to a model and filing whatever comes back. A
scanned or handwritten document is a different job: put the page image in front
of a vision model instead.

Output is one JSON object per page on stdout (JSON lines), so it pipes. Use
--summary for a table instead.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from docclass.classify import (
    ClassificationError,
    classify_page,
    default_taxonomy_path,
    load_taxonomy,
)

PAGE_BREAK = "\f"


def page_texts(path):
    """Per-page text from a PDF, via poppler's pdftotext.

    Raises ClassificationError with something actionable rather than a
    traceback: this is the one dependency the tool cannot do without, and it
    is a named system package.
    """
    if not os.path.isfile(path):
        raise ClassificationError("no such file: %s" % path)
    if shutil.which("pdftotext") is None:
        raise ClassificationError(
            "pdftotext is not installed. It is part of poppler-utils:\n"
            "    sudo apt install poppler-utils")
    try:
        proc = subprocess.run(
            ["pdftotext", "-layout", path, "-"],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        raise ClassificationError("pdftotext timed out on %s" % path) from None
    if proc.returncode != 0:
        raise ClassificationError(
            "pdftotext failed on %s: %s" % (path, (proc.stderr or "").strip()[:300]))

    pages = proc.stdout.split(PAGE_BREAK)
    if pages and not pages[-1].strip():
        pages = pages[:-1]
    return pages


def classify_document(path, taxonomy, ask=None, first=None, last=None):
    pages = page_texts(path)
    start = (first - 1) if first else 0
    end = last if last else len(pages)
    out = []
    for index in range(start, min(end, len(pages))):
        result = classify_page(pages[index], taxonomy, ask=ask, page_number=index + 1)
        result["file"] = os.path.basename(path)
        out.append(result)
    return out


def print_summary(results):
    print("%-5s %-9s %-34s %-6s %s" % ("page", "status", "label", "conf", "why"))
    print("-" * 100)
    for r in results:
        conf = r.get("member_confidence")
        if conf is None:
            conf = r.get("family_confidence") or 0.0
        print("%-5s %-9s %-34s %-6.2f %s" % (
            r.get("page"), r.get("status"), r.get("label") or "-", conf,
            (r.get("reason") or "")[:44]))
    print()
    counts = {}
    for r in results:
        counts[r.get("status")] = counts.get(r.get("status"), 0) + 1
    print("pages: %d  %s" % (len(results),
                             "  ".join("%s=%d" % kv for kv in sorted(counts.items()))))
    review = [r for r in results if r.get("status") != "classified"]
    if review:
        print("%d page(s) need a human: %s"
              % (len(review), ", ".join(str(r.get("page")) for r in review)))


def _page_number(text):
    """A 1-based page number. A negative --first indexed pages from the end
    and then classified them again from the start, numbered 0 and below."""
    try:
        n = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("%r is not a page number" % text) from None
    if n < 1:
        raise argparse.ArgumentTypeError("page numbers start at 1, not %d" % n)
    return n


def main(argv=None):
    parser = argparse.ArgumentParser(description=next(iter((__doc__ or "").splitlines()), ""))
    parser.add_argument("pdf", help="a text-layer PDF")
    parser.add_argument("--taxonomy", default=None,
                        help="taxonomy JSON (default: docclass/taxonomies/example.json)")
    parser.add_argument("--first", type=_page_number, default=None, help="first page, 1-based")
    parser.add_argument("--last", type=_page_number, default=None, help="last page, inclusive")
    parser.add_argument("--summary", action="store_true", help="a table instead of JSON lines")
    args = parser.parse_args(argv)

    try:
        taxonomy = load_taxonomy(args.taxonomy or default_taxonomy_path())
        results = classify_document(args.pdf, taxonomy, first=args.first, last=args.last)
    except ClassificationError as exc:
        print("docclass: %s" % exc, file=sys.stderr)
        return 2

    if args.summary:
        print_summary(results)
    else:
        for result in results:
            print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
