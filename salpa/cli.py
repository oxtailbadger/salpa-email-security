from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List

from salpa.parser import parse_eml
from salpa.analyzers import analyze
from salpa.report import build_report


def collect_eml_files(paths: List[str]) -> List[Path]:
    files = []
    for p in paths:
        path = Path(p)
        if path.is_file() and path.suffix == ".eml":
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(path.glob("*.eml")))
        else:
            print(f"Warning: skipping {p} (not a .eml file or directory)", file=sys.stderr)
    return files


def main():
    parser = argparse.ArgumentParser(
        prog="salpa",
        description="Salpa — Phishing Email Analyzer. Ingests .eml files and scores phishing likelihood.",
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="One or more .eml files or directories containing .eml files",
    )
    parser.add_argument(
        "-o", "--output",
        help="Write JSON report to a file instead of stdout",
    )
    args = parser.parse_args()

    eml_files = collect_eml_files(args.paths)
    if not eml_files:
        print("No .eml files found.", file=sys.stderr)
        sys.exit(1)

    results = []
    errors = 0
    for eml_path in eml_files:
        try:
            parsed = parse_eml(eml_path)
            features = analyze(parsed)
            results.append({
                "file": str(eml_path),
                "parsed": parsed,
                "features": features,
            })
        except Exception as e:
            errors += 1
            print(f"Error processing {eml_path}: {e}", file=sys.stderr)

    if errors:
        print(f"{errors} file(s) failed to parse.", file=sys.stderr)

    report = build_report(results)
    output = json.dumps(report, indent=2, ensure_ascii=False)

    if args.output:
        Path(args.output).write_text(output + "\n")
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)
