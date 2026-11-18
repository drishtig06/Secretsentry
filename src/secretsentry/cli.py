from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from secretsentry import __version__
from secretsentry.scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretsentry",
        description="Scan local files for common accidentally committed secrets.",
    )
    parser.add_argument(
        "path", nargs="?", type=Path, default=Path.cwd(), help="file or directory to scan"
    )
    parser.add_argument(
        "--exclude", action="append", default=[], metavar="NAME",
        help="exclude a file or directory name (repeatable)",
    )
    parser.add_argument(
        "--max-file-size", type=int, default=1_000_000, metavar="BYTES",
        help="skip files larger than this (default: 1000000)",
    )
    parser.add_argument("--json", action="store_true", help="print redacted findings as JSON")
    parser.add_argument("--output", type=Path, help="write redacted JSON findings to a file")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_file_size < 1:
        parser.error("--max-file-size must be greater than zero")
    if not args.path.exists():
        parser.error(f"scan path does not exist: {args.path}")

    findings = scan(args.path, excludes=set(args.exclude), max_file_size=args.max_file_size)
    payload = json.dumps([asdict(finding) for finding in findings], indent=2)
    if args.output:
        try:
            args.output.write_text(f"{payload}\n", encoding="utf-8")
        except OSError as error:
            print(f"secretsentry: cannot write report: {error}", file=sys.stderr)
            return 2

    if args.json:
        print(payload)
    elif findings:
        for finding in findings:
            print(
                f"{finding.path}:{finding.line}: {finding.rule_id}: "
                f"{finding.description} [{finding.redacted_match}]"
            )
        print(f"\nFound {len(findings)} possible secret(s). Values are redacted.")
    else:
        print("No possible secrets found.")

    return 1 if findings else 0
