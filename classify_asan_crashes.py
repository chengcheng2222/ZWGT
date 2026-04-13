#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional

SUMMARY_RE = re.compile(r"^SUMMARY:\s+AddressSanitizer:\s+(.+)$", re.MULTILINE)


def extract_summary(output: str) -> Optional[str]:
    m = SUMMARY_RE.search(output)
    return m.group(1).strip() if m else None


def safe_read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def list_seed_files(crash_dirs: List[str]) -> List[str]:
    seeds: List[str] = []
    for crash_dir in crash_dirs:
        if not os.path.isdir(crash_dir):
            continue

        try:
            names = sorted(os.listdir(crash_dir))
        except OSError:
            continue

        for name in names:
            path = os.path.join(crash_dir, name)
            if name.startswith("id") and os.path.isfile(path):
                seeds.append(path)

    return sorted(seeds)


def write_text(path: str, content: str) -> None:
    ensure_parent_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Classify crash seeds with an ASAN-built binary and deduplicate by ASAN SUMMARY."
    )
    parser.add_argument("--program", required=True, help="Path to ASAN target program")
    parser.add_argument("--arg", action="append", default=[], help="Argument passed to ASAN target, may be repeated")
    parser.add_argument("--timeout", type=int, default=15, help="Per-seed timeout in seconds")
    parser.add_argument("--output-json", required=True, help="Path to JSON report")
    parser.add_argument("--output-text", required=True, help="Path to human-readable summary")
    parser.add_argument("--details-dir", default="", help="Directory to store first full ASAN log for each unique bug type")
    parser.add_argument("crash_dirs", nargs="+", help="One or more crash directories")

    args = parser.parse_args()

    program = args.program
    program_args = args.arg
    target_cmd = [program] + program_args

    if not os.path.isfile(program):
        print(f"[ERROR] ASAN program does not exist: {program}", file=sys.stderr)
        return 2

    if not os.access(program, os.X_OK):
        print(f"[ERROR] ASAN program is not executable: {program}", file=sys.stderr)
        return 2

    seed_files = list_seed_files(args.crash_dirs)

    unique: Dict[str, Dict] = {}
    unclassified: List[Dict] = []
    timeouts: List[Dict] = []
    errors: List[Dict] = []

    total = 0
    duplicate_count = 0
    unclassified_count = 0
    timeout_count = 0
    error_count = 0

    if args.details_dir:
        os.makedirs(args.details_dir, exist_ok=True)

    for seed in seed_files:
        total += 1
        try:
            data = safe_read_bytes(seed)

            result = subprocess.run(
                target_cmd,
                input=data,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=args.timeout,
                check=False,
            )

            output = result.stdout.decode("utf-8", errors="replace")
            summary = extract_summary(output)

            if summary is None:
                unclassified_count += 1
                unclassified.append(
                    {
                        "seed": seed,
                        "returncode": result.returncode,
                    }
                )
                continue

            if summary not in unique:
                bug = {
                    "summary": summary,
                    "first_seed": seed,
                    "seed_paths": [seed],
                    "seed_count": 1,
                    "returncode": result.returncode,
                    "detail_log": "",
                }

                if args.details_dir:
                    digest = hashlib.sha256(summary.encode("utf-8")).hexdigest()[:16]
                    detail_name = f"bug_{len(unique) + 1:03d}_{digest}.log"
                    detail_path = os.path.join(args.details_dir, detail_name)
                    write_text(detail_path, output)
                    bug["detail_log"] = detail_path

                unique[summary] = bug
            else:
                unique[summary]["seed_paths"].append(seed)
                unique[summary]["seed_count"] += 1
                duplicate_count += 1

        except subprocess.TimeoutExpired as e:
            timeout_count += 1
            partial = ""
            if e.stdout:
                partial = e.stdout.decode("utf-8", errors="replace")
            timeouts.append(
                {
                    "seed": seed,
                    "partial_output": partial,
                }
            )

        except Exception as e:
            error_count += 1
            errors.append(
                {
                    "seed": seed,
                    "error": str(e),
                }
            )

    unique_bugs = sorted(unique.values(), key=lambda x: (x["summary"], x["first_seed"]))

    report = {
        "command": target_cmd,
        "crash_dirs": args.crash_dirs,
        "total_seed_files": total,
        "unique_bug_count": len(unique_bugs),
        "duplicate_count": duplicate_count,
        "unclassified_count": unclassified_count,
        "timeout_count": timeout_count,
        "error_count": error_count,
        "unique_bugs": unique_bugs,
        "unclassified": unclassified,
        "timeouts": timeouts,
        "errors": errors,
    }

    ensure_parent_dir(args.output_json)
    with open(args.output_json, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    lines: List[str] = []
    lines.append("=" * 120)
    lines.append("[ASAN DEDUPLICATED CRASH SUMMARY]")
    lines.append(f"Target command: {' '.join(target_cmd)}")
    lines.append(f"Crash directories: {', '.join(args.crash_dirs)}")
    lines.append(f"Total crash seeds: {total}")
    lines.append(f"Unique bug types: {len(unique_bugs)}")
    lines.append(f"Duplicate crash seeds: {duplicate_count}")
    lines.append(f"Unclassified seeds (no SUMMARY): {unclassified_count}")
    lines.append(f"Timeouts: {timeout_count}")
    lines.append(f"Execution errors: {error_count}")
    lines.append("=" * 120)
    lines.append("")

    if unique_bugs:
        for idx, bug in enumerate(unique_bugs, 1):
            lines.append("-" * 120)
            lines.append(f"[Unique Bug #{idx}]")
            lines.append(f"SUMMARY: AddressSanitizer: {bug['summary']}")
            lines.append(f"First seed: {bug['first_seed']}")
            lines.append(f"Matching seed count: {bug['seed_count']}")
            if bug.get("detail_log"):
                lines.append(f"Saved full ASAN log: {bug['detail_log']}")
            lines.append("Matching seed files:")
            for seed_path in bug["seed_paths"]:
                lines.append(f"  - {seed_path}")
            lines.append("")
    else:
        lines.append("[INFO] No ASAN SUMMARY extracted from crash seeds.")
        lines.append("")

    if unclassified:
        lines.append("-" * 120)
        lines.append("[Unclassified seeds]")
        for item in unclassified:
            lines.append(f"  - {item['seed']} (returncode={item['returncode']})")
        lines.append("")

    if timeouts:
        lines.append("-" * 120)
        lines.append("[Timeout seeds]")
        for item in timeouts:
            lines.append(f"  - {item['seed']}")
        lines.append("")

    if errors:
        lines.append("-" * 120)
        lines.append("[Execution errors]")
        for item in errors:
            lines.append(f"  - {item['seed']} :: {item['error']}")
        lines.append("")

    text_output = "\n".join(lines)
    write_text(args.output_text, text_output)
    print(text_output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
