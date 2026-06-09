#!/usr/bin/env python3
"""
Q2: SRAS-FT failed RPE recovery latency — collect recovery perf and generate reports.

Collect mode (--repeat): watch a recovering RPE for crash/restart recovery events,
snapshot each rpe_ft_recovery_perf_*.json into --perf-dir, then write reports.

Report mode (--input and/or --report-only): aggregate existing recovery perf JSON files.
"""
import argparse
import csv
import glob
import hashlib
import json
import logging
import os
import re
import sys
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

STACK_FIELDS = [
    "recovery_query_ms",
    "evidence_quote_verification_ms",
    "signed_state_verification_ms",
    "counter_selection_ms",
    "new_quote_generation_ms",
    "new_quote_broadcast_ms",
]

RECOVERY_RUNS_SUBDIR = "recovery_runs"


def json_signature(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if payload.get("total_recovery_ms") is None:
        return None
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_recovery_json(path):
    with open(path, "r", encoding="utf-8") as f:
        result = json.load(f)
    result["_source"] = path
    return result


def load_recovery_results(directory):
    results = []
    runs_dir = os.path.join(directory, RECOVERY_RUNS_SUBDIR)
    patterns = []
    if os.path.isdir(runs_dir):
        patterns.append(os.path.join(runs_dir, "*.json"))
    patterns.append(os.path.join(directory, "rpe_ft_recovery_perf_*.json"))
    seen = set()
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            if path in seen:
                continue
            seen.add(path)
            results.append(load_recovery_json(path))
    return results


def load_recovery_results_from_paths(paths):
    return [load_recovery_json(path) for path in paths]


def mean(values):
    values = [value for value in values if value is not None]
    if not values:
        return 0.0
    return sum(values) / len(values)


def infer_num_rpes(label, directory):
    match = re.search(r"(?:^|[_-])n(\d+)(?:$|[_-])", label or "")
    if match:
        return int(match.group(1))
    if directory:
        match = re.search(r"(?:^|[_-])n(\d+)(?:$|[_-])", os.path.basename(directory.rstrip(os.sep)))
        if match:
            return int(match.group(1))
    return None


def summarize_results(label, results, num_rpes=None, directory=None):
    if not results:
        return None
    if num_rpes is None:
        num_rpes = infer_num_rpes(label, directory)
    row = {
        "label": label,
        "num_rpes": num_rpes,
        "runs": len(results),
    }
    for field in STACK_FIELDS:
        row[field] = mean([result.get(field, 0.0) for result in results])
    row["total_recovery_ms"] = mean([result.get("total_recovery_ms", 0.0) for result in results])
    row["valid_response_count"] = mean([result.get("valid_response_count", 0) for result in results])
    row["quorum"] = mean([result.get("quorum", 0) for result in results])
    return row


def summarize(label, directory, num_rpes=None):
    return summarize_results(label, load_recovery_results(directory), num_rpes=num_rpes, directory=directory)


def fmt(value):
    if value is None:
        return "N/A"
    return "%.3f" % value


def write_csv(rows, output_path):
    fieldnames = [
        "label",
        "num_rpes",
        "runs",
        "total_recovery_ms",
        "recovery_query_ms",
        "evidence_quote_verification_ms",
        "signed_state_verification_ms",
        "counter_selection_ms",
        "new_quote_generation_ms",
        "new_quote_broadcast_ms",
        "valid_response_count",
        "quorum",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_txt(rows, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 100 + "\n")
        f.write("Q2: SRAS-FT Failed RPE Recovery Latency\n")
        f.write("=" * 100 + "\n\n")
        f.write(
            "Stack components (ms): Recovery Query | Evidence Quote Verify | "
            "Signed State Verify | Counter Selection | New Quote Gen | New Quote Broadcast\n"
        )
        f.write(
            "Label | N | Runs | Total | Recovery Query | Evidence Quote Verify | "
            "Signed State Verify | Counter Selection | New Quote Gen | New Quote Broadcast\n"
        )
        f.write("-" * 150 + "\n")
        for row in rows:
            f.write(
                "%s | %s | %d | %s | %s | %s | %s | %s | %s | %s\n"
                % (
                    row["label"],
                    row["num_rpes"] if row["num_rpes"] is not None else "N/A",
                    row["runs"],
                    fmt(row["total_recovery_ms"]),
                    fmt(row["recovery_query_ms"]),
                    fmt(row["evidence_quote_verification_ms"]),
                    fmt(row["signed_state_verification_ms"]),
                    fmt(row["counter_selection_ms"]),
                    fmt(row["new_quote_generation_ms"]),
                    fmt(row["new_quote_broadcast_ms"]),
                )
            )
        f.write(
            "\nAll values are milliseconds. Evidence/signed-state verify columns sum per-response "
            "costs across quorum responses. New Quote Broadcast is non-blocking dispatch only.\n"
        )


def write_reports(rows, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, "q2_ft_recovery_report.csv")
    txt_path = os.path.join(output_dir, "q2_ft_recovery_report.txt")
    json_path = os.path.join(output_dir, "q2_ft_recovery_report.json")
    write_csv(rows, csv_path)
    write_txt(rows, txt_path)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    return csv_path, txt_path, json_path


def parse_input(value):
    if "=" in value:
        label, directory = value.split("=", 1)
        return label.strip(), directory.strip()
    directory = value.strip()
    return os.path.basename(directory.rstrip(os.sep)), directory


class Q2FTRecoveryTest:
    def __init__(self, perf_dir, rpe_dir=None, label=None, num_rpes=None):
        self.perf_dir = os.path.abspath(perf_dir)
        self.rpe_dir = os.path.abspath(rpe_dir) if rpe_dir else None
        self.label = label or os.path.basename(self.perf_dir.rstrip(os.sep))
        self.num_rpes = num_rpes
        self.runs_dir = os.path.join(self.perf_dir, RECOVERY_RUNS_SUBDIR)

    def _discover_live_recovery_files(self):
        if not self.rpe_dir:
            return []
        perf_data_dir = os.path.join(self.rpe_dir, "performance_data")
        return sorted(glob.glob(os.path.join(perf_data_dir, "rpe_ft_recovery_perf_*.json")))

    def _expt_cache_path(self):
        if not self.rpe_dir:
            return None
        for subdir in ("performance_data", "collaterals"):
            path = os.path.join(self.rpe_dir, subdir, "expt_cache.json")
            if os.path.exists(path):
                return path
        return os.path.join(self.rpe_dir, "performance_data", "expt_cache.json")

    def _next_run_path(self):
        os.makedirs(self.runs_dir, exist_ok=True)
        existing = sorted(glob.glob(os.path.join(self.runs_dir, "run_*.json")))
        next_idx = len(existing) + 1
        return os.path.join(self.runs_dir, "run_%04d.json" % next_idx)

    def _print_collect_instructions(self, repeat):
        logger.info("=" * 60)
        logger.info("Q2 recovery collection: waiting for %d new crash/restart recovery run(s)", repeat)
        logger.info("Recovering RPE directory: %s", self.rpe_dir)
        logger.info("Output directory: %s", self.perf_dir)
        logger.info("=" * 60)
        logger.info("Prerequisites:")
        logger.info("  1. Multi-party FT is up and CE auths have populated peer recorded state")
        logger.info("  2. %s exists (from a prior normal RPE startup)", self._expt_cache_path())
        logger.info("For each repeat:")
        logger.info("  - kill the recovering RPE process (simulate crash)")
        logger.info("  - do NOT use start_multi_rpe.py --stop (it deletes expt_cache.json)")
        logger.info("  - restart: cd %s && ./startup.sh start", self.rpe_dir)
        logger.info("=" * 60)

    def collect_recovery_runs(self, repeat, timeout=900):
        if repeat < 1:
            raise ValueError("--repeat must be >= 1")
        if not self.rpe_dir or not os.path.isdir(self.rpe_dir):
            logger.error("Recovering RPE directory not found: %s", self.rpe_dir)
            return None

        live_files = self._discover_live_recovery_files()
        if not live_files:
            logger.warning(
                "No live rpe_ft_recovery_perf_*.json under %s/performance_data yet; "
                "will watch for first recovery write",
                self.rpe_dir,
            )

        expt_cache = self._expt_cache_path()
        if not os.path.exists(expt_cache):
            logger.warning("expt_cache.json not found at %s — recovery may not run on restart", expt_cache)

        self._print_collect_instructions(repeat)
        last_signatures = {path: json_signature(path) for path in live_files}
        collected_paths = []
        start_time = time.time()

        while len(collected_paths) < repeat:
            if time.time() - start_time > timeout:
                logger.error(
                    "Timeout waiting for %d recovery run(s); collected %d",
                    repeat,
                    len(collected_paths),
                )
                return None

            live_files = self._discover_live_recovery_files()
            for path in live_files:
                signature = json_signature(path)
                if signature is None:
                    continue
                if last_signatures.get(path) == signature:
                    continue
                dest = self._next_run_path()
                with open(path, "r", encoding="utf-8") as src_file:
                    payload = json.load(src_file)
                payload["_collected_from"] = path
                payload["_collected_at"] = time.time()
                with open(dest, "w", encoding="utf-8") as dest_file:
                    json.dump(payload, dest_file, indent=2)
                last_signatures[path] = signature
                collected_paths.append(dest)
                logger.info(
                    "Captured recovery run %d/%d: total=%.3fms -> %s",
                    len(collected_paths),
                    repeat,
                    float(payload.get("total_recovery_ms", 0.0)),
                    dest,
                )
                if len(collected_paths) >= repeat:
                    break
            time.sleep(1)

        results = load_recovery_results_from_paths(collected_paths)
        row = summarize_results(self.label, results, num_rpes=self.num_rpes, directory=self.perf_dir)
        session = {
            "label": self.label,
            "recovering_rpe_dir": self.rpe_dir,
            "target_new_recovery_runs": repeat,
            "collected_new_recovery_runs": len(collected_paths),
            "recovery_run_files": collected_paths,
            "summary": row,
            "recovery_results": results,
        }
        session_path = os.path.join(self.perf_dir, "q2_recovery_session.json")
        os.makedirs(self.perf_dir, exist_ok=True)
        with open(session_path, "w", encoding="utf-8") as f:
            json.dump(session, f, indent=2)

        csv_path, txt_path, json_path = write_reports([row], self.perf_dir)
        logger.info("=" * 60)
        logger.info("Q2 recovery report: %d run(s) collected", len(collected_paths))
        if row:
            logger.info(
                "  total=%.3fms query=%.3fms evidence_verify=%.3fms signed_state_verify=%.3fms "
                "counter_select=%.3fms quote_gen=%.3fms quote_broadcast=%.3fms",
                row["total_recovery_ms"],
                row["recovery_query_ms"],
                row["evidence_quote_verification_ms"],
                row["signed_state_verification_ms"],
                row["counter_selection_ms"],
                row["new_quote_generation_ms"],
                row["new_quote_broadcast_ms"],
            )
        logger.info("  Session: %s", session_path)
        logger.info("  CSV: %s", csv_path)
        logger.info("  TXT: %s", txt_path)
        logger.info("  JSON: %s", json_path)
        logger.info("=" * 60)
        return session


def generate_report(inputs, output_dir):
    rows = []
    for raw_input in inputs:
        label, directory = parse_input(raw_input)
        row = summarize(label, directory)
        if row is None:
            raise SystemExit("No recovery perf JSON files found in %s" % directory)
        rows.append(row)
    rows.sort(key=lambda row: (row["num_rpes"] is None, row["num_rpes"] or 0, row["label"]))
    return write_reports(rows, output_dir)


def main():
    parser = argparse.ArgumentParser(
        description="Q2 SRAS-FT recovery test: collect crash/restart perf and/or generate reports"
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=None,
        help="Collect N new recovery runs from --rpe-dir after crash/restart",
    )
    parser.add_argument(
        "--rpe-dir",
        type=str,
        default=None,
        help="Recovering RPE directory to watch (default: RPE_party1 under project root)",
    )
    parser.add_argument(
        "--perf-dir",
        type=str,
        default="./performance_data/q2",
        help="Directory for collected recovery runs and generated reports",
    )
    parser.add_argument(
        "--label",
        type=str,
        default=None,
        help="Report label (default: perf-dir basename, e.g. q2_n5)",
    )
    parser.add_argument(
        "--num-rpes",
        type=int,
        default=None,
        help="Override N for report row (default: infer nN from label/path)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=900,
        help="Seconds to wait for --repeat collection (default: 900)",
    )
    parser.add_argument(
        "--input",
        action="append",
        help="Report-only input directory, optionally label=dir. Repeat for N=2/4/8.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Report output directory for --input mode (default: --perf-dir)",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Only generate report from --input and/or existing --perf-dir/recovery_runs",
    )
    args = parser.parse_args()

    if args.repeat is not None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        rpe_dir = args.rpe_dir
        if rpe_dir is None:
            rpe_dir = os.path.join(base_dir, "RPE_party1")
        test = Q2FTRecoveryTest(
            perf_dir=args.perf_dir,
            rpe_dir=rpe_dir,
            label=args.label,
            num_rpes=args.num_rpes,
        )
        result = test.collect_recovery_runs(args.repeat, timeout=args.timeout)
        sys.exit(0 if result else 1)

    if args.input:
        output_dir = args.output_dir or args.perf_dir
        csv_path, txt_path, json_path = generate_report(args.input, output_dir)
        print("Generated:")
        print("  %s" % csv_path)
        print("  %s" % txt_path)
        print("  %s" % json_path)
        sys.exit(0)

    if args.report_only:
        output_dir = args.output_dir or args.perf_dir
        label = args.label or os.path.basename(os.path.abspath(output_dir).rstrip(os.sep))
        row = summarize(label, output_dir, num_rpes=args.num_rpes)
        if row is None:
            raise SystemExit("No recovery perf JSON files found in %s" % output_dir)
        csv_path, txt_path, json_path = write_reports([row], output_dir)
        print("Generated:")
        print("  %s" % csv_path)
        print("  %s" % txt_path)
        print("  %s" % json_path)
        sys.exit(0)

    parser.error("Specify --repeat, --input, or --report-only")


if __name__ == "__main__":
    main()
