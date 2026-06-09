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

Q2_PRIMARY_FIELDS = [
    "recovery_success_ms",
    "warmup_elapsed_ms",
    "full_query_collection_ms",
]

QUORUM_BREAKDOWN_FIELDS = [
    "evidence_quote_verification_ms",
    "signed_state_verification_ms",
    "counter_selection_ms",
]

POST_RECOVERY_FIELDS = [
    "new_quote_generation_ms",
    "new_quote_broadcast_ms",
]

OPTIONAL_COUNT_FIELDS = [
    "warmup_warmed_peers",
    "warmup_total_peers",
    "evidence_update_peer_count",
    "evidence_update_accepted_count",
]

RECOVERY_RUNS_SUBDIR = "recovery_runs"

DETAIL_METRIC_FIELDS = [
    "recovery_success_ms",
    "warmup_elapsed_ms",
    "full_query_collection_ms",
    "evidence_quote_verification_ms",
    "signed_state_verification_ms",
    "counter_selection_ms",
    "new_quote_generation_ms",
    "new_quote_broadcast_ms",
    "warmup_warmed_peers",
    "warmup_total_peers",
    "evidence_update_peer_count",
    "evidence_update_accepted_count",
    "valid_response_count",
    "quorum",
]


def recovery_success_ms(result):
    value = result.get("recovery_success_ms")
    if value is not None:
        return float(value)
    value = result.get("total_recovery_ms")
    if value is not None:
        return float(value)
    return 0.0


def json_signature(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if payload.get("total_recovery_ms") is None and payload.get("recovery_success_ms") is None:
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
    row["recovery_success_ms"] = mean([recovery_success_ms(result) for result in results])
    row["total_recovery_ms"] = row["recovery_success_ms"]
    row["recovery_query_ms"] = row["recovery_success_ms"]
    for field in Q2_PRIMARY_FIELDS:
        if field == "recovery_success_ms":
            continue
        row[field] = mean([result.get(field, 0.0) for result in results])
    for field in QUORUM_BREAKDOWN_FIELDS + POST_RECOVERY_FIELDS + OPTIONAL_COUNT_FIELDS:
        row[field] = mean([result.get(field, 0.0) for result in results])
    row["valid_response_count"] = mean([result.get("valid_response_count", 0) for result in results])
    row["quorum"] = mean([result.get("quorum", 0) for result in results])
    return row


def summarize(label, directory, num_rpes=None):
    return summarize_results(label, load_recovery_results(directory), num_rpes=num_rpes, directory=directory)


def run_label_from_result(result, index):
    source = result.get("_source") or ""
    if source:
        name = os.path.basename(source)
        if name.endswith(".json"):
            name = name[:-5]
        return name
    return "run_%04d" % (index + 1)


def build_run_detail_row(result, run_name, label=None, num_rpes=None):
    row = {
        "run": run_name,
        "label": label,
        "num_rpes": num_rpes,
        "recovery_success_ms": recovery_success_ms(result),
    }
    for field in DETAIL_METRIC_FIELDS:
        if field == "recovery_success_ms":
            continue
        row[field] = result.get(field, 0.0)
    return row


def build_detail_rows(label, results, num_rpes=None, directory=None):
    if not results:
        return []
    if num_rpes is None:
        num_rpes = infer_num_rpes(label, directory)
    detail_rows = []
    for index, result in enumerate(results):
        detail_rows.append(
            build_run_detail_row(
                result,
                run_label_from_result(result, index),
                label=label,
                num_rpes=num_rpes,
            )
        )
    avg = summarize_results(label, results, num_rpes=num_rpes, directory=directory)
    avg["run"] = "AVG"
    detail_rows.append(avg)
    return detail_rows


def detail_csv_fieldnames():
    return ["run", "label", "num_rpes"] + DETAIL_METRIC_FIELDS


def fmt(value):
    if value is None:
        return "N/A"
    return "%.3f" % value


def csv_fieldnames():
    return [
        "label",
        "num_rpes",
        "runs",
        "recovery_success_ms",
        "total_recovery_ms",
        "warmup_elapsed_ms",
        "full_query_collection_ms",
        "evidence_quote_verification_ms",
        "signed_state_verification_ms",
        "counter_selection_ms",
        "new_quote_generation_ms",
        "new_quote_broadcast_ms",
        "warmup_warmed_peers",
        "warmup_total_peers",
        "evidence_update_peer_count",
        "evidence_update_accepted_count",
        "valid_response_count",
        "quorum",
    ]


def write_detail_csv(detail_rows, output_path):
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=detail_csv_fieldnames())
        writer.writeheader()
        for row in detail_rows:
            writer.writerow({key: row.get(key) for key in detail_csv_fieldnames()})


def write_csv(rows, output_path):
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fieldnames())
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in csv_fieldnames()})


def _write_detail_table_txt(f, detail_rows, title):
    f.write(title + "\n")
    header = (
        "Run | Label | N | Recovery Success | Warmup | Full Collection | "
        "Evidence (sum) | Signed State (sum) | Counter Select | Quote Gen | "
        "Broadcast | Warmed | Warm Total | Update Peers | Valid | Quorum\n"
    )
    f.write(header)
    f.write("-" * 180 + "\n")
    for row in detail_rows:
        f.write(
            "%s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s\n"
            % (
                row.get("run", ""),
                row.get("label", ""),
                row.get("num_rpes") if row.get("num_rpes") is not None else "N/A",
                fmt(row.get("recovery_success_ms")),
                fmt(row.get("warmup_elapsed_ms")),
                fmt(row.get("full_query_collection_ms")),
                fmt(row.get("evidence_quote_verification_ms")),
                fmt(row.get("signed_state_verification_ms")),
                fmt(row.get("counter_selection_ms")),
                fmt(row.get("new_quote_generation_ms")),
                fmt(row.get("new_quote_broadcast_ms")),
                fmt(row.get("warmup_warmed_peers")),
                fmt(row.get("warmup_total_peers")),
                fmt(row.get("evidence_update_peer_count")),
                fmt(row.get("valid_response_count")),
                fmt(row.get("quorum")),
            )
        )
    f.write("\n")


def write_txt(rows, output_path, detail_rows=None):
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 100 + "\n")
        f.write("Q2: SRAS-FT Failed RPE Recovery Latency\n")
        f.write("=" * 100 + "\n\n")
        f.write(
            "Q2 metric (recovery_success_ms): RecoveryQuery quorum reached and attestation counter "
            "selected. Excludes warmup, waiting for slow peers after quorum, new quote generation, "
            "and EvidenceUpdate dispatch.\n\n"
        )

        if detail_rows:
            _write_detail_table_txt(
                f,
                detail_rows,
                "All runs (ms; last row AVG)",
            )

        f.write("Summary by label (ms)\n")
        f.write("Primary timing (ms)\n")
        f.write(
            "Label | N | Runs | Recovery Success | Warmup | Full Query Collection\n"
        )
        f.write("-" * 90 + "\n")
        for row in rows:
            f.write(
                "%s | %s | %d | %s | %s | %s\n"
                % (
                    row["label"],
                    row["num_rpes"] if row["num_rpes"] is not None else "N/A",
                    row["runs"],
                    fmt(row["recovery_success_ms"]),
                    fmt(row["warmup_elapsed_ms"]),
                    fmt(row["full_query_collection_ms"]),
                )
            )

        f.write(
            "\nQuorum validation breakdown (ms; sum of per-responder costs inside quorum, "
            "not additive wall-clock stack)\n"
        )
        f.write(
            "Label | Evidence Quote Verify (sum) | Signed State Verify (sum) | Counter Select\n"
        )
        f.write("-" * 90 + "\n")
        for row in rows:
            f.write(
                "%s | %s | %s | %s\n"
                % (
                    row["label"],
                    fmt(row["evidence_quote_verification_ms"]),
                    fmt(row["signed_state_verification_ms"]),
                    fmt(row["counter_selection_ms"]),
                )
            )

        f.write("\nPost-recovery (excluded from Q2 recovery_success_ms)\n")
        f.write("Label | New Quote Gen | Broadcast Dispatch | Update Peers Dispatched\n")
        f.write("-" * 90 + "\n")
        for row in rows:
            f.write(
                "%s | %s | %s | %s\n"
                % (
                    row["label"],
                    fmt(row["new_quote_generation_ms"]),
                    fmt(row["new_quote_broadcast_ms"]),
                    fmt(row["evidence_update_peer_count"]),
                )
            )

        f.write(
            "\nNotes:\n"
            "- total_recovery_ms in perf JSON equals recovery_success_ms (Q2 answer).\n"
            "- recovery_query_ms is a legacy alias of recovery_success_ms.\n"
            "- full_query_collection_ms may exceed recovery_success_ms when slow peers finish after quorum.\n"
            "- new_quote_broadcast_ms is non-blocking dispatch only; peer DCAP verify is deferred to CE connect.\n"
            "- evidence_update_accepted_count counts dispatched peers when broadcast does not wait.\n"
        )


def write_reports(rows, output_dir, detail_rows=None):
    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, "q2_ft_recovery_report.csv")
    detail_csv_path = os.path.join(output_dir, "q2_ft_recovery_runs.csv")
    txt_path = os.path.join(output_dir, "q2_ft_recovery_report.txt")
    json_path = os.path.join(output_dir, "q2_ft_recovery_report.json")
    write_csv(rows, csv_path)
    if detail_rows:
        write_detail_csv(detail_rows, detail_csv_path)
    write_txt(rows, txt_path, detail_rows=detail_rows)
    json_payload = {
        "summary": rows,
        "detail_with_avg": detail_rows or [],
        "runs": [row for row in (detail_rows or []) if row.get("run") != "AVG"],
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_payload, f, indent=2)
    return csv_path, txt_path, json_path, detail_csv_path


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
                    "Captured recovery run %d/%d: recovery_success=%.3fms -> %s",
                    len(collected_paths),
                    repeat,
                    recovery_success_ms(payload),
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

        detail_rows = build_detail_rows(self.label, results, num_rpes=self.num_rpes, directory=self.perf_dir)
        csv_path, txt_path, json_path, detail_csv_path = write_reports([row], self.perf_dir, detail_rows=detail_rows)
        logger.info("=" * 60)
        logger.info("Q2 recovery report: %d run(s) collected", len(collected_paths))
        if row:
            logger.info(
                "  recovery_success=%.3fms warmup=%.3fms full_collection=%.3fms "
                "evidence_verify(sum)=%.3fms signed_state_verify(sum)=%.3fms "
                "quote_gen=%.3fms quote_broadcast=%.3fms",
                row["recovery_success_ms"],
                row["warmup_elapsed_ms"],
                row["full_query_collection_ms"],
                row["evidence_quote_verification_ms"],
                row["signed_state_verification_ms"],
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
    detail_rows = []
    for raw_input in inputs:
        label, directory = parse_input(raw_input)
        results = load_recovery_results(directory)
        if not results:
            raise SystemExit("No recovery perf JSON files found in %s" % directory)
        row = summarize_results(label, results, directory=directory)
        rows.append(row)
        detail_rows.extend(build_detail_rows(label, results, directory=directory))
    rows.sort(key=lambda row: (row["num_rpes"] is None, row["num_rpes"] or 0, row["label"]))
    return write_reports(rows, output_dir, detail_rows=detail_rows)


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
        csv_path, txt_path, json_path, detail_csv_path = generate_report(args.input, output_dir)
        print("Generated:")
        print("  %s" % csv_path)
        print("  %s" % detail_csv_path)
        print("  %s" % txt_path)
        print("  %s" % json_path)
        sys.exit(0)

    if args.report_only:
        output_dir = args.output_dir or args.perf_dir
        label = args.label or os.path.basename(os.path.abspath(output_dir).rstrip(os.sep))
        results = load_recovery_results(output_dir)
        if not results:
            raise SystemExit("No recovery perf JSON files found in %s" % output_dir)
        row = summarize_results(label, results, num_rpes=args.num_rpes, directory=output_dir)
        detail_rows = build_detail_rows(label, results, num_rpes=args.num_rpes, directory=output_dir)
        csv_path, txt_path, json_path, detail_csv_path = write_reports([row], output_dir, detail_rows=detail_rows)
        print("Generated:")
        print("  %s" % csv_path)
        print("  %s" % txt_path)
        print("  %s" % json_path)
        print("  %s" % detail_csv_path)
        sys.exit(0)

    parser.error("Specify --repeat, --input, or --report-only")


if __name__ == "__main__":
    main()
