#!/usr/bin/env python3
"""
Summarize Stage 2 / Stage 3 expectation-policy enforcement overhead comparison results.

Inputs:
- Stage 2: performance_data/test_result_*rpes.json
- Stage 3: performance_data/phase3_test_result_*ces.json

Outputs:
- quote_verification_comparison_report.json
- quote_verification_comparison_report.csv
- quote_verification_comparison_report.txt
"""
import argparse
import csv
import glob
import json
import logging
import os
import re


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def _safe_get(stats, key):
    return stats.get(key, {}) if isinstance(stats, dict) else {}


def _extract_stage2_rows(perf_dir):
    rows = []
    for path in sorted(glob.glob(os.path.join(perf_dir, "test_result_*rpes.json"))):
        with open(path, "r") as f:
            result = json.load(f)
        stats = result.get("statistics", {})
        native = _safe_get(stats, "phase2_native_quote_verification")
        ours = _safe_get(stats, "phase2_verification")
        quote_count = result.get("num_rpes", 0) or 1
        rows.append({
            "stage": "stage2",
            "count_label": "rpes",
            "count": result.get("num_rpes", 0),
            "metric_scope": "per_quote",
            "native_avg": native.get("avg", 0) / quote_count,
            "ours_avg": ours.get("avg", 0) / quote_count,
            "source_file": os.path.basename(path),
        })
    return rows


def _extract_stage3_rows(perf_dir):
    rows = []
    for path in sorted(glob.glob(os.path.join(perf_dir, "phase3_test_result_*ces.json"))):
        with open(path, "r") as f:
            result = json.load(f)
        stats = result.get("statistics", {})
        native = _safe_get(stats, "stage3_native_quote_verification")
        ours = _safe_get(stats, "auth_duration")
        rows.append({
            "stage": "stage3",
            "count_label": "ces",
            "count": result.get("num_ces", 0),
            "metric_scope": "per_auth",
            "native_avg": native.get("avg", 0),
            "ours_avg": ours.get("avg", 0),
            "source_file": os.path.basename(path),
        })
    return rows


def _sort_rows(rows):
    order = {"stage2": 0, "stage3": 1}
    return sorted(rows, key=lambda row: (order.get(row["stage"], 99), row["count"]))


def _write_json(rows, output_dir):
    path = os.path.join(output_dir, "quote_verification_comparison_report.json")
    with open(path, "w") as f:
        json.dump({"results": rows}, f, indent=2)
    return path


def _write_csv(rows, output_dir):
    path = os.path.join(output_dir, "quote_verification_comparison_report.csv")
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Stage",
            "Count Label",
            "Count",
            "Metric Scope",
            "Native Avg (s)",
            "Ours Avg (s)",
            "Source File",
        ])
        for row in rows:
            writer.writerow([
                row["stage"],
                row["count_label"],
                row["count"],
                row["metric_scope"],
                "%.3f" % row["native_avg"],
                "%.3f" % row["ours_avg"],
                row["source_file"],
            ])
    return path


def _write_txt(rows, output_dir):
    path = os.path.join(output_dir, "quote_verification_comparison_report.txt")
    with open(path, "w") as f:
        f.write("=" * 140 + "\n")
        f.write("Expectation-Policy Enforcement Overhead Report\n")
        f.write("=" * 140 + "\n\n")
        f.write("Stage  | Count | Kind | Scope     | Native Avg | Ours Avg | Source\n")
        f.write("-" * 110 + "\n")
        for row in rows:
            f.write(
                "%6s | %5d | %4s | %-9s | %10.3f | %8.3f | %s\n"
                % (
                    row["stage"],
                    row["count"],
                    row["count_label"],
                    row["metric_scope"],
                    row["native_avg"],
                    row["ours_avg"],
                    row["source_file"],
                )
            )
    return path


def main():
    parser = argparse.ArgumentParser(description="Generate Stage 2/3 expectation-policy overhead report")
    parser.add_argument("--perf-dir", type=str, default="./performance_data", help="performance data directory")
    args = parser.parse_args()

    perf_dir = os.path.abspath(args.perf_dir)
    os.makedirs(perf_dir, exist_ok=True)

    rows = _extract_stage2_rows(perf_dir) + _extract_stage3_rows(perf_dir)
    rows = _sort_rows(rows)

    if not rows:
        logger.error("No stage2/stage3 result files found in %s", perf_dir)
        return 1

    json_path = _write_json(rows, perf_dir)
    csv_path = _write_csv(rows, perf_dir)
    txt_path = _write_txt(rows, perf_dir)

    logger.info("Expectation-policy overhead report saved to:")
    logger.info("  %s", json_path)
    logger.info("  %s", csv_path)
    logger.info("  %s", txt_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
