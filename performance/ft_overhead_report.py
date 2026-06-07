#!/usr/bin/env python3
import argparse
import csv
import glob
import json
import os
import re


def load_results(perf_dir):
    results = {}
    pattern = os.path.join(perf_dir, "phase3_test_result_*ces.json")
    for path in glob.glob(pattern):
        match = re.search(r"phase3_test_result_(\d+)ces\.json$", os.path.basename(path))
        if not match:
            continue
        with open(path, "r", encoding="utf-8") as f:
            result = json.load(f)
        results[int(match.group(1))] = result
    return results


def get_avg_auth(result):
    return result.get("statistics", {}).get("auth_duration", {}).get("avg", 0.0) or 0.0


def get_total_time(result):
    return result.get("rpe_total_time", 0.0) or 0.0


def get_ft_prop(result):
    return result.get("statistics", {}).get("ft_state_propagation", {}).get("avg", 0.0) or 0.0


def pct(delta, base):
    if base <= 0:
        return None
    return (delta / base) * 100.0


def fmt(value):
    if value is None:
        return "N/A"
    return "%.6f" % value


def build_rows(baseline_results, ft_results):
    rows = []
    for num_ces in sorted(set(baseline_results.keys()) & set(ft_results.keys())):
        baseline = baseline_results[num_ces]
        ft = ft_results[num_ces]
        baseline_avg = get_avg_auth(baseline)
        ft_avg = get_avg_auth(ft)
        avg_delta = ft_avg - baseline_avg
        baseline_total = get_total_time(baseline)
        ft_total = get_total_time(ft)
        total_delta = ft_total - baseline_total
        rows.append({
            "num_ces": num_ces,
            "baseline_avg_auth_s": baseline_avg,
            "ft_avg_auth_s": ft_avg,
            "avg_auth_overhead_s": avg_delta,
            "avg_auth_overhead_pct": pct(avg_delta, baseline_avg),
            "ft_state_propagation_avg_s": get_ft_prop(ft),
            "baseline_total_time_s": baseline_total,
            "ft_total_time_s": ft_total,
            "total_time_overhead_s": total_delta,
            "total_time_overhead_pct": pct(total_delta, baseline_total),
        })
    return rows


def write_csv(rows, output_path):
    fieldnames = [
        "num_ces",
        "baseline_avg_auth_s",
        "ft_avg_auth_s",
        "avg_auth_overhead_s",
        "avg_auth_overhead_pct",
        "ft_state_propagation_avg_s",
        "baseline_total_time_s",
        "ft_total_time_s",
        "total_time_overhead_s",
        "total_time_overhead_pct",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_txt(rows, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 100 + "\n")
        f.write("Q1: SRAS-FT Attestation Overhead Before TEE Certificate Issuance\n")
        f.write("=" * 100 + "\n\n")
        f.write(
            "CEs | Baseline Avg Auth | SRAS-FT Avg Auth | Avg Overhead | Overhead % | "
            "FT Prop Avg | Baseline Total | SRAS-FT Total | Total Overhead | Total Overhead %\n"
        )
        f.write("-" * 142 + "\n")
        for row in rows:
            f.write(
                "%3d | %17s | %16s | %12s | %10s | %11s | %14s | %13s | %14s | %16s\n"
                % (
                    row["num_ces"],
                    fmt(row["baseline_avg_auth_s"]),
                    fmt(row["ft_avg_auth_s"]),
                    fmt(row["avg_auth_overhead_s"]),
                    fmt(row["avg_auth_overhead_pct"]),
                    fmt(row["ft_state_propagation_avg_s"]),
                    fmt(row["baseline_total_time_s"]),
                    fmt(row["ft_total_time_s"]),
                    fmt(row["total_time_overhead_s"]),
                    fmt(row["total_time_overhead_pct"]),
                )
            )
        f.write("\nMetric definitions:\n")
        f.write("- Avg Auth: RPE-side CE auth_duration, from CE auth start to certificate sent.\n")
        f.write("- Avg Overhead: SRAS-FT Avg Auth minus baseline Avg Auth.\n")
        f.write("- FT Prop Avg: measured SRAS-FT state propagation and Echo verification time.\n")
        f.write("- Total Time: first auth_start to last auth_end for the tested CE batch.\n")


def main():
    parser = argparse.ArgumentParser(description="Compare SRAS and SRAS-FT phase3 attestation overhead")
    parser.add_argument("--baseline-dir", required=True, help="Directory containing baseline phase3_test_result_*ces.json")
    parser.add_argument("--ft-dir", required=True, help="Directory containing SRAS-FT phase3_test_result_*ces.json")
    parser.add_argument("--output-dir", default="./performance_data", help="Directory for generated reports")
    args = parser.parse_args()

    baseline_results = load_results(args.baseline_dir)
    ft_results = load_results(args.ft_dir)
    rows = build_rows(baseline_results, ft_results)
    if not rows:
        raise SystemExit("No matching phase3_test_result_*ces.json files found between baseline and FT directories")

    os.makedirs(args.output_dir, exist_ok=True)
    csv_path = os.path.join(args.output_dir, "sras_ft_overhead_report.csv")
    txt_path = os.path.join(args.output_dir, "sras_ft_overhead_report.txt")
    json_path = os.path.join(args.output_dir, "sras_ft_overhead_report.json")

    write_csv(rows, csv_path)
    write_txt(rows, txt_path)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)

    print("Generated:")
    print("  %s" % csv_path)
    print("  %s" % txt_path)
    print("  %s" % json_path)


if __name__ == "__main__":
    main()
