#!/usr/bin/env python3
"""Benchmark runner with CSV and chart generation.

Usage:
    python scripts/run_benchmarks.py [--output-dir results/]

Generates:
    - results/benchmark_results.csv
    - results/throughput_chart.png
    - results/latency_chart.png
    - results/profile_comparison.png
"""

import argparse
import asyncio
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# Try to import matplotlib for charts
try:
    import matplotlib

    matplotlib.use("Agg")  # Non-interactive backend
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not installed. Charts will not be generated.")


# Sample test URLs
SAMPLE_URLS = [
    "https://google.com",
    "https://github.com",
    "https://example.com",
    "https://wikipedia.org",
    "https://stackoverflow.com",
    "https://amazon.com",
    "https://microsoft.com",
    "https://apple.com",
    "https://cloudflare.com",
    "https://mozilla.org",
]


def run_pytest_benchmark(output_dir: Path) -> dict:
    """Run pytest-benchmark and return parsed results."""
    results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "benchmarks": [],
    }

    # Run pytest-benchmark
    json_output = output_dir / "benchmark_raw.json"
    cmd = [
        "python", "-m", "pytest",
        "tests/bench/",
        "--benchmark-only",
        "--benchmark-json", str(json_output),
        "-v",
    ]

    print(f"Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Warning: pytest-benchmark returned non-zero: {e}")
        print(f"stderr: {e.stderr}")
        print("Attempting to continue with results...")

    # Parse JSON output
    if json_output.exists():
        with open(json_output) as f:
            data = json.load(f)

        for bench in data.get("benchmarks", []):
            results["benchmarks"].append({
                "name": bench.get("name", "unknown"),
                "group": bench.get("group", "default"),
                "mean": bench.get("stats", {}).get("mean", 0),
                "median": bench.get("stats", {}).get("median", 0),
                "stddev": bench.get("stats", {}).get("stddev", 0),
                "min": bench.get("stats", {}).get("min", 0),
                "max": bench.get("stats", {}).get("max", 0),
                "ops": bench.get("stats", {}).get("ops", 0),  # ops/second
            })

    return results


def generate_csv(results: dict, output_path: Path) -> None:
    """Generate CSV report from benchmark results."""
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "benchmark_name",
            "group",
            "mean_seconds",
            "median_seconds",
            "stddev_seconds",
            "min_seconds",
            "max_seconds",
            "ops_per_second",
            "timestamp",
            "python_version",
        ])

        for bench in results["benchmarks"]:
            writer.writerow([
                bench["name"],
                bench["group"],
                bench["mean"],
                bench["median"],
                bench["stddev"],
                bench["min"],
                bench["max"],
                bench["ops"],
                results["timestamp"],
                results["python_version"],
            ])

    print(f"CSV report written to: {output_path}")


def generate_charts(results: dict, output_dir: Path) -> None:
    """Generate performance charts."""
    if not HAS_MATPLOTLIB:
        print("Skipping chart generation (matplotlib not available)")
        return

    benchmarks = results["benchmarks"]
    if not benchmarks:
        print("No benchmarks to plot")
        return

    # Prepare data for charts
    throughput_benches = [b for b in benchmarks if b["group"] == "throughput"]
    latency_benches = [b for b in benchmarks if b["group"] == "latency"]
    comparison_benches = [b for b in benchmarks if b["group"] == "comparison"]

    # Chart 1: Throughput (ops/second)
    if throughput_benches:
        fig, ax = plt.subplots(figsize=(10, 6))
        names = [b["name"].replace("test_throughput_", "") for b in throughput_benches]
        ops = [b["ops"] for b in throughput_benches]

        colors = plt.cm.viridis([0.3, 0.5, 0.7])
        bars = ax.bar(names, ops, color=colors)
        ax.set_ylabel("Operations per second")
        ax.set_title("Benchmark: Throughput (Higher is Better)")
        ax.set_ylim(0, max(ops) * 1.2 if ops else 1)

        for bar, val in zip(bars, ops):
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2.,
                height,
                f"{val:.1f}",
                ha="center",
                va="bottom",
            )

        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.savefig(output_dir / "throughput_chart.png", dpi=150)
        plt.close()
        print(f"Throughput chart saved to: {output_dir / 'throughput_chart.png'}")

    # Chart 2: Latency comparison (mean time in ms)
    if latency_benches:
        fig, ax = plt.subplots(figsize=(10, 6))
        names = [b["name"].replace("test_latency_", "") for b in latency_benches]
        times = [b["mean"] * 1000 for b in latency_benches]  # Convert to ms

        colors = plt.cm.plasma([0.3, 0.5, 0.6, 0.7])
        bars = ax.bar(names, times, color=colors)
        ax.set_ylabel("Mean time (milliseconds)")
        ax.set_title("Benchmark: Latency (Lower is Better)")
        ax.set_ylim(0, max(times) * 1.2 if times else 1)

        for bar, val in zip(bars, times):
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2.,
                height,
                f"{val:.2f}ms",
                ha="center",
                va="bottom",
            )

        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.savefig(output_dir / "latency_chart.png", dpi=150)
        plt.close()
        print(f"Latency chart saved to: {output_dir / 'latency_chart.png'}")

    # Chart 3: Profile comparison
    if comparison_benches:
        fig, ax = plt.subplots(figsize=(10, 6))
        names = [b["name"].replace("test_profile_comparison_", "") for b in comparison_benches]
        times = [b["mean"] * 1000 for b in comparison_benches]  # Convert to ms

        colors = ["#4CAF50", "#2196F3", "#FF9800"][:len(names)]
        bars = ax.bar(names, times, color=colors)
        ax.set_ylabel("Mean time (milliseconds)")
        ax.set_title("Profile Comparison: fast vs thorough vs free (Lower is Better)")
        ax.set_ylim(0, max(times) * 1.2 if times else 1)

        for bar, val in zip(bars, times):
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2.,
                height,
                f"{val:.2f}ms",
                ha="center",
                va="bottom",
            )

        plt.tight_layout()
        plt.savefig(output_dir / "profile_comparison.png", dpi=150)
        plt.close()
        print(f"Profile comparison chart saved to: {output_dir / 'profile_comparison.png'}")


def generate_markdown_summary(results: dict, output_path: Path) -> None:
    """Generate markdown summary report."""
    lines = [
        "# Benchmark Results\n",
        f"**Date:** {results['timestamp']}\n",
        f"**Python Version:** {results['python_version']}\n\n",
        "## Summary\n\n",
        "| Benchmark | Group | Mean (ms) | Ops/sec |\n",
        "|-----------|-------|-----------|---------|\n",
    ]

    for bench in results["benchmarks"]:
        mean_ms = bench["mean"] * 1000
        ops = bench["ops"]
        lines.append(
            f"| {bench['name']} | {bench['group']} | {mean_ms:.4f} | {ops:.2f} |\n"
        )

    lines.append("\n## Notes\n\n")
    lines.append("- **Throughput**: Higher ops/sec is better\n")
    lines.append("- **Latency**: Lower mean time is better\n")
    lines.append("- **Profiles**: Fast uses fewer providers, thorough uses more\n")

    with open(output_path, "w") as f:
        f.writelines(lines)

    print(f"Markdown summary written to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Run benchmarks and generate reports")
    parser.add_argument(
        "--output-dir",
        type=str,
        default="results",
        help="Output directory for results (default: results/)",
    )
    parser.add_argument(
        "--skip-charts",
        action="store_true",
        help="Skip chart generation",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("URL Reputation Benchmark Suite")
    print("=" * 60)

    # Run benchmarks
    print("\n[1/3] Running pytest-benchmark...\n")
    results = run_pytest_benchmark(output_dir)

    # Generate CSV
    print("\n[2/3] Generating CSV report...")
    generate_csv(results, output_dir / "benchmark_results.csv")

    # Generate charts
    if not args.skip_charts:
        print("\n[3/3] Generating charts...")
        generate_charts(results, output_dir)
    else:
        print("\n[3/3] Skipping chart generation (--skip-charts)")

    # Generate markdown
    print("\n[Bonus] Generating markdown summary...")
    generate_markdown_summary(results, output_dir / "benchmark_summary.md")

    print("\n" + "=" * 60)
    print("Benchmark complete!")
    print(f"Results saved to: {output_dir.absolute()}")
    print("=" * 60)

    # Print quick summary
    print("\nQuick Summary:")
    for bench in results["benchmarks"][:5]:
        mean_ms = bench["mean"] * 1000
        print(f"  {bench['name']}: {mean_ms:.4f}ms, {bench['ops']:.2f} ops/sec")


if __name__ == "__main__":
    main()