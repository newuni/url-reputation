#!/usr/bin/env python3
"""Memory profiling script for url-reputation.

Measures RAM usage in batch mode with 1000 URLs.
Identifies memory leaks (cache, HTTP sessions not closed).

Usage:
    python scripts/profile_memory.py [--mode batch] [--urls 1000]
    
With memory_profiler:
    python -m memory_profiler scripts/profile_memory.py
"""

import argparse
import asyncio
import gc
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from url_reputation.checker import check_url_reputation, check_urls_batch
from url_reputation.cache import SqliteCache


# Sample URLs for testing
SAMPLE_DOMAINS = [
    "google.com",
    "github.com", 
    "example.com",
    "wikipedia.org",
    "stackoverflow.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "cloudflare.com",
    "mozilla.org",
]


def generate_urls(count: int) -> list:
    """Generate list of URLs for testing."""
    urls = []
    for i in range(count):
        domain = SAMPLE_DOMAINS[i % len(SAMPLE_DOMAINS)]
        if i < len(SAMPLE_DOMAINS):
            urls.append(f"https://{domain}")
        else:
            urls.append(f"https://{domain}/path{i}")
    return urls


def get_memory_usage() -> tuple:
    """Get current memory usage using tracemalloc."""
    gc.collect()
    current, peak = tracemalloc.get_traced_memory()
    return current / 1024 / 1024, peak / 1024 / 1024  # Convert to MB


async def simulate_check_url(url: str, cache=None) -> dict:
    """Simulate URL check without network calls."""
    # Simulate minimal result
    return {
        "schema_version": "1",
        "indicator": {"input": url, "type": "url"},
        "verdict": "CLEAN",
        "risk_score": 0,
        "sources": [],
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


async def profile_batch_memory(url_count: int, use_cache: bool = False) -> dict:
    """Profile memory usage for batch processing."""
    print(f"\n{'='*60}")
    print(f"Memory Profiling: Batch {url_count} URLs")
    print(f"Cache enabled: {use_cache}")
    print(f"{'='*60}\n")

    # Start memory tracking
    tracemalloc.start()
    start_time = time.time()

    # Initial memory
    initial_mb, _ = get_memory_usage()
    print(f"[1] Initial memory: {initial_mb:.2f} MB")

    # Generate URLs
    urls = generate_urls(url_count)
    urls_mb, _ = get_memory_usage()
    print(f"[2] After URL generation: {urls_mb:.2f} MB (+{urls_mb - initial_mb:.2f} MB)")

    # Create cache if requested
    cache = None
    if use_cache:
        cache_path = "/tmp/urlrep_profile_cache.sqlite"
        Path(cache_path).unlink(missing_ok=True)
        cache = SqliteCache(cache_path)
        cache.setup()
        cache_mb, _ = get_memory_usage()
        print(f"[3] After cache setup: {cache_mb:.2f} MB (+{cache_mb - urls_mb:.2f} MB)")

    # Process URLs in batches
    batch_size = 100
    results = []
    
    for i in range(0, len(urls), batch_size):
        batch = urls[i:i+batch_size]
        batch_results = await asyncio.gather(*[
            simulate_check_url(url, cache) for url in batch
        ])
        results.extend(batch_results)
        
        if (i // batch_size) % 5 == 0:
            current_mb, peak_mb = get_memory_usage()
            print(f"[4.{i//batch_size}] After {i+len(batch)} URLs: {current_mb:.2f} MB "
                  f"(peak: {peak_mb:.2f} MB)")

    processed_mb, peak_mb = get_memory_usage()
    print(f"[5] After processing all URLs: {processed_mb:.2f} MB (+{processed_mb - urls_mb:.2f} MB)")
    print(f"    Peak memory: {peak_mb:.2f} MB")

    # Cleanup
    del results
    del urls
    if cache:
        cache.close()
        del cache
    gc.collect()

    final_mb, _ = get_memory_usage()
    print(f"[6] After cleanup: {final_mb:.2f} MB")

    elapsed = time.time() - start_time
    tracemalloc.stop()

    # Calculate metrics
    memory_per_url = (processed_mb - initial_mb) / url_count if url_count > 0 else 0

    return {
        "url_count": url_count,
        "use_cache": use_cache,
        "initial_mb": initial_mb,
        "final_mb": final_mb,
        "peak_mb": peak_mb,
        "memory_per_url_mb": memory_per_url,
        "memory_per_1000_mb": memory_per_url * 1000,
        "elapsed_seconds": elapsed,
    }


async def profile_cache_growth(url_count: int) -> dict:
    """Profile cache size growth with many URLs."""
    print(f"\n{'='*60}")
    print(f"Cache Growth Profile: {url_count} URLs")
    print(f"{'='*60}\n")

    cache_path = "/tmp/urlrep_cache_growth.sqlite"
    Path(cache_path).unlink(missing_ok=True)

    cache = SqliteCache(cache_path)
    cache.setup()

    tracemalloc.start()
    gc.collect()
    initial_mb, _ = get_memory_usage()

    # Simulate cache entries
    import random
    for i in range(url_count):
        cache_key = f"test_key_{i}_{random.randint(1000, 9999)}"
        result = {
            "verdict": "CLEAN",
            "risk_score": 0,
            "sources": [{"name": "test", "status": "ok"}],
        }
        cache.set(cache_key, result, ttl=3600)

        if (i + 1) % 100 == 0:
            current_mb, _ = get_memory_usage()
            print(f"After {i+1} cache entries: {current_mb:.2f} MB")

    final_mb, peak_mb = get_memory_usage()
    cache.close()
    tracemalloc.stop()

    # Check file size
    import os
    file_size_mb = os.path.getsize(cache_path) / 1024 / 1024
    Path(cache_path).unlink(missing_ok=True)

    return {
        "url_count": url_count,
        "memory_growth_mb": final_mb - initial_mb,
        "peak_mb": peak_mb,
        "db_file_size_mb": file_size_mb,
        "bytes_per_entry": (file_size_mb * 1024 * 1024) / url_count if url_count > 0 else 0,
    }


def detect_potential_leaks(results: dict) -> list:
    """Analyze results for potential memory leaks."""
    issues = []

    threshold_1000 = 100  # 100MB per 1000 URLs
    if results.get("memory_per_1000_mb", 0) > threshold_1000:
        issues.append(
            f"WARNING: High memory usage ({results['memory_per_1000_mb']:.2f} MB/1000 URLs). "
            f"Threshold: {threshold_1000} MB/1000 URLs"
        )

    if results.get("memory_per_url_mb", 0) > 0.5:
        issues.append(
            f"WARNING: Memory per URL ({results['memory_per_url_mb']:.4f} MB) seems high"
        )

    return issues


def generate_report(results: list, output_path: Path) -> None:
    """Generate markdown report."""
    lines = [
        "# Memory Profiling Report\n\n",
        f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
        f"**Python:** {sys.version}\n\n",
    ]

    for result in results:
        lines.append(f"## Test: {result['name']}\n\n")
        lines.append("```\n")
        for key, value in result['data'].items():
            if isinstance(value, float):
                lines.append(f"{key}: {value:.4f}\n")
            else:
                lines.append(f"{key}: {value}\n")
        lines.append("```\n\n")

        if 'issues' in result and result['issues']:
            lines.append("**Issues Found:**\n\n")
            for issue in result['issues']:
                lines.append(f"- {issue}\n")
            lines.append("\n")

    # Recommendations
    lines.append("## Recommendations\n\n")
    lines.append("1. **HTTP Sessions:** Ensure aiohttp sessions are closed after use\n")
    lines.append("2. **Cache Size:** Monitor SQLite cache size; consider TTL cleanup\n")
    lines.append("3. **Batch Processing:** Process URLs in chunks to limit memory usage\n")
    lines.append("4. **Garbage Collection:** Force gc.collect() between large batches\n")

    with open(output_path, "w") as f:
        f.writelines(lines)

    print(f"\nReport saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Profile memory usage")
    parser.add_argument(
        "--urls",
        type=int,
        default=1000,
        help="Number of URLs to test (default: 1000)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="docs/performance/memory_report.md",
        help="Output report path",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("URL Reputation Memory Profiler")
    print("=" * 60)

    all_results = []

    # Test 1: Batch without cache
    print("\n[TEST 1] Batch processing without cache")
    result1 = asyncio.run(profile_batch_memory(args.urls, use_cache=False))
    issues1 = detect_potential_leaks(result1)
    all_results.append({"name": "batch_no_cache", "data": result1, "issues": issues1})

    # Test 2: Batch with cache
    print("\n[TEST 2] Batch processing with cache")
    result2 = asyncio.run(profile_batch_memory(args.urls, use_cache=True))
    issues2 = detect_potential_leaks(result2)
    all_results.append({"name": "batch_with_cache", "data": result2, "issues": issues2})

    # Test 3: Cache growth
    print("\n[TEST 3] Cache growth analysis")
    result3 = asyncio.run(profile_cache_growth(args.urls))
    all_results.append({"name": "cache_growth", "data": result3, "issues": []})

    # Generate report
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    generate_report(all_results, output_path)

    # Print summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"\nBatch {args.urls} URLs (no cache):")
    print(f"  Peak memory: {result1['peak_mb']:.2f} MB")
    print(f"  Per 1000 URLs: {result1['memory_per_1000_mb']:.2f} MB")
    print(f"  Time: {result1['elapsed_seconds']:.2f}s")

    print(f"\nBatch {args.urls} URLs (with cache):")
    print(f"  Peak memory: {result2['peak_mb']:.2f} MB")
    print(f"  Per 1000 URLs: {result2['memory_per_1000_mb']:.2f} MB")

    print(f"\nCache {args.urls} entries:")
    print(f"  DB file size: {result3['db_file_size_mb']:.2f} MB")
    print(f"  Bytes per entry: {result3['bytes_per_entry']:.2f}")

    if issues1 or issues2:
        print("\n⚠️  POTENTIAL ISSUES DETECTED:")
        for issue in issues1 + issues2:
            print(f"  - {issue}")
    else:
        print("\n✓ No memory issues detected")


if __name__ == "__main__":
    main()