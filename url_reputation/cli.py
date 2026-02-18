#!/usr/bin/env python3
"""
URL Reputation Checker - CLI entry point
"""

from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from typing import Any, cast

from .checker import check_url_reputation
from .enrichment.service import enrich_indicator  # kept for test/backwards-compat patching
from .markdown import to_markdown_batch, to_markdown_single
from .models import IndicatorType
from .output import (
    exit_code_from_results,
    exit_code_from_verdict,
    to_sarif,
    worst_verdict,
)
from .scoring import aggregate_risk_score
from .webhook import notify_on_risk


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check URL/domain reputation across multiple security sources"
    )
    parser.add_argument("url", nargs="?", help="URL or domain to check (optional if using --file)")
    parser.add_argument("--file", "-f", help="File with URLs to check (one per line)", default=None)
    parser.add_argument(
        "--sources",
        "-s",
        help="Comma-separated list of sources (default: all available)",
        default=None,
    )
    parser.add_argument(
        "--profile",
        help="Provider profile preset: free, fast, privacy, thorough (ignored if --sources is set)",
        choices=["free", "fast", "privacy", "thorough"],
        default=None,
    )
    parser.add_argument(
        "--json", "-j", action="store_true", help="Output as JSON (alias for --format json)"
    )
    parser.add_argument(
        "--format",
        choices=["pretty", "json", "ndjson", "sarif", "markdown"],
        default=None,
        help="Output format (default: pretty; --json is an alias for json)",
    )
    parser.add_argument(
        "--legacy-json",
        action="store_true",
        help="Include legacy fields in JSON output (e.g. sources_map)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["CLEAN", "LOW_RISK", "MEDIUM_RISK", "HIGH_RISK", "ERROR"],
        default=None,
        help="Exit non-zero when verdict is at or above this level (useful for CI)",
    )
    parser.add_argument(
        "--timeout", "-t", type=int, default=30, help="Timeout per source in seconds (default: 30)"
    )
    parser.add_argument(
        "--cache",
        nargs="?",
        const="default",
        default=None,
        help="Enable sqlite cache (optionally provide path). If set without value, uses default path.",
    )
    parser.add_argument(
        "--cache-ttl", default="24h", help="Cache TTL (e.g. 3600, 10m, 24h, 7d). Default: 24h"
    )
    parser.add_argument(
        "--no-cache", action="store_true", help="Disable cache even if --cache is set"
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=5,
        help="Max parallel workers for batch processing (default: 5)",
    )
    parser.add_argument(
        "--max-requests",
        type=int,
        default=None,
        help="Batch mode only: stop after processing at most N URLs (default: no limit)",
    )
    parser.add_argument(
        "--budget-seconds",
        type=float,
        default=None,
        help="Batch mode only: stop submitting new URLs after this many seconds (default: no limit)",
    )
    parser.add_argument(
        "--preserve-order",
        action="store_true",
        help="Batch mode only: yield results in input order (buffered). Default streams as results complete.",
    )
    parser.add_argument(
        "--webhook", help="Webhook URL for notifications (or set WEBHOOK_URL env var)", default=None
    )
    parser.add_argument(
        "--webhook-secret", help="Webhook HMAC secret (or set WEBHOOK_SECRET env var)", default=None
    )
    parser.add_argument(
        "--notify-on",
        help="Risk level to notify on: all, high, medium (default: medium)",
        choices=["all", "high", "medium"],
        default="medium",
    )
    parser.add_argument(
        "--enrich", help="Enrichment data to include: dns,whois (comma-separated)", default=None
    )

    args = parser.parse_args()

    out_format = args.format
    if out_format is None:
        out_format = "json" if args.json else "pretty"

    # Validate arguments
    if not args.url and not args.file:
        parser.error("Either URL or --file is required")

    from .profiles import get_profile

    sources = args.sources.split(",") if args.sources else None
    if sources is None and args.profile:
        sources = get_profile(args.profile).providers

    exit_code = 0

    # Batch mode: process file
    if args.file:
        results_iter = iter_urls_from_file(args.file)
        results = run_batch(
            results_iter,
            sources=sources,
            timeout=args.timeout,
            max_workers=args.workers,
            cache=args.cache,
            cache_ttl=args.cache_ttl,
            no_cache=args.no_cache,
            max_requests=args.max_requests,
            budget_seconds=args.budget_seconds,
            preserve_order=args.preserve_order,
        )

        if out_format == "json":
            payload = list(results)
            print(json.dumps(payload, indent=2))
            exit_code = exit_code_from_results(payload, fail_on=args.fail_on)
        elif out_format == "markdown":
            payload = list(results)
            print(to_markdown_batch(payload))
            exit_code = exit_code_from_results(payload, fail_on=args.fail_on)
        elif out_format == "ndjson":
            worst = "CLEAN"
            for r in results:
                if args.legacy_json:
                    r["sources_map"] = {s.get("name"): s.get("raw") for s in r.get("sources", [])}
                print(json.dumps(r, ensure_ascii=False))
                worst = worst_verdict(worst, r.get("verdict", "ERROR"))
            exit_code = exit_code_from_verdict(worst, fail_on=args.fail_on)
        elif out_format == "sarif":
            payload = list(results)
            print(json.dumps(to_sarif(payload), indent=2))
            exit_code = exit_code_from_results(payload, fail_on=args.fail_on)
        else:
            payload = list(results)
            print_batch_results(payload)
            exit_code = exit_code_from_results(payload, fail_on=args.fail_on)

    else:
        # Single URL mode
        cache_path = None
        cache_ttl_seconds = None
        if args.cache and not args.no_cache:
            from .cache import default_cache_path, parse_ttl

            cache_path = default_cache_path() if args.cache == "default" else args.cache
            cache_ttl_seconds = parse_ttl(args.cache_ttl)

        result = check_url_reputation(
            args.url,
            sources,
            args.timeout,
            cache_path=cache_path,
            cache_ttl_seconds=cache_ttl_seconds,
        )

        # Add enrichment if requested (kept for backwards-compat and CLI tests).
        if args.enrich:
            enrich_types = [t.strip() for t in args.enrich.split(",")]
            ind = result.get("indicator") or {}
            indicator_type_raw = ind.get("type") or "domain"
            indicator_type = cast(IndicatorType, str(indicator_type_raw))
            indicator_canonical = ind.get("canonical") or result.get("domain")

            # Use canonical indicator so enrichers see normalized input.
            result["enrichment"] = enrich_indicator(
                str(indicator_canonical),
                indicator_type=indicator_type,
                types=enrich_types,
                timeout=args.timeout,
            )

            # Recompute aggregated score so enrichment-based rules can contribute (T19).
            sources_map: dict[str, dict[str, Any]] = {
                str(s["name"]): cast(dict[str, Any], (s.get("raw") or {}))
                for s in result.get("sources", [])
                if isinstance(s, dict) and s.get("name")
            }
            agg = aggregate_risk_score(sources_map, enrichment=result.get("enrichment"))
            result["risk_score"] = agg.risk_score
            result["verdict"] = agg.verdict
            result["score_breakdown"] = agg.score_breakdown
            result["reasons"] = agg.reasons

        if out_format == "json":
            if args.legacy_json:
                # Provide a legacy map of provider results for older consumers.
                result["sources_map"] = {
                    s.get("name"): s.get("raw") for s in result.get("sources", [])
                }
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif out_format == "markdown":
            print(to_markdown_single(result))
        elif out_format == "sarif":
            print(json.dumps(to_sarif([result]), indent=2))
        else:
            print_human_readable(result)
            if args.enrich:
                print_enrichment(result.get("enrichment", {}))

        # Send webhook notification if configured
        _maybe_send_webhook(result, args)
        exit_code = exit_code_from_verdict(result.get("verdict", "ERROR"), fail_on=args.fail_on)

    raise SystemExit(exit_code)


def iter_urls_from_file(filepath: str) -> Iterator[str]:
    """Yield URLs from a file (streaming).

    Skips empty lines and comments.
    """
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                yield line


def check_urls_from_file(
    filepath: str,
    sources: list[str] | None = None,
    timeout: int = 30,
    max_workers: int = 5,
) -> list[dict[str, Any]]:
    """Backward-compatible wrapper: returns a list.

    Note: for large files prefer streaming via `iter_urls_from_file()` + `run_batch()`.
    """

    urls_iter = iter_urls_from_file(filepath)
    return list(
        run_batch(
            urls_iter,
            sources=sources,
            timeout=timeout,
            max_workers=max_workers,
            cache=None,
            cache_ttl="24h",
            no_cache=True,
            # This wrapper returns a list; preserve input order for stable callers.
            preserve_order=True,
            max_requests=None,
            budget_seconds=None,
        )
    )


def run_batch(
    urls_iter: Iterable[str],
    *,
    sources: list[str] | None,
    timeout: int,
    max_workers: int,
    cache: str | None,
    cache_ttl: str,
    no_cache: bool,
    max_requests: int | None = None,
    budget_seconds: float | None = None,
    preserve_order: bool = False,
) -> Iterator[dict[str, Any]]:
    """Run batch checks with bounded in-flight tasks.

    This avoids loading huge files into memory.

    Notes:
    - By default, results are yielded as they are completed (not necessarily original order).
    - With preserve_order=True, results are yielded in input order (buffered).
    - budget_seconds limits submission of new work; it does not hard-stop in-flight tasks.
    """

    from .cache import default_cache_path, parse_ttl

    cache_path = None
    cache_ttl_seconds = None
    if cache and not no_cache:
        cache_path = default_cache_path() if cache == "default" else cache
        cache_ttl_seconds = parse_ttl(cache_ttl)

    max_in_flight = max_workers * 3

    def submit(executor: ThreadPoolExecutor, url: str) -> Future[dict[str, Any]]:
        return executor.submit(
            check_url_reputation,
            url,
            sources,
            timeout,
            cache_path=cache_path,
            cache_ttl_seconds=cache_ttl_seconds,
        )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        start = time.monotonic()

        def budget_exhausted() -> bool:
            if budget_seconds is None:
                return False
            return (time.monotonic() - start) >= float(budget_seconds)

        # Track futures -> (index, url) so we can optionally reorder on output.
        pending: set[Future[dict[str, Any]]] = set()
        meta: dict[Future[dict[str, Any]], tuple[int, str]] = {}

        next_index = 0  # next input index to yield (preserve_order)
        buffer: dict[int, dict[str, Any]] = {}

        # Submission + streaming loop with bounded in-flight futures.
        for submitted, url in enumerate(urls_iter):
            if max_requests is not None and submitted >= int(max_requests):
                break
            if budget_exhausted():
                break

            fut = submit(executor, url)
            idx = submitted

            pending.add(fut)
            meta[fut] = (idx, url)

            if len(pending) >= max_in_flight:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for d in done:
                    i, u = meta.pop(d)
                    if preserve_order:
                        try:
                            buffer[i] = d.result()
                        except Exception as e:
                            buffer[i] = {"url": u, "error": str(e), "verdict": "ERROR"}
                    else:
                        try:
                            yield d.result()
                        except Exception as e:
                            yield {"url": u, "error": str(e), "verdict": "ERROR"}

                if preserve_order:
                    while next_index in buffer:
                        yield buffer.pop(next_index)
                        next_index += 1

        # Drain remaining futures.
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for d in done:
                i, u = meta.pop(d)
                if preserve_order:
                    try:
                        buffer[i] = d.result()
                    except Exception as e:
                        buffer[i] = {"url": u, "error": str(e), "verdict": "ERROR"}
                else:
                    try:
                        yield d.result()
                    except Exception as e:
                        yield {"url": u, "error": str(e), "verdict": "ERROR"}

            if preserve_order:
                while next_index in buffer:
                    yield buffer.pop(next_index)
                    next_index += 1


def _maybe_send_webhook(result: dict[str, Any], args: argparse.Namespace) -> None:
    """Send webhook notification if configured and criteria met."""
    webhook_url = args.webhook or os.getenv("WEBHOOK_URL")
    if not webhook_url:
        return

    # Determine notification criteria
    notify_levels = {
        "all": (["CLEAN", "LOW_RISK", "MEDIUM_RISK", "HIGH_RISK"], 0),
        "medium": (["MEDIUM_RISK", "HIGH_RISK"], 50),
        "high": (["HIGH_RISK"], 76),
    }
    verdicts, min_score = notify_levels.get(args.notify_on, notify_levels["medium"])

    response = notify_on_risk(
        result,
        webhook_url=webhook_url,
        webhook_secret=args.webhook_secret,
        min_risk_score=min_score,
        verdicts=verdicts,
    )

    if response:
        if response.get("success"):
            print(f"\n📤 Webhook sent: {response.get('status_code')}")
        else:
            print(f"\n⚠️ Webhook failed: {response.get('error')}")


def print_enrichment(enrichment: dict[str, Any]) -> None:
    """Print enrichment data in human-readable format."""
    if not enrichment:
        return

    print("\n📋 Enrichment Data:")
    print(f"{'-' * 50}")

    # DNS
    if "dns" in enrichment:
        dns = enrichment["dns"]
        print("\n🌐 DNS Records:")
        if dns.get("a_records"):
            print(f"  A:     {', '.join(dns['a_records'])}")
        if dns.get("aaaa_records"):
            print(f"  AAAA:  {', '.join(dns['aaaa_records'][:2])}...")
        if dns.get("mx_records"):
            mx = dns["mx_records"]
            if isinstance(mx[0], dict):
                print(f"  MX:    {mx[0].get('host', mx[0])}")
            else:
                print(f"  MX:    {mx[0]}")
        if dns.get("ns_records"):
            print(f"  NS:    {', '.join(dns['ns_records'][:2])}")

        # Security
        spf = "✅" if dns.get("has_spf") else "❌"
        dmarc = "✅" if dns.get("has_dmarc") else "❌"
        print(f"  SPF:   {spf}  DMARC: {dmarc}")

    # Whois
    if "whois" in enrichment:
        whois = enrichment["whois"]
        print("\n📝 Whois:")
        if whois.get("creation_date"):
            age = whois.get("domain_age_days", "?")
            new_badge = " ⚠️ NEW!" if whois.get("is_new_domain") else ""
            print(f"  Created:   {whois['creation_date'][:10]} ({age} days){new_badge}")
        if whois.get("registrar"):
            print(f"  Registrar: {whois['registrar'][:40]}")
        if whois.get("registrant_country"):
            print(f"  Country:   {whois['registrant_country']}")
        if whois.get("error"):
            print(f"  ⚠️ {whois['error']}")

    # Risk indicators
    if "risk_indicators" in enrichment:
        print("\n⚠️ Risk Indicators:")
        for indicator in enrichment["risk_indicators"]:
            print(f"  • {indicator}")


def print_batch_results(results: list[dict[str, Any]]) -> None:
    """Print batch results in human-readable format."""
    print("\n🔍 URL Reputation Batch Report")
    print(f"{'=' * 60}")
    print(f"Total URLs: {len(results)}")

    # Summary counts
    verdicts: dict[str, int] = {}
    for r in results:
        v = r.get("verdict", "ERROR")
        verdicts[v] = verdicts.get(v, 0) + 1

    print("\n📊 Summary:")
    verdict_emoji = {
        "CLEAN": "✅",
        "LOW_RISK": "⚠️",
        "MEDIUM_RISK": "🟠",
        "HIGH_RISK": "🔴",
        "ERROR": "❌",
    }
    for verdict, count in sorted(verdicts.items()):
        emoji = verdict_emoji.get(verdict, "❓")
        print(f"  {emoji} {verdict}: {count}")

    print(f"\n{'=' * 60}")
    print("📋 Results:")
    print(f"{'-' * 60}")

    for result in results:
        url = result.get("url", "unknown")
        verdict = result.get("verdict", "ERROR")
        score = result.get("risk_score", "-")
        emoji = verdict_emoji.get(verdict, "❓")

        if verdict == "ERROR":
            print(f"  {emoji} {url}")
            print(f"      Error: {result.get('error', 'Unknown error')}")
        else:
            print(f"  {emoji} [{score:>3}/100] {verdict:<12} {url}")

    print()


def print_human_readable(result: dict[str, Any]) -> None:
    """Print human-readable output."""
    print("\n🔍 URL Reputation Report")
    print(f"{'=' * 50}")
    print(f"URL:    {result['url']}")
    print(f"Domain: {result['domain']}")
    print(f"{'=' * 50}")

    verdict_emoji = {"CLEAN": "✅", "LOW_RISK": "⚠️", "MEDIUM_RISK": "🟠", "HIGH_RISK": "🔴"}

    print(f"\n{verdict_emoji.get(result['verdict'], '❓')} Verdict: {result['verdict']}")
    print(f"📊 Risk Score: {result['risk_score']}/100")

    print("\n📋 Source Results:")
    print(f"{'-' * 50}")

    # Schema v1: sources is a list of source results
    for src in result.get("sources", []):
        source = src.get("name", "unknown")
        status = src.get("status")
        data = src.get("raw", {})
        err = src.get("error")

        if status == "error" or err:
            print(f"  {source}: ❌ Error - {err or 'Unknown error'}")
        elif source == "virustotal":
            detected = data.get("detected", 0)
            total = data.get("total", 0)
            icon = "🔴" if detected > 0 else "✅"
            print(f"  {source}: {icon} {detected}/{total} engines detected")
        elif data.get("listed"):
            threat = data.get("threat_type", data.get("match_type", "unknown"))
            print(f"  {source}: 🔴 Listed ({threat})")
        elif data.get("malicious"):
            print(f"  {source}: 🔴 Malicious")
        elif data.get("threats"):
            print(f"  {source}: 🔴 Threats found")
        elif data.get("abuse_score", 0) > 50:
            print(f"  {source}: 🟠 Abuse score: {data['abuse_score']}")
        else:
            print(f"  {source}: ✅ Clean")

    print(f"\n⏱️  Checked at: {result['checked_at']}")


if __name__ == "__main__":
    main()
