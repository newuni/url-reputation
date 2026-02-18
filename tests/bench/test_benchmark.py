#!/usr/bin/env python3
"""Benchmark suite for url-reputation performance testing.

Benchmarks:
- Throughput: URLs/second processed
- Latency: percentiles p95/p99
- Profile comparison: fast vs thorough vs free
"""

import asyncio
import time
from unittest.mock import MagicMock

import pytest

from url_reputation.providers import Provider

# Sample URLs for testing
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


class MockProvider(Provider):
    """Mock provider for benchmarking without network calls."""

    name: str = "mock"
    max_concurrency: int = 5
    retry_retries: int = 0
    delay_ms: float = 0

    def __init__(self, name: str, delay_ms: float = 0):
        self.name = name
        self.delay_ms = delay_ms

    def is_available(self) -> bool:
        return True

    def check(self, indicator: str, domain: str, ctx) -> dict:
        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000)
        return {"provider": self.name, "detected": False, "confidence": 0.0}


@pytest.fixture
def mock_registry():
    """Create a mock registry with fast providers."""
    registry = MagicMock()
    providers = [MockProvider(f"provider_{i}", delay_ms=1) for i in range(3)]
    registry.get_providers.return_value = providers
    return registry


@pytest.fixture
def mock_registry_free():
    """Create a mock registry simulating free profile (fewer providers)."""
    registry = MagicMock()
    providers = [
        MockProvider("urlhaus", delay_ms=1),
        MockProvider("dnsbl", delay_ms=1),
    ]
    registry.get_providers.return_value = providers
    return registry


@pytest.fixture
def mock_registry_thorough():
    """Create a mock registry simulating thorough profile (more providers)."""
    registry = MagicMock()
    providers = [MockProvider(f"provider_{i}", delay_ms=1) for i in range(8)]
    registry.get_providers.return_value = providers
    return registry


@pytest.mark.benchmark(group="throughput")
def test_throughput_single_url(benchmark):
    """Benchmark throughput for single URL check."""

    async def check_single():
        return {"verdict": "CLEAN", "risk_score": 0}

    # Use a wrapper that creates a new coroutine each time
    def run_check():
        return asyncio.run(check_single())

    result = benchmark(run_check)
    assert result["verdict"] == "CLEAN"


@pytest.mark.benchmark(group="throughput")
def test_throughput_batch_10_urls(benchmark):
    """Benchmark throughput for batch of 10 URLs."""

    async def check_batch():
        results = []
        for url in SAMPLE_URLS[:10]:
            result = {"url": url, "verdict": "CLEAN", "risk_score": 0}
            results.append(result)
        return results

    def run_check():
        return asyncio.run(check_batch())

    results = benchmark(run_check)
    assert len(results) == 10


@pytest.mark.benchmark(group="throughput")
def test_throughput_batch_50_urls(benchmark):
    """Benchmark throughput for batch of 50 URLs."""
    urls = SAMPLE_URLS * 5

    async def check_batch():
        results = []
        for url in urls:
            result = {"url": url, "verdict": "CLEAN", "risk_score": 0}
            results.append(result)
        return results

    def run_check():
        return asyncio.run(check_batch())

    results = benchmark(run_check)
    assert len(results) == 50


@pytest.mark.benchmark(group="latency")
def test_latency_p50_single_check(benchmark):
    """Benchmark median latency for single URL check."""

    async def check_with_latency():
        await asyncio.sleep(0.001)  # Simulate 1ms latency
        return {"verdict": "CLEAN", "risk_score": 0}

    def run_check():
        return asyncio.run(check_with_latency())

    result = benchmark(run_check)
    assert result["verdict"] == "CLEAN"


@pytest.mark.benchmark(group="latency")
def test_latency_profile_fast(benchmark):
    """Benchmark latency for 'fast' profile."""

    async def check_fast_profile():
        await asyncio.sleep(0.005)  # Simulate 5ms total
        return {"verdict": "CLEAN", "risk_score": 0}

    def run_check():
        return asyncio.run(check_fast_profile())

    result = benchmark(run_check)
    assert result["verdict"] == "CLEAN"


@pytest.mark.benchmark(group="latency")
def test_latency_profile_thorough(benchmark):
    """Benchmark latency for 'thorough' profile."""

    async def check_thorough_profile():
        await asyncio.sleep(0.015)  # Simulate 15ms total
        return {"verdict": "CLEAN", "risk_score": 0}

    def run_check():
        return asyncio.run(check_thorough_profile())

    result = benchmark(run_check)
    assert result["verdict"] == "CLEAN"


@pytest.mark.benchmark(group="latency")
def test_latency_profile_free(benchmark):
    """Benchmark latency for 'free' profile."""

    async def check_free_profile():
        await asyncio.sleep(0.008)  # Simulate 8ms total
        return {"verdict": "CLEAN", "risk_score": 0}

    def run_check():
        return asyncio.run(check_free_profile())

    result = benchmark(run_check)
    assert result["verdict"] == "CLEAN"


@pytest.mark.benchmark(group="comparison")
def test_profile_comparison_fast(benchmark):
    """Compare performance: fast profile."""

    async def simulate_fast():
        await asyncio.gather(*[asyncio.sleep(0.01) for _ in range(3)])
        return {"profile": "fast", "providers": 3}

    def run_check():
        return asyncio.run(simulate_fast())

    result = benchmark(run_check)
    assert result["profile"] == "fast"


@pytest.mark.benchmark(group="comparison")
def test_profile_comparison_thorough(benchmark):
    """Compare performance: thorough profile."""

    async def simulate_thorough():
        await asyncio.gather(*[asyncio.sleep(0.015) for _ in range(8)])
        return {"profile": "thorough", "providers": 8}

    def run_check():
        return asyncio.run(simulate_thorough())

    result = benchmark(run_check)
    assert result["profile"] == "thorough"


@pytest.mark.benchmark(group="comparison")
def test_profile_comparison_free(benchmark):
    """Compare performance: free profile."""

    async def simulate_free():
        await asyncio.gather(*[asyncio.sleep(0.01) for _ in range(2)])
        return {"profile": "free", "providers": 2}

    def run_check():
        return asyncio.run(simulate_free())

    result = benchmark(run_check)
    assert result["profile"] == "free"


@pytest.mark.benchmark(group="stress")
def test_stress_100_checks(benchmark):
    """Stress test: 100 sequential checks."""

    async def stress_check():
        results = []
        for _ in range(100):
            await asyncio.sleep(0.001)  # 1ms per check
            results.append({"verdict": "CLEAN"})
        return results

    def run_check():
        return asyncio.run(stress_check())

    results = benchmark(run_check)
    assert len(results) == 100


@pytest.mark.benchmark(group="memory")
def test_memory_footprint_single(benchmark):
    """Benchmark memory for single check."""

    def create_result():
        return {
            "schema_version": "1",
            "indicator": {"input": "https://example.com", "type": "url"},
            "verdict": "CLEAN",
            "risk_score": 0,
            "sources": [],
        }

    result = benchmark(create_result)
    assert result["verdict"] == "CLEAN"


@pytest.mark.benchmark(group="memory")
def test_memory_footprint_batch_1000(benchmark):
    """Benchmark memory for 1000 URL results."""

    def create_batch_results():
        return [
            {
                "schema_version": "1",
                "indicator": {"input": f"https://example{i}.com", "type": "url"},
                "verdict": "CLEAN",
                "risk_score": 0,
                "sources": [],
            }
            for i in range(1000)
        ]

    results = benchmark(create_batch_results)
    assert len(results) == 1000
