"""Built-in providers wrapping existing source modules."""

from __future__ import annotations

import os
from typing import Any

from ..sources import (
    abuseipdb,
    alienvault_otx,
    dnsbl,
    ipqualityscore,
    phishtank,
    safebrowsing,
    threatfox,
    urlhaus,
    urlscan,
    virustotal,
)
from .base import Provider, ProviderContext


class _FnProvider(Provider):
    def __init__(self, name: str, fn, available_fn=None, *, max_concurrency: int = 5, retry_retries: int = 2):
        self.name = name
        self._fn = fn
        self._available_fn = available_fn
        self.max_concurrency = max_concurrency
        self.retry_retries = retry_retries

    def is_available(self) -> bool:
        if self._available_fn:
            return bool(self._available_fn())
        return True

    def check(self, indicator: str, domain: str, ctx: ProviderContext) -> dict[str, Any]:
        return self._fn(indicator, domain, ctx.timeout)


def builtin_providers() -> dict[str, Provider]:
    return {
        # Free sources
        'urlhaus': _FnProvider('urlhaus', urlhaus.check, max_concurrency=10),
        'phishtank': _FnProvider('phishtank', phishtank.check, max_concurrency=10),
        'dnsbl': _FnProvider('dnsbl', dnsbl.check, max_concurrency=10),
        'alienvault_otx': _FnProvider('alienvault_otx', alienvault_otx.check, max_concurrency=5),

        # API key required
        'virustotal': _FnProvider(
            'virustotal',
            virustotal.check,
            lambda: os.getenv('VIRUSTOTAL_API_KEY'),
            max_concurrency=2,
            retry_retries=2,
        ),
        'urlscan': _FnProvider(
            'urlscan',
            urlscan.check,
            lambda: os.getenv('URLSCAN_API_KEY'),
            max_concurrency=1,
            retry_retries=1,
        ),
        'safebrowsing': _FnProvider(
            'safebrowsing',
            safebrowsing.check,
            lambda: os.getenv('GOOGLE_SAFEBROWSING_API_KEY'),
            max_concurrency=2,
            retry_retries=2,
        ),
        'abuseipdb': _FnProvider(
            'abuseipdb',
            abuseipdb.check,
            lambda: os.getenv('ABUSEIPDB_API_KEY'),
            max_concurrency=2,
            retry_retries=2,
        ),
        'ipqualityscore': _FnProvider(
            'ipqualityscore',
            ipqualityscore.check,
            lambda: os.getenv('IPQUALITYSCORE_API_KEY'),
            max_concurrency=2,
            retry_retries=2,
        ),
        'threatfox': _FnProvider(
            'threatfox',
            threatfox.check,
            lambda: os.getenv('THREATFOX_API_KEY'),
            max_concurrency=2,
            retry_retries=2,
        ),
    }
