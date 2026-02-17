"""Built-in providers wrapping existing source modules."""

from __future__ import annotations

import os
from typing import Any

from .base import Provider, ProviderContext
from ..sources import (
    urlhaus,
    phishtank,
    dnsbl,
    virustotal,
    urlscan,
    safebrowsing,
    abuseipdb,
    alienvault_otx,
    ipqualityscore,
    threatfox,
)


class _FnProvider(Provider):
    def __init__(self, name: str, fn, available_fn=None):
        self.name = name
        self._fn = fn
        self._available_fn = available_fn

    def is_available(self) -> bool:
        if self._available_fn:
            return bool(self._available_fn())
        return True

    def check(self, indicator: str, domain: str, ctx: ProviderContext) -> dict[str, Any]:
        return self._fn(indicator, domain, ctx.timeout)


def builtin_providers() -> dict[str, Provider]:
    return {
        # Free sources
        'urlhaus': _FnProvider('urlhaus', urlhaus.check),
        'phishtank': _FnProvider('phishtank', phishtank.check),
        'dnsbl': _FnProvider('dnsbl', dnsbl.check),
        'alienvault_otx': _FnProvider('alienvault_otx', alienvault_otx.check),

        # API key required
        'virustotal': _FnProvider('virustotal', virustotal.check, lambda: os.getenv('VIRUSTOTAL_API_KEY')),
        'urlscan': _FnProvider('urlscan', urlscan.check, lambda: os.getenv('URLSCAN_API_KEY')),
        'safebrowsing': _FnProvider('safebrowsing', safebrowsing.check, lambda: os.getenv('GOOGLE_SAFEBROWSING_API_KEY')),
        'abuseipdb': _FnProvider('abuseipdb', abuseipdb.check, lambda: os.getenv('ABUSEIPDB_API_KEY')),
        'ipqualityscore': _FnProvider('ipqualityscore', ipqualityscore.check, lambda: os.getenv('IPQUALITYSCORE_API_KEY')),
        'threatfox': _FnProvider('threatfox', threatfox.check, lambda: os.getenv('THREATFOX_API_KEY')),
    }
