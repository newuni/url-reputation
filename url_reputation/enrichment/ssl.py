"""SSL/TLS certificate enrichment.

Collects leaf certificate metadata for HTTPS endpoints and emits lightweight
risk indicators (expiry soon, expired, self-signed, hostname mismatch).
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import Any, cast
from urllib.parse import urlparse

from .base import Enricher, EnrichmentContext


class SslCertEnricher(Enricher):
    name = "ssl"

    def enrich(self, indicator: str, ctx: EnrichmentContext) -> dict[str, object]:
        host = indicator
        port = 443

        if ctx.indicator_type == "url":
            parsed = urlparse(indicator)
            if parsed.hostname:
                host = parsed.hostname
            if parsed.port:
                port = parsed.port
        elif ctx.indicator_type == "domain":
            host = indicator
        else:
            # ip is supported as host too
            host = indicator

        out: dict[str, object] = {
            "host": host,
            "port": port,
            "valid": False,
            "issuer": None,
            "subject": None,
            "san": [],
            "not_before": None,
            "not_after": None,
            "days_to_expiry": None,
            "expired": None,
            "self_signed": None,
            "hostname_match": None,
            "risk_indicators": [],
        }

        try:
            context = ssl.create_default_context()
            # We still verify trust chain, but do hostname checks ourselves
            # so we can report mismatch explicitly in enrichment output.
            context.check_hostname = False

            with socket.create_connection((host, port), timeout=max(1, int(ctx.timeout))) as sock, context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = cast(dict[str, Any], ssock.getpeercert() or {})

            subject_parts = cast(list[tuple[tuple[str, str], ...]], cert.get("subject", ()))
            issuer_parts = cast(list[tuple[tuple[str, str], ...]], cert.get("issuer", ()))
            subject = ", ".join(f"{k}={v}" for rdn in subject_parts for (k, v) in rdn)
            issuer = ", ".join(f"{k}={v}" for rdn in issuer_parts for (k, v) in rdn)
            san_pairs = cast(list[tuple[str, str]], cert.get("subjectAltName", []))
            san = [value for (kind, value) in san_pairs if kind == "DNS"]

            not_before_raw = cert.get("notBefore")
            not_after_raw = cert.get("notAfter")
            not_before = (
                datetime.strptime(not_before_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                if isinstance(not_before_raw, str)
                else None
            )
            not_after = (
                datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                if isinstance(not_after_raw, str)
                else None
            )

            days_to_expiry = None
            expired = None
            if not_after is not None:
                delta = not_after - datetime.now(timezone.utc)
                days_to_expiry = int(delta.total_seconds() // 86400)
                expired = days_to_expiry < 0

            hostname_match = False
            host_l = host.lower().strip('.')
            for pattern in san:
                pat = pattern.lower().strip('.')
                if fnmatch(host_l, pat):
                    hostname_match = True
                    break
            if not hostname_match:
                try:
                    # fallback to CN
                    for rdn in subject_parts:
                        for key, value in rdn:
                            if key == "commonName" and fnmatch(host_l, str(value).lower().strip('.')):
                                hostname_match = True
                                break
                except Exception:
                    pass

            self_signed = bool(subject and issuer and subject == issuer)

            risk_indicators: list[str] = []
            if expired:
                risk_indicators.append("SSL certificate expired")
            if days_to_expiry is not None and 0 <= days_to_expiry <= 14:
                risk_indicators.append("SSL certificate expires within 14 days")
            if self_signed:
                risk_indicators.append("Self-signed certificate")
            if not hostname_match:
                risk_indicators.append("Certificate hostname mismatch")

            out.update(
                {
                    "valid": True,
                    "issuer": issuer,
                    "subject": subject,
                    "san": san,
                    "not_before": not_before.isoformat() if not_before else None,
                    "not_after": not_after.isoformat() if not_after else None,
                    "days_to_expiry": days_to_expiry,
                    "expired": expired,
                    "self_signed": self_signed,
                    "hostname_match": hostname_match,
                    "risk_indicators": risk_indicators,
                }
            )
            return out
        except Exception as e:
            out["error"] = str(e)
            return out


class TlsEnricher(SslCertEnricher):
    name = "tls"
