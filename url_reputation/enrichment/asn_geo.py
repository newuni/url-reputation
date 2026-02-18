"""ASN + Geo enrichment (T16).

Online-first, no API keys:
- RIPEstat (HTTPS JSON) for ASN/prefix/holder
- Team Cymru (whois over TCP/43) for ASN/prefix/name
- ip-api.com (HTTPS JSON) for basic geo fields (rate-limit friendly via caching)

Offline/local fallback:
- Return resolved IPs (domain -> A/AAAA) or the input IP, and emit a quality report.

This module intentionally avoids new hard dependencies.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import time
from dataclasses import dataclass
from typing import Any, Optional, cast
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .base import Enricher, EnrichmentContext


def _is_offline() -> bool:
    # Opt-in offline mode (useful for deterministic runs).
    return os.getenv("URL_REPUTATION_OFFLINE", "").strip().lower() in {"1", "true", "yes", "on"}


def _now() -> float:
    # Isolated for testability.
    return time.time()


@dataclass
class _TTLCache:
    """Tiny TTL cache to reduce rate limiting in a single process."""

    ttl_seconds: int
    max_items: int = 1024

    def __post_init__(self) -> None:
        self._d: dict[str, tuple[float, dict[str, Any]]] = {}

    def get(self, key: str) -> Optional[dict[str, Any]]:
        v = self._d.get(key)
        if not v:
            return None
        expires_at, payload = v
        if expires_at <= _now():
            self._d.pop(key, None)
            return None
        return payload

    def set(self, key: str, value: dict[str, Any]) -> None:
        if len(self._d) >= self.max_items:
            # Simple eviction: drop an arbitrary (oldest not tracked) entry.
            try:
                self._d.pop(next(iter(self._d)))
            except Exception:
                self._d.clear()
        self._d[key] = (_now() + max(0, int(self.ttl_seconds)), value)


_DEFAULT_TTL = int(os.getenv("URL_REPUTATION_ASN_GEO_TTL_SECONDS", "21600"))  # 6h
_RIPE_CACHE = _TTLCache(ttl_seconds=_DEFAULT_TTL, max_items=2048)
_CYMRU_CACHE = _TTLCache(ttl_seconds=_DEFAULT_TTL, max_items=2048)
_IPAPI_CACHE = _TTLCache(ttl_seconds=_DEFAULT_TTL, max_items=2048)


def _safe_int(x: Any) -> Optional[int]:
    try:
        if x is None:
            return None
        if isinstance(x, int):
            return x
        s = str(x).strip()
        if s.upper().startswith("AS"):
            s = s[2:]
        return int(s)
    except Exception:
        return None


def _http_get_json(url: str, *, timeout: int, user_agent: str) -> dict[str, Any]:
    req = Request(url, headers={"User-Agent": user_agent, "Accept": "application/json"})
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        # Ensure JSON-safe return even for unexpected upstream output.
        return {"_error": "invalid_json", "_raw": raw[:200].decode("utf-8", errors="replace")}


def _resolve_domain_ips(domain: str, *, timeout: int) -> list[str]:
    """Resolve domain A/AAAA to IPs, preferring existing DNS utilities when available."""
    ips: set[str] = set()

    # Reuse legacy DNS enricher if present (it already supports dnspython or socket fallback).
    try:
        from ..enrich import enrich_dns

        out = enrich_dns(domain, timeout=timeout) or {}
        for k in ("a_records", "aaaa_records"):
            for ip in out.get(k) or []:
                try:
                    ipaddress.ip_address(str(ip))
                    ips.add(str(ip))
                except Exception:
                    continue
    except Exception:
        pass

    if ips:
        return sorted(ips)

    # Fallback: system resolver via socket.getaddrinfo.
    try:
        socket.setdefaulttimeout(timeout)
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                for info in socket.getaddrinfo(domain, None, family):
                    ip = info[4][0]
                    try:
                        ip_s = str(ip)
                        ipaddress.ip_address(ip_s)
                        ips.add(ip_s)
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass

    return sorted(ips)


def _sort_ips(ips: list[str]) -> list[str]:
    """Return a stable, de-duplicated, JSON-safe IP list."""
    out: list[tuple[int, str]] = []
    seen: set[str] = set()
    for s in ips:
        if s in seen:
            continue
        seen.add(s)
        try:
            ip = ipaddress.ip_address(s)
            out.append((ip.version, str(ip)))
        except Exception:
            continue

    # Within each IP version, sort by packed bytes for deterministic ordering.
    def _key(t: tuple[int, str]):
        v, s = t
        try:
            return (v, ipaddress.ip_address(s).packed)
        except Exception:
            return (v, s.encode("utf-8", errors="ignore"))

    return [s for _, s in sorted(out, key=_key)]


def _ripe_lookup(ip: str, *, timeout: int) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """Return (asn_dict, note)."""
    ck = f"ripe:{ip}"
    cached = _RIPE_CACHE.get(ck)
    if cached is not None:
        return cached.get("asn"), cached.get("note")

    url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"
    try:
        j = _http_get_json(url, timeout=timeout, user_agent="url-reputation/asn_geo(ripe)")
    except Exception as e:
        note = f"ripe_lookup_failed: {type(e).__name__}"
        _RIPE_CACHE.set(ck, {"asn": None, "note": note})
        return None, note

    data = j.get("data") or {}

    asn_num: Optional[int] = None
    asn_name: Optional[str] = None
    asn_org: Optional[str] = None
    prefix: Optional[str] = None

    # Flexible parsing; RIPEstat shape can vary by endpoint/version.
    try:
        # Common: data.asns = [{"asn": 15169, "holder": "..."}]
        asns = data.get("asns") or []
        if isinstance(asns, list) and asns:
            first = asns[0] if isinstance(asns[0], dict) else {}
            asn_num = _safe_int(first.get("asn") if isinstance(first, dict) else None)
            holder = first.get("holder") if isinstance(first, dict) else None
            if isinstance(holder, str) and holder.strip():
                asn_org = holder.strip()
    except Exception:
        pass

    try:
        # Common: data.prefix = "1.2.3.0/24" OR data.prefixes = [...]
        if isinstance(data.get("prefix"), str):
            prefix = data.get("prefix")
        else:
            prefixes = data.get("prefixes") or []
            if isinstance(prefixes, list) and prefixes:
                p0 = prefixes[0]
                if isinstance(p0, str):
                    prefix = p0
                elif isinstance(p0, dict) and isinstance(p0.get("prefix"), str):
                    prefix = p0.get("prefix")
    except Exception:
        pass

    # Some variants provide a "holder"/"name" at top level.
    for k in ("holder", "name", "as_name", "asname", "org"):
        v = data.get(k)
        if isinstance(v, str) and v.strip():
            if asn_org is None:
                asn_org = v.strip()
            break

    if asn_num is None:
        note = "ripe_no_asn"
        _RIPE_CACHE.set(ck, {"asn": None, "note": note})
        return None, note

    asn = {"number": asn_num, "name": asn_name, "org": asn_org, "prefix": prefix}
    _RIPE_CACHE.set(ck, {"asn": asn, "note": None})
    return asn, None


def _cymru_lookup(ip: str, *, timeout: int) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """Return (asn_dict, note)."""
    ck = f"cymru:{ip}"
    cached = _CYMRU_CACHE.get(ck)
    if cached is not None:
        return cached.get("asn"), cached.get("note")

    # Team Cymru whois supports a simple bulk protocol.
    # We keep parsing robust and accept best-effort results.
    try:
        s = socket.create_connection(("whois.cymru.com", 43), timeout=timeout)
        with s:
            f = s.makefile("rwb", buffering=0)
            f.write(b"begin\nverbose\n")
            f.write(ip.encode("utf-8", errors="strict") + b"\n")
            f.write(b"end\n")
            try:
                f.flush()
            except Exception:
                pass

            text = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                text += chunk
                if len(text) > 256 * 1024:
                    break
    except Exception as e:
        note = f"cymru_lookup_failed: {type(e).__name__}"
        _CYMRU_CACHE.set(ck, {"asn": None, "note": note})
        return None, note

    try:
        decoded = text.decode("utf-8", errors="replace")
    except Exception:
        decoded = ""

    asn_num: Optional[int] = None
    prefix: Optional[str] = None
    cc: Optional[str] = None
    as_name: Optional[str] = None

    # Expect one line like:
    # ASN | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    for line in decoded.splitlines():
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        # Header line often begins with "AS" or "ASN".
        if parts[0].lower() in {"asn", "as"}:
            continue
        if parts[1] != ip:
            continue

        asn_num = _safe_int(parts[0])
        prefix = parts[2] or None
        cc = parts[3] or None
        as_name = parts[6] or None
        break

    if asn_num is None:
        note = "cymru_no_asn"
        _CYMRU_CACHE.set(ck, {"asn": None, "note": note})
        return None, note

    asn = {"number": asn_num, "name": as_name, "org": as_name, "prefix": prefix, "cc": cc}
    _CYMRU_CACHE.set(ck, {"asn": asn, "note": None})
    return asn, None


def _ip_api_lookup(ip: str, *, timeout: int) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """Return (geo_dict, note)."""
    ck = f"ipapi:{ip}"
    cached = _IPAPI_CACHE.get(ck)
    if cached is not None:
        return cached.get("geo"), cached.get("note")

    # ip-api fields: keep small and stable.
    fields = ",".join(
        [
            "status",
            "message",
            "country",
            "regionName",
            "city",
            "lat",
            "lon",
            "isp",
            "as",
            "asname",
            "org",
            "query",
        ]
    )
    url = f"https://ip-api.com/json/{ip}?fields={fields}"

    try:
        j = _http_get_json(url, timeout=timeout, user_agent="url-reputation/asn_geo(ip-api)")
    except Exception as e:
        note = f"ip_api_failed: {type(e).__name__}"
        _IPAPI_CACHE.set(ck, {"geo": None, "note": note})
        return None, note

    if (j.get("status") or "").lower() != "success":
        msg = j.get("message")
        note = f"ip_api_fail: {msg}" if msg else "ip_api_fail"
        _IPAPI_CACHE.set(ck, {"geo": None, "note": note})
        return None, note

    geo = {
        "country": j.get("country"),
        "region": j.get("regionName"),
        "city": j.get("city"),
        "lat": j.get("lat"),
        "lon": j.get("lon"),
        "isp": j.get("isp"),
        "as": j.get("as") or j.get("asname"),
        "org": j.get("org"),
    }

    # Normalize to JSON-safe primitives.
    lat = geo.get("lat")
    if lat is not None:
        try:
            geo["lat"] = float(cast(Any, lat))
        except Exception:
            geo["lat"] = None
    lon = geo.get("lon")
    if lon is not None:
        try:
            geo["lon"] = float(cast(Any, lon))
        except Exception:
            geo["lon"] = None

    _IPAPI_CACHE.set(ck, {"geo": geo, "note": None})
    return geo, None


def _coverage(
    ips: list[str], asn: Optional[dict[str, Any]], geo: Optional[dict[str, Any]]
) -> list[str]:
    cov: list[str] = []
    if ips:
        cov.append("ips")
    if asn and asn.get("number") is not None:
        cov.append("asn")
    if asn and asn.get("org"):
        cov.append("org")
    if asn and asn.get("prefix"):
        cov.append("prefix")
    if geo and geo.get("country"):
        cov.append("country")
    if geo and geo.get("region"):
        cov.append("region")
    if geo and geo.get("city"):
        cov.append("city")
    if geo and geo.get("lat") is not None and geo.get("lon") is not None:
        cov.append("latlon")
    if geo and geo.get("isp"):
        cov.append("isp")
    return cov


def _quality(
    *,
    ips: list[str],
    asn: Optional[dict[str, Any]],
    geo: Optional[dict[str, Any]],
    sources: list[str],
    notes: list[str],
) -> dict[str, Any]:
    cov = _coverage(ips, asn, geo)

    if not cov:
        source = "none"
        confidence = "low"
    else:
        # If we got all desired high-value fields online, call it online/high.
        has_asn = asn is not None and asn.get("number") is not None
        has_geo = geo is not None and geo.get("country") is not None
        if has_asn and has_geo and sources:
            source = "online"
            confidence = "high"
        elif (has_asn or has_geo) and sources:
            source = "mixed"
            confidence = "medium"
        else:
            source = "local"
            confidence = "low"

    return {
        "source": source,
        "confidence": confidence,
        "coverage": cov,
        "notes": notes,
        "sources": sorted(set(sources)),
    }


class AsnGeoEnricher(Enricher):
    name = "asn_geo"

    def enrich(self, indicator: str, ctx: EnrichmentContext) -> dict[str, Any]:
        notes: list[str] = []
        srcs: list[str] = []

        # Determine IPs.
        ips: list[str] = []
        ind = indicator

        if ctx.indicator_type == "url":
            try:
                host = urlparse(indicator).hostname
                if host:
                    ind = host
                else:
                    notes.append("no_url_host")
            except Exception:
                notes.append("url_parse_failed")

        if ctx.indicator_type == "ip":
            try:
                ipaddress.ip_address(ind)
                ips = [ind]
            except Exception:
                notes.append("invalid_ip")
        elif ctx.indicator_type == "domain" or ctx.indicator_type == "url":
            ips = _resolve_domain_ips(ind, timeout=max(1, int(ctx.timeout)))
            if not ips:
                notes.append("no_a_aaaa_records")
        else:
            return {
                "skipped": True,
                "reason": "asn_geo enrichment requires indicator_type=domain|ip|url",
            }

        ips = _sort_ips(ips)

        # Choose a primary IP for lookups (rate-limit friendly).
        primary_ip = ips[0] if ips else None
        if len(ips) > 1:
            notes.append("multiple_ips_using_first_for_lookups")

        asn: Optional[dict[str, Any]] = None
        geo: Optional[dict[str, Any]] = None

        if _is_offline():
            notes.append("offline_mode_enabled")
        elif primary_ip:
            # ASN: RIPE first, then Cymru. If both disagree, keep RIPE and note.
            ripe_asn, ripe_note = _ripe_lookup(primary_ip, timeout=max(1, int(ctx.timeout)))
            if ripe_note:
                notes.append(ripe_note)
            if ripe_asn:
                asn = ripe_asn
                srcs.append("ripe")

            cymru_asn, cymru_note = _cymru_lookup(primary_ip, timeout=max(1, int(ctx.timeout)))
            if cymru_note:
                notes.append(cymru_note)
            if cymru_asn:
                srcs.append("cymru")
                if asn is None:
                    # Keep only the fields we expose (ensure stable shape).
                    asn = {
                        "number": cymru_asn.get("number"),
                        "name": cymru_asn.get("name"),
                        "org": cymru_asn.get("org"),
                        "prefix": cymru_asn.get("prefix"),
                    }
                else:
                    if (
                        cymru_asn.get("number") is not None
                        and asn.get("number") is not None
                        and _safe_int(cymru_asn.get("number")) != _safe_int(asn.get("number"))
                    ):
                        notes.append("conflicting_asn_sources_ripe_vs_cymru")

            # Geo: ip-api.
            geo_out, geo_note = _ip_api_lookup(primary_ip, timeout=max(1, int(ctx.timeout)))
            if geo_note:
                notes.append(geo_note)
            if geo_out:
                geo = {
                    "country": geo_out.get("country"),
                    "region": geo_out.get("region"),
                    "city": geo_out.get("city"),
                    "lat": geo_out.get("lat"),
                    "lon": geo_out.get("lon"),
                    "isp": geo_out.get("isp"),
                }
                srcs.append("ip-api")

                # If ASN missing, try to parse from ip-api "as" field ("AS1234 Foo").
                if asn is None:
                    as_s = geo_out.get("as")
                    if isinstance(as_s, str) and as_s.strip():
                        maybe_num = _safe_int(as_s.split()[0])
                        if maybe_num is not None:
                            asn = {"number": maybe_num, "name": None, "org": as_s, "prefix": None}
                            notes.append("asn_from_ip_api")
                            srcs.append("ip-api")

        q = _quality(ips=ips, asn=asn, geo=geo, sources=srcs, notes=notes)
        return {"ips": ips, "asn": asn, "geo": geo, "quality": q}
