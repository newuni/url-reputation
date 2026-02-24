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

_WEAK_CIPHER_MARKERS = (
    "RC4",
    "3DES",
    "DES",
    "NULL",
    "EXPORT",
    "MD5",
    "PSK",
    "SRP",
    "ADH",
    "AECDH",
)
_STRONG_CIPHER_MARKERS = ("GCM", "CHACHA20", "POLY1305")


def _supported_tls_versions() -> list[tuple[str, object]]:
    """Return TLS versions we can probe in this Python runtime."""
    tls_version = getattr(ssl, "TLSVersion", None)
    if tls_version is None:
        return []

    versions: list[tuple[str, object]] = []
    for label, attr in (
        ("TLSv1.0", "TLSv1"),
        ("TLSv1.1", "TLSv1_1"),
        ("TLSv1.2", "TLSv1_2"),
        ("TLSv1.3", "TLSv1_3"),
    ):
        value = getattr(tls_version, attr, None)
        if value is not None:
            versions.append((label, value))
    return versions


def _classify_cipher(cipher_name: str | None) -> str:
    if not cipher_name:
        return "unknown"

    name = cipher_name.upper()
    if any(marker in name for marker in _WEAK_CIPHER_MARKERS):
        return "weak"
    if "RSA" in name and "ECDHE" not in name and "DHE" not in name:
        # RSA key exchange without (EC)DHE has no forward secrecy.
        return "moderate"
    if any(marker in name for marker in _STRONG_CIPHER_MARKERS):
        return "strong"
    if "ECDHE" in name or "DHE" in name:
        return "strong"
    return "moderate"


def _probe_tls_version(host: str, port: int, version: object, timeout: int) -> dict[str, object]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = cast(ssl.TLSVersion, version)
    context.maximum_version = cast(ssl.TLSVersion, version)

    legacy_versions = {
        getattr(getattr(ssl, "TLSVersion", object), "TLSv1", None),
        getattr(getattr(ssl, "TLSVersion", object), "TLSv1_1", None),
    }
    if version in legacy_versions:
        try:
            # Probe only: reduce OpenSSL policy to detect legacy support.
            context.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cipher = tls_sock.cipher() or (None, None, None)
                cipher_name, _, bits = cipher
                return {
                    "supported": True,
                    "protocol": tls_sock.version(),
                    "cipher": cipher_name,
                    "cipher_bits": bits,
                    "cipher_strength": _classify_cipher(cast(str | None, cipher_name)),
                }
    except ssl.SSLError as e:
        return {"supported": False, "error": f"SSL error: {str(e)}"}
    except socket.timeout:
        return {"supported": False, "error": "Connection timeout"}
    except OSError as e:
        return {"supported": False, "error": str(e)}


def _grade_tls_posture(protocols: dict[str, dict[str, object]]) -> dict[str, object]:
    supported = [name for name, data in protocols.items() if bool(data.get("supported"))]
    if not supported:
        return {
            "supported_protocols": [],
            "legacy_protocols_enabled": [],
            "weak_cipher_protocols": [],
            "score": 0,
            "grade": "F",
            "assessment": "No TLS handshake succeeded",
            "risk_indicators": ["No supported TLS protocols detected"],
        }

    legacy_protocols = [p for p in ("TLSv1.0", "TLSv1.1") if p in supported]
    weak_cipher_protocols: list[str] = []
    moderate_cipher_protocols: list[str] = []

    for protocol in supported:
        entry = protocols.get(protocol, {})
        strength = cast(str | None, entry.get("cipher_strength"))
        if not strength:
            strength = _classify_cipher(cast(str | None, entry.get("cipher")))
        if strength == "weak":
            weak_cipher_protocols.append(protocol)
        elif strength == "moderate":
            moderate_cipher_protocols.append(protocol)

    score = 100
    if legacy_protocols:
        score -= 45 if len(legacy_protocols) == 2 else 30
    if "TLSv1.2" in supported and "TLSv1.3" not in supported:
        score -= 10
    if weak_cipher_protocols:
        score -= 35
    elif moderate_cipher_protocols:
        score -= 10
    if supported == ["TLSv1.2"]:
        score -= 5

    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
        assessment = "Modern TLS posture"
    elif score >= 75:
        grade = "B"
        assessment = "Good TLS posture with minor hardening opportunities"
    elif score >= 60:
        grade = "C"
        assessment = "Mixed TLS posture; hardening recommended"
    elif score >= 40:
        grade = "D"
        assessment = "Weak TLS posture; prioritize remediation"
    else:
        grade = "F"
        assessment = "Critical TLS weaknesses detected"

    risk_indicators: list[str] = []
    if grade in {"C", "D", "F"}:
        risk_indicators.append(f"Weak TLS posture (grade {grade})")
    if legacy_protocols:
        risk_indicators.append(f"Legacy TLS protocols enabled: {', '.join(legacy_protocols)}")
    if weak_cipher_protocols:
        risk_indicators.append(f"Weak ciphers negotiated: {', '.join(weak_cipher_protocols)}")

    return {
        "supported_protocols": supported,
        "legacy_protocols_enabled": legacy_protocols,
        "weak_cipher_protocols": weak_cipher_protocols,
        "score": score,
        "grade": grade,
        "assessment": assessment,
        "risk_indicators": risk_indicators,
    }


def _probe_tls_posture(host: str, port: int, timeout: int) -> dict[str, object]:
    protocols: dict[str, dict[str, object]] = {}
    negotiated_ciphers: dict[str, str] = {}

    versions = _supported_tls_versions()
    if not versions:
        return {
            "protocols": {},
            "supported_protocols": [],
            "legacy_protocols_enabled": [],
            "weak_cipher_protocols": [],
            "negotiated_ciphers": {},
            "score": 0,
            "grade": "F",
            "assessment": "TLS probing not supported by runtime",
            "risk_indicators": ["TLS probing not supported by runtime"],
            "error": "TLS probing not supported on this Python runtime",
        }

    for label, version in versions:
        probe = _probe_tls_version(host, port, version, timeout=timeout)
        protocols[label] = probe
        cipher = probe.get("cipher")
        if probe.get("supported") and isinstance(cipher, str):
            negotiated_ciphers[label] = cipher

    grading = _grade_tls_posture(protocols)
    out: dict[str, object] = {"protocols": protocols, "negotiated_ciphers": negotiated_ciphers}
    out.update(grading)
    if not grading.get("supported_protocols"):
        errors = [d.get("error") for d in protocols.values() if d.get("error")]
        if errors:
            out["error"] = cast(str, errors[0])
    return out


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

        cert_error: str | None = None
        try:
            context = ssl.create_default_context()
            # We still verify trust chain, but do hostname checks ourselves
            # so we can report mismatch explicitly in enrichment output.
            context.check_hostname = False

            with (
                socket.create_connection((host, port), timeout=max(1, int(ctx.timeout))) as sock,
                context.wrap_socket(sock, server_hostname=host) as ssock,
            ):
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
                datetime.strptime(not_before_raw, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                if isinstance(not_before_raw, str)
                else None
            )
            not_after = (
                datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
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
            host_l = host.lower().strip(".")
            for pattern in san:
                pat = pattern.lower().strip(".")
                if fnmatch(host_l, pat):
                    hostname_match = True
                    break
            if not hostname_match:
                try:
                    # fallback to CN
                    for rdn in subject_parts:
                        for key, value in rdn:
                            if key == "commonName" and fnmatch(
                                host_l, str(value).lower().strip(".")
                            ):
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
        except Exception as e:
            cert_error = str(e)
            out["error"] = cert_error

        # Stronger posture analysis is only emitted for the tls enricher.
        if self.name == "tls":
            posture = _probe_tls_posture(host, port, timeout=max(1, int(ctx.timeout)))
            posture_risks = posture.pop("risk_indicators", [])
            out.update(posture)
            existing_risks = cast(list[str], out.get("risk_indicators", []))
            if isinstance(posture_risks, list):
                for indicator in posture_risks:
                    if isinstance(indicator, str) and indicator not in existing_risks:
                        existing_risks.append(indicator)
            out["risk_indicators"] = existing_risks

        return out


class TlsEnricher(SslCertEnricher):
    name = "tls"
