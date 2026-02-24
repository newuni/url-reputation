"""Explainable, configurable risk score aggregation (T19).

This module aggregates provider results (and optional enrichment) into:
- risk_score: int (0-100)
- verdict: CLEAN/LOW_RISK/MEDIUM_RISK/HIGH_RISK
- score_breakdown: list of rule contributions (explainable)
- reasons: human-readable strings

Backwards-compat: callers can still use `url_reputation.checker.calculate_risk_score`,
which now delegates to this module and returns only (score, verdict).
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .models import Verdict

# Base points for common threat types used by provider rules.
THREAT_WEIGHTS: dict[str, int] = {
    "malware": 40,
    "phishing": 35,
    "spam": 20,
    "suspicious": 15,
    "unknown": 10,
}


DEFAULT_PROVIDER_WEIGHTS: dict[str, float] = {
    # Providers (sources)
    "virustotal": 1.0,
    "urlhaus": 1.0,
    "phishtank": 1.0,
    "dnsbl": 1.0,
    "safebrowsing": 1.0,
    "abuseipdb": 1.0,
    "urlscan": 1.0,
    "alienvault_otx": 1.0,
    "threatfox": 1.0,
    "ipqualityscore": 1.0,
    # Enrichment modules (when present)
    "redirects": 1.0,
    "whois": 1.0,
    "ssl": 1.0,
    "tls": 1.0,
}


def _round_half_up(x: float) -> int:
    # Deterministic round-half-up for positive contributions.
    if x <= 0:
        return 0
    return int(x + 0.5)


def load_provider_weights_from_env(
    env_var: str = "URL_REPUTATION_PROVIDER_WEIGHTS",
) -> dict[str, float]:
    """Load provider weights from a JSON env var.

    Example:
      URL_REPUTATION_PROVIDER_WEIGHTS='{"phishtank": 0.5, "virustotal": 1.2}'
    """

    raw = os.getenv(env_var)
    weights = dict(DEFAULT_PROVIDER_WEIGHTS)
    if not raw:
        return weights

    try:
        parsed = json.loads(raw)
    except Exception:
        return weights

    if not isinstance(parsed, dict):
        return weights

    for k, v in parsed.items():
        if not isinstance(k, str):
            continue
        if isinstance(v, (int, float)):
            weights[k] = float(v)

    return weights


@dataclass(frozen=True)
class ScoreContribution:
    """A single rule contribution to the aggregated score."""

    rule_id: str
    provider: str
    points: int
    weight: float
    weighted_points: int
    reason: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "provider": self.provider,
            "points": int(self.points),
            "weight": float(self.weight),
            "weighted_points": int(self.weighted_points),
            "reason": self.reason,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class AggregatedScore:
    risk_score: int
    verdict: Verdict
    score_breakdown: list[dict[str, Any]]
    reasons: list[str]


def _verdict_from_score(score: int) -> Verdict:
    if score <= 20:
        return "CLEAN"
    if score <= 50:
        return "LOW_RISK"
    if score <= 75:
        return "MEDIUM_RISK"
    return "HIGH_RISK"


def _add_contribution(
    out: list[ScoreContribution],
    *,
    rule_id: str,
    provider: str,
    points: int,
    weights: Mapping[str, float],
    reason: str,
    evidence: dict[str, Any] | None = None,
) -> None:
    if points <= 0:
        return
    w = float(weights.get(provider, 1.0))
    weighted = _round_half_up(points * w)
    if weighted <= 0:
        return
    out.append(
        ScoreContribution(
            rule_id=rule_id,
            provider=provider,
            points=int(points),
            weight=w,
            weighted_points=int(weighted),
            reason=reason,
            evidence=evidence or {},
        )
    )


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def aggregate_risk_score(
    results: Mapping[str, Mapping[str, Any]],
    *,
    enrichment: Mapping[str, Any] | None = None,
    provider_weights: Mapping[str, float] | None = None,
) -> AggregatedScore:
    """Aggregate provider results (+ optional enrichment) into an explainable score."""

    weights = (
        dict(provider_weights) if provider_weights is not None else load_provider_weights_from_env()
    )

    contribs: list[ScoreContribution] = []

    # Provider-based rules. Iterate deterministically.
    for provider in sorted(results.keys()):
        payload = results.get(provider) or {}
        if not isinstance(payload, Mapping):
            continue
        if payload.get("error"):
            continue

        if provider == "virustotal":
            detected = payload.get("detected", 0) or 0
            total = payload.get("total", 70) or 70
            if (
                isinstance(detected, (int, float))
                and isinstance(total, (int, float))
                and detected > 0
            ):
                ratio = float(detected) / max(float(total), 1.0)
                pts = int(ratio * 50)
                _add_contribution(
                    contribs,
                    rule_id="provider.virustotal.detections_ratio",
                    provider="virustotal",
                    points=pts,
                    weights=weights,
                    reason="VirusTotal detections reported",
                    evidence={"detected": detected, "total": total, "ratio": ratio},
                )

        elif provider == "urlhaus" and bool(payload.get("listed")):
            _add_contribution(
                contribs,
                rule_id="provider.urlhaus.listed",
                provider="urlhaus",
                points=THREAT_WEIGHTS["malware"],
                weights=weights,
                reason="URLhaus listing (malware)",
                evidence={
                    "match_type": payload.get("match_type"),
                    "threat_type": payload.get("threat_type"),
                },
            )

        elif provider == "phishtank" and bool(payload.get("listed")):
            _add_contribution(
                contribs,
                rule_id="provider.phishtank.listed",
                provider="phishtank",
                points=THREAT_WEIGHTS["phishing"],
                weights=weights,
                reason="PhishTank listing (phishing)",
                evidence={},
            )

        elif provider == "dnsbl" and bool(payload.get("listed")):
            _add_contribution(
                contribs,
                rule_id="provider.dnsbl.listed",
                provider="dnsbl",
                points=THREAT_WEIGHTS["spam"],
                weights=weights,
                reason="DNSBL listing (spam/suspicious)",
                evidence={},
            )

        elif provider == "safebrowsing" and payload.get("threats"):
            _add_contribution(
                contribs,
                rule_id="provider.safebrowsing.threats",
                provider="safebrowsing",
                points=THREAT_WEIGHTS["malware"],
                weights=weights,
                reason="Google Safe Browsing threats reported",
                evidence={"threat_count": len(payload.get("threats") or [])},
            )

        elif provider == "abuseipdb":
            abuse_score = payload.get("abuse_score", 0) or 0
            if isinstance(abuse_score, (int, float)) and float(abuse_score) > 50:
                pts = int(float(abuse_score) * 0.4)
                _add_contribution(
                    contribs,
                    rule_id="provider.abuseipdb.abuse_score",
                    provider="abuseipdb",
                    points=pts,
                    weights=weights,
                    reason="AbuseIPDB high abuse score",
                    evidence={"abuse_score": abuse_score},
                )

        elif provider == "urlscan" and bool(payload.get("malicious")):
            _add_contribution(
                contribs,
                rule_id="provider.urlscan.malicious",
                provider="urlscan",
                points=THREAT_WEIGHTS["suspicious"],
                weights=weights,
                reason="urlscan marked as malicious/suspicious",
                evidence={},
            )

        elif provider == "alienvault_otx":
            if bool(payload.get("has_pulses")) and not bool(payload.get("is_whitelisted")):
                pulse_count = payload.get("pulse_count", 0) or 0
                if isinstance(pulse_count, (int, float)) and pulse_count >= 5:
                    _add_contribution(
                        contribs,
                        rule_id="provider.alienvault_otx.pulses_many",
                        provider="alienvault_otx",
                        points=THREAT_WEIGHTS["malware"],
                        weights=weights,
                        reason="AlienVault OTX: many pulses reported",
                        evidence={"pulse_count": pulse_count},
                    )
                elif isinstance(pulse_count, (int, float)) and pulse_count >= 1:
                    _add_contribution(
                        contribs,
                        rule_id="provider.alienvault_otx.pulses_some",
                        provider="alienvault_otx",
                        points=THREAT_WEIGHTS["suspicious"],
                        weights=weights,
                        reason="AlienVault OTX: pulses reported",
                        evidence={"pulse_count": pulse_count},
                    )

        elif provider == "threatfox" and bool(payload.get("listed")):
            _add_contribution(
                contribs,
                rule_id="provider.threatfox.listed",
                provider="threatfox",
                points=THREAT_WEIGHTS["malware"],
                weights=weights,
                reason="ThreatFox listing (malware)",
                evidence={},
            )

        elif provider == "ipqualityscore":
            if bool(payload.get("malware")):
                _add_contribution(
                    contribs,
                    rule_id="provider.ipqualityscore.malware",
                    provider="ipqualityscore",
                    points=THREAT_WEIGHTS["malware"],
                    weights=weights,
                    reason="IPQualityScore flagged malware",
                    evidence={},
                )
            elif bool(payload.get("phishing")):
                _add_contribution(
                    contribs,
                    rule_id="provider.ipqualityscore.phishing",
                    provider="ipqualityscore",
                    points=THREAT_WEIGHTS["phishing"],
                    weights=weights,
                    reason="IPQualityScore flagged phishing",
                    evidence={},
                )
            else:
                rs = payload.get("risk_score", 0) or 0
                if bool(payload.get("suspicious")) or (
                    isinstance(rs, (int, float)) and float(rs) >= 75
                ):
                    _add_contribution(
                        contribs,
                        rule_id="provider.ipqualityscore.suspicious",
                        provider="ipqualityscore",
                        points=THREAT_WEIGHTS["suspicious"],
                        weights=weights,
                        reason="IPQualityScore flagged suspicious/high risk score",
                        evidence={"risk_score": rs},
                    )

    # Enrichment-based rules (only if provided).
    if enrichment and isinstance(enrichment, Mapping):
        redirects = enrichment.get("redirects")
        if isinstance(redirects, Mapping):
            hops = redirects.get("hops", 0) or 0
            try:
                hops_i = int(hops)
            except Exception:
                hops_i = 0

            if hops_i > 0:
                if hops_i >= 3:
                    pts = 10
                    why = "Multiple redirects observed"
                else:
                    pts = 5
                    why = "Redirects observed"

                # Add a small extra penalty when redirect crosses domains.
                chain = redirects.get("chain") or []
                initial_url = None
                if isinstance(chain, list) and chain:
                    first = chain[0]
                    if isinstance(first, Mapping):
                        initial_url = first.get("url")
                final_url = redirects.get("final_url")
                if (
                    isinstance(initial_url, str)
                    and isinstance(final_url, str)
                    and _host(initial_url)
                    and _host(final_url)
                    and _host(initial_url) != _host(final_url)
                ):
                    pts += 5
                    why = why + " (cross-domain)"

                _add_contribution(
                    contribs,
                    rule_id="enrichment.redirects.hops",
                    provider="redirects",
                    points=pts,
                    weights=weights,
                    reason=why,
                    evidence={"hops": hops_i, "final_url": final_url},
                )

        whois = enrichment.get("whois")
        if isinstance(whois, Mapping):
            age_days = whois.get("domain_age_days")
            # Some WHOIS implementations may return strings; ignore for scoring.
            age_i: int | None = int(age_days) if isinstance(age_days, (int, float)) else None

            if age_i is not None and age_i >= 0:
                if age_i < 7:
                    pts = 25
                    why = "Very new domain (< 7 days)"
                elif age_i < 30:
                    pts = 15
                    why = "New domain (< 30 days)"
                elif age_i < 180:
                    pts = 5
                    why = "Relatively new domain (< 180 days)"
                else:
                    pts = 0
                    why = ""

                if pts > 0:
                    _add_contribution(
                        contribs,
                        rule_id="enrichment.whois.domain_age",
                        provider="whois",
                        points=pts,
                        weights=weights,
                        reason=why,
                        evidence={
                            "domain_age_days": age_i,
                            "creation_date": whois.get("creation_date"),
                        },
                    )

        ssl_data = enrichment.get("ssl") or enrichment.get("tls") or enrichment.get("tls_cert")
        if isinstance(ssl_data, Mapping):
            if bool(ssl_data.get("expired")):
                _add_contribution(
                    contribs,
                    rule_id="enrichment.ssl.expired",
                    provider="ssl",
                    points=20,
                    weights=weights,
                    reason="SSL certificate expired",
                    evidence={"expired": True},
                )
            days = ssl_data.get("days_to_expiry")
            if isinstance(days, (int, float)) and 0 <= int(days) <= 14:
                _add_contribution(
                    contribs,
                    rule_id="enrichment.ssl.expiring_soon",
                    provider="ssl",
                    points=10,
                    weights=weights,
                    reason="SSL certificate expires soon",
                    evidence={"days_to_expiry": int(days)},
                )
            if bool(ssl_data.get("self_signed")):
                _add_contribution(
                    contribs,
                    rule_id="enrichment.ssl.self_signed",
                    provider="ssl",
                    points=10,
                    weights=weights,
                    reason="Self-signed TLS certificate",
                    evidence={"self_signed": True},
                )
            if ssl_data.get("hostname_match") is False:
                _add_contribution(
                    contribs,
                    rule_id="enrichment.ssl.hostname_mismatch",
                    provider="ssl",
                    points=10,
                    weights=weights,
                    reason="TLS certificate hostname mismatch",
                    evidence={"hostname_match": False},
                )
            grade = ssl_data.get("grade")
            grade_points = {"C": 5, "D": 15, "F": 25}.get(str(grade), 0)
            if grade_points > 0:
                _add_contribution(
                    contribs,
                    rule_id="enrichment.tls.posture_grade",
                    provider="tls",
                    points=grade_points,
                    weights=weights,
                    reason=f"Weak TLS posture grade {grade}",
                    evidence={"grade": grade},
                )
            legacy = ssl_data.get("legacy_protocols_enabled")
            if isinstance(legacy, list) and legacy:
                _add_contribution(
                    contribs,
                    rule_id="enrichment.tls.legacy_protocols",
                    provider="tls",
                    points=10,
                    weights=weights,
                    reason="Legacy TLS protocols enabled",
                    evidence={"legacy_protocols_enabled": legacy},
                )
            weak_cipher_protocols = ssl_data.get("weak_cipher_protocols")
            if isinstance(weak_cipher_protocols, list) and weak_cipher_protocols:
                _add_contribution(
                    contribs,
                    rule_id="enrichment.tls.weak_ciphers",
                    provider="tls",
                    points=10,
                    weights=weights,
                    reason="Weak TLS cipher negotiation detected",
                    evidence={"weak_cipher_protocols": weak_cipher_protocols},
                )

    # Deterministic ordering for explainability outputs.
    contribs_sorted = sorted(contribs, key=lambda c: (c.rule_id, c.provider, -c.weighted_points))

    total = sum(c.weighted_points for c in contribs_sorted)
    total_capped = max(0, min(int(total), 100))
    verdict = _verdict_from_score(total_capped)

    breakdown = [c.to_dict() for c in contribs_sorted]
    reasons = [f"{c.reason} (+{c.weighted_points})" for c in contribs_sorted]

    return AggregatedScore(
        risk_score=total_capped,
        verdict=verdict,
        score_breakdown=breakdown,
        reasons=reasons,
    )
