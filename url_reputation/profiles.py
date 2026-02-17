"""Profiles: sensible defaults for provider selection.

Profiles are a developer-experience feature: users can pick a single preset
instead of knowing each provider.

Notes:
- Profiles only affect **provider selection** (and optionally timeouts later).
- If the user passes `--sources`, it takes precedence over `--profile`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ProfileName = Literal["free", "fast", "thorough", "privacy"]


@dataclass(frozen=True)
class Profile:
    name: ProfileName
    providers: list[str]
    description: str


PROFILES: dict[ProfileName, Profile] = {
    "free": Profile(
        name="free",
        providers=[
            "urlhaus",
            "phishtank",
            "dnsbl",
            "alienvault_otx",
        ],
        description="Only providers that work without API keys.",
    ),
    "fast": Profile(
        name="fast",
        providers=[
            "urlhaus",
            "phishtank",
            "dnsbl",
            "alienvault_otx",
        ],
        description="Same as free, intended for low-latency checks.",
    ),
    "privacy": Profile(
        name="privacy",
        providers=[
            "urlhaus",
            "phishtank",
            "dnsbl",
            "alienvault_otx",
        ],
        description="Avoid providers that require submitting full URLs; defaults to free providers.",
    ),
    "thorough": Profile(
        name="thorough",
        providers=[
            # Free
            "urlhaus",
            "phishtank",
            "dnsbl",
            "alienvault_otx",
            # Key-based (will auto-skip if key missing)
            "virustotal",
            "urlscan",
            "safebrowsing",
            "abuseipdb",
            "ipqualityscore",
            "threatfox",
        ],
        description="Try everything available (skips providers missing API keys).",
    ),
}


def get_profile(name: ProfileName) -> Profile:
    return PROFILES[name]
