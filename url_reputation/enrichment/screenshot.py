"""Screenshot enrichment (best-effort).

Optional dependency: playwright. If unavailable, returns skipped reason.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from urllib.parse import urlparse

from .base import Enricher, EnrichmentContext


class ScreenshotEnricher(Enricher):
    name = "screenshot"

    def enrich(self, indicator: str, ctx: EnrichmentContext) -> dict[str, object]:
        if ctx.indicator_type not in {"url", "domain"}:
            return {"skipped": True, "reason": "screenshot requires url/domain"}

        target_url = indicator if ctx.indicator_type == "url" else f"https://{indicator}"

        parsed = urlparse(target_url)
        if not parsed.scheme:
            target_url = f"https://{target_url}"

        out_dir = Path(os.getenv("URL_REPUTATION_SCREENSHOT_DIR", "/tmp/url-reputation-shots"))
        out_dir.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(target_url.encode("utf-8")).hexdigest()[:16]
        out_path = out_dir / f"{digest}.png"

        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return {
                "skipped": True,
                "reason": "playwright not installed",
                "target_url": target_url,
            }

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1366, "height": 900})
                page.goto(
                    target_url,
                    wait_until="domcontentloaded",
                    timeout=max(1000, int(ctx.timeout) * 1000),
                )
                page.screenshot(path=str(out_path), full_page=True)
                browser.close()
            return {
                "target_url": target_url,
                "path": str(out_path),
                "exists": out_path.exists(),
            }
        except Exception as e:
            return {
                "target_url": target_url,
                "error": str(e),
            }
