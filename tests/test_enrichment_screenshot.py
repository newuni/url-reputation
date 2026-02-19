from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from url_reputation.enrichment.base import EnrichmentContext
from url_reputation.enrichment.screenshot import ScreenshotEnricher


def test_screenshot_skipped_for_ip() -> None:
    out = ScreenshotEnricher().enrich("1.1.1.1", EnrichmentContext(indicator_type="ip"))
    assert out.get("skipped") is True


def test_screenshot_missing_playwright(monkeypatch: Any) -> None:
    real_import = __import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "playwright.sync_api":
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)

    out = ScreenshotEnricher().enrich("example.com", EnrichmentContext(indicator_type="domain"))
    assert out.get("skipped") is True


def test_screenshot_success(monkeypatch: Any, tmp_path: Any) -> None:
    class FakePage:
        def new_page(self, viewport: dict[str, int]) -> "FakePage":
            return self

        def goto(self, *args: Any, **kwargs: Any) -> None:
            return None

        def screenshot(self, path: str, full_page: bool = True) -> None:
            with open(path, "wb") as f:
                f.write(b"png")

    class FakeBrowser:
        def new_page(self, viewport: dict[str, int]) -> FakePage:
            return FakePage()

        def close(self) -> None:
            return None

    class FakeChromium:
        def launch(self, headless: bool = True) -> FakeBrowser:
            return FakeBrowser()

    class FakePlaywrightCtx:
        chromium = FakeChromium()

        def __enter__(self) -> "FakePlaywrightCtx":
            return self

        def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
            return None

    monkeypatch.setenv("URL_REPUTATION_SCREENSHOT_DIR", str(tmp_path))
    monkeypatch.setitem(
        __import__("sys").modules,
        "playwright.sync_api",
        SimpleNamespace(sync_playwright=lambda: FakePlaywrightCtx()),
    )

    out = ScreenshotEnricher().enrich(
        "https://example.com", EnrichmentContext(indicator_type="url")
    )
    assert out.get("exists") is True
    assert str(out.get("path", "")).endswith(".png")
