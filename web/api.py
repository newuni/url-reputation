"""
URL Reputation Web API
FastAPI backend for the url-reputation checker
"""

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, cast

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Add parent to path for url_reputation imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from url_reputation import check_url_reputation, check_urls_batch
from url_reputation.enrichment.service import enrich_indicator
from url_reputation.models import IndicatorType
from url_reputation.scoring import aggregate_risk_score

app = FastAPI(
    title="URL Reputation Checker",
    description="Multi-source URL/domain security analysis",
    version="1.8.0",
)


class CheckRequest(BaseModel):
    url: str
    sources: Optional[list[str]] = None
    enrich: Optional[list[str]] = None  # ["dns", "whois", "asn_geo", "redirects"]
    timeout: Optional[int] = 30


class BatchRequest(BaseModel):
    urls: list[str]
    sources: Optional[list[str]] = None
    max_workers: Optional[int] = 5
    timeout: Optional[int] = 30


@app.get("/api/health")
async def health():
    """Health check endpoint"""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.post("/api/check")
async def check_url(request: CheckRequest):
    """Check a single URL reputation"""
    try:
        result = check_url_reputation(
            url=request.url, sources=request.sources, timeout=request.timeout or 30
        )

        # Add enrichment if requested (same engine used by CLI)
        if request.enrich:
            indicator = result.get("indicator") or {}
            indicator_type = cast(IndicatorType, str(indicator.get("type") or "domain"))
            canonical = indicator.get("canonical") or result.get("domain") or request.url

            result["enrichment"] = enrich_indicator(
                str(canonical),
                indicator_type=indicator_type,
                types=request.enrich,
                timeout=request.timeout or 30,
            )

            # Recompute score/verdict so enrichment signals (e.g. new domain) can affect output.
            sources_map = {
                str(s.get("name")): (s.get("raw") or {})
                for s in result.get("sources", [])
                if isinstance(s, dict) and s.get("name")
            }
            agg = aggregate_risk_score(sources_map, enrichment=result.get("enrichment"))
            result["risk_score"] = agg.risk_score
            result["verdict"] = agg.verdict
            result["score_breakdown"] = agg.score_breakdown
            result["reasons"] = agg.reasons

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/api/batch")
async def check_batch(request: BatchRequest):
    """Check multiple URLs"""
    if len(request.urls) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 URLs per batch")

    try:
        results = check_urls_batch(
            urls=request.urls,
            sources=request.sources,
            max_workers=request.max_workers or 5,
            timeout=request.timeout or 30,
        )

        # Summary stats
        summary = {
            "total": len(results),
            "clean": sum(1 for r in results if r["verdict"] == "CLEAN"),
            "low_risk": sum(1 for r in results if r["verdict"] == "LOW_RISK"),
            "medium_risk": sum(1 for r in results if r["verdict"] == "MEDIUM_RISK"),
            "high_risk": sum(1 for r in results if r["verdict"] == "HIGH_RISK"),
        }

        return {"summary": summary, "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/screenshot")
async def get_screenshot(path: str = Query(..., description="Absolute screenshot file path")):
    """Serve generated screenshot files to the web UI."""
    try:
        p = Path(path).resolve()
        allowed_root = Path(os.getenv("URL_REPUTATION_SCREENSHOT_DIR", "/tmp/url-reputation-shots")).resolve()
        if not str(p).startswith(str(allowed_root)):
            raise HTTPException(status_code=403, detail="Screenshot path not allowed")
        if not p.exists() or not p.is_file():
            raise HTTPException(status_code=404, detail="Screenshot not found")
        return FileResponse(p)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.get("/api/sources")
async def list_sources():
    """List available reputation sources"""
    return {
        "free": [
            {"id": "urlhaus", "name": "URLhaus", "description": "Malware URLs (abuse.ch)"},
            {"id": "phishtank", "name": "OpenPhish", "description": "Phishing URLs"},
            {"id": "dnsbl", "name": "DNSBL", "description": "Spamhaus, SURBL, ZEN"},
            {
                "id": "alienvault_otx",
                "name": "AlienVault OTX",
                "description": "Community threat intel",
            },
        ],
        "api_key_required": [
            {
                "id": "virustotal",
                "name": "VirusTotal",
                "description": "70+ AV engines",
                "configured": bool(os.getenv("VIRUSTOTAL_API_KEY")),
            },
            {
                "id": "urlscan",
                "name": "URLScan.io",
                "description": "Sandbox analysis",
                "configured": bool(os.getenv("URLSCAN_API_KEY")),
            },
            {
                "id": "safebrowsing",
                "name": "Google Safe Browsing",
                "description": "Phishing/malware",
                "configured": bool(os.getenv("GOOGLE_SAFEBROWSING_API_KEY")),
            },
            {
                "id": "abuseipdb",
                "name": "AbuseIPDB",
                "description": "IP reputation",
                "configured": bool(os.getenv("ABUSEIPDB_API_KEY")),
            },
            {
                "id": "ipqualityscore",
                "name": "IPQualityScore",
                "description": "Fraud detection",
                "configured": bool(os.getenv("IPQUALITYSCORE_API_KEY")),
            },
            {
                "id": "threatfox",
                "name": "ThreatFox",
                "description": "IOCs (abuse.ch)",
                "configured": bool(os.getenv("THREATFOX_API_KEY")),
            },
        ],
    }


# Serve static files
static_path = Path(__file__).parent / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=static_path), name="static")

    @app.get("/")
    async def root():
        return FileResponse(static_path / "index.html")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
