"""
URL Reputation Web API
FastAPI backend for the url-reputation checker
"""

import os
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl
import uvicorn

# Add parent to path for url_reputation imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from url_reputation import check_url_reputation, check_urls_batch
from url_reputation.enrich import enrich

app = FastAPI(
    title="URL Reputation Checker",
    description="Multi-source URL/domain security analysis",
    version="1.1.0"
)


class CheckRequest(BaseModel):
    url: str
    sources: Optional[list[str]] = None
    enrich: Optional[list[str]] = None  # ["dns", "whois"]
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
            url=request.url,
            sources=request.sources,
            timeout=request.timeout or 30
        )
        
        # Add enrichment if requested
        if request.enrich:
            result["enrichment"] = enrich(
                result["domain"],
                request.enrich,
                timeout=request.timeout or 30
            )
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
            timeout=request.timeout or 30
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
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/sources")
async def list_sources():
    """List available reputation sources"""
    return {
        "free": [
            {"id": "urlhaus", "name": "URLhaus", "description": "Malware URLs (abuse.ch)"},
            {"id": "phishtank", "name": "OpenPhish", "description": "Phishing URLs"},
            {"id": "dnsbl", "name": "DNSBL", "description": "Spamhaus, SURBL, ZEN"},
            {"id": "alienvault_otx", "name": "AlienVault OTX", "description": "Community threat intel"},
        ],
        "api_key_required": [
            {"id": "virustotal", "name": "VirusTotal", "description": "70+ AV engines", "configured": bool(os.getenv("VIRUSTOTAL_API_KEY"))},
            {"id": "urlscan", "name": "URLScan.io", "description": "Sandbox analysis", "configured": bool(os.getenv("URLSCAN_API_KEY"))},
            {"id": "safebrowsing", "name": "Google Safe Browsing", "description": "Phishing/malware", "configured": bool(os.getenv("GOOGLE_SAFEBROWSING_API_KEY"))},
            {"id": "abuseipdb", "name": "AbuseIPDB", "description": "IP reputation", "configured": bool(os.getenv("ABUSEIPDB_API_KEY"))},
            {"id": "ipqualityscore", "name": "IPQualityScore", "description": "Fraud detection", "configured": bool(os.getenv("IPQUALITYSCORE_API_KEY"))},
            {"id": "threatfox", "name": "ThreatFox", "description": "IOCs (abuse.ch)", "configured": bool(os.getenv("THREATFOX_API_KEY"))},
        ]
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
