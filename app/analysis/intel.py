from __future__ import annotations

import base64
import hashlib
import logging
from urllib.parse import urlparse

import httpx

from app.config import Settings
from app.schemas import IntelResult

log = logging.getLogger("scamshield.intel")
SAFE_BROWSING = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
VT_URL_REPORT = "https://www.virustotal.com/api/v3/urls/{id}"


def _normalize_url(raw: str) -> str | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"}:
        return None
    host = (parsed.hostname or "").lower()
    if not host or host in {"localhost"}:
        return None
    return parsed.geturl()


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def check_safe_browsing(urls: list[str], settings: Settings) -> IntelResult:
    key = settings.google_safe_browsing_api_key
    if not key:
        return IntelResult(provider="google_safe_browsing", status="skipped", summary="API key not configured")
    payload = {
        "client": {"clientId": "scamshield-ai", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls[:10]],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=settings.intel_timeout_seconds) as client:
            res = await client.post(SAFE_BROWSING, params={"key": key}, json=payload)
        if res.status_code >= 400:
            return IntelResult(provider="google_safe_browsing", status="error", summary=f"HTTP {res.status_code}")
        data = res.json()
        matches = data.get("matches") or []
        if matches:
            kinds = sorted({m.get("threatType", "UNKNOWN") for m in matches})
            return IntelResult(provider="google_safe_browsing", status="ok", summary="Listed as " + ", ".join(kinds), raw={"match_count": len(matches), "types": kinds})
        return IntelResult(provider="google_safe_browsing", status="ok", summary="No Safe Browsing match (absence of a hit is not proof of safety)", raw={"match_count": 0})
    except Exception as exc:
        log.warning("safe browsing failed: %s", exc)
        return IntelResult(provider="google_safe_browsing", status="error", summary="provider unreachable")


async def check_virustotal(urls: list[str], settings: Settings) -> IntelResult:
    key = settings.virustotal_api_key
    if not key:
        return IntelResult(provider="virustotal", status="skipped", summary="API key not configured")
    url = urls[0]
    try:
        async with httpx.AsyncClient(timeout=settings.intel_timeout_seconds) as client:
            res = await client.get(VT_URL_REPORT.format(id=_vt_url_id(url)), headers={"x-apikey": key})
        if res.status_code == 404:
            return IntelResult(provider="virustotal", status="unknown", summary="URL not in VirusTotal corpus")
        if res.status_code >= 400:
            return IntelResult(provider="virustotal", status="error", summary=f"HTTP {res.status_code}")
        stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        return IntelResult(provider="virustotal", status="ok", summary=f"{malicious} malicious / {suspicious} suspicious vendor flags", raw={"stats": stats})
    except Exception as exc:
        log.warning("virustotal failed: %s", exc)
        return IntelResult(provider="virustotal", status="error", summary="provider unreachable")


async def lookup(urls: list[str], settings: Settings) -> list[IntelResult]:
    normalized = []
    for raw in urls:
        n = _normalize_url(raw)
        if n:
            normalized.append(n)
    if not normalized:
        return [IntelResult(provider="live_intel", status="skipped", summary="No checkable http(s) URL")]
    return [await check_safe_browsing(normalized, settings), await check_virustotal(normalized, settings)]


def intel_weight(results: list[IntelResult]) -> list[tuple[str, int, str]]:
    extra: list[tuple[str, int, str]] = []
    for item in results:
        if item.status != "ok":
            continue
        if item.provider == "google_safe_browsing" and item.raw.get("match_count"):
            extra.append(("gsb_hit", 40, item.summary))
        if item.provider == "virustotal":
            stats = item.raw.get("stats") or {}
            mal = int(stats.get("malicious") or 0)
            sus = int(stats.get("suspicious") or 0)
            if mal >= 3:
                extra.append(("vt_malicious", 36, item.summary))
            elif mal >= 1 or sus >= 3:
                extra.append(("vt_suspicious", 18, item.summary))
    return extra


def fingerprint(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()
