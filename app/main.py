from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.analysis.engine import analyze_text
from app.analysis.indicators import extract
from app.analysis.intel import fingerprint, lookup
from app.audit import write_event
from app.config import Settings, get_settings
from app.rate_limit import limit_check
from app.schemas import CheckRequest, CheckResponse, EvidenceItem, HealthResponse
from app.security import SecurityHeadersMiddleware, household_hash, new_check_id

log = logging.getLogger("scamshield")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title=settings.app_name, version=__version__, docs_url=None, redoc_url=None)
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.settings = settings
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            version=__version__,
            intel={
                "google_safe_browsing": "configured" if settings.google_safe_browsing_api_key else "off",
                "virustotal": "configured" if settings.virustotal_api_key else "off",
            },
        )

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    async def _run_check(request: Request, content: str, source_hint: str, household_raw: str) -> CheckResponse:
        if len(content) > settings.max_text_chars:
            raise HTTPException(status_code=413, detail="Content too large")
        household = household_hash(household_raw, settings)
        limit_check(request, household, settings.rate_limit_checks_per_minute)
        urls = [i.value for i in extract(content) if i.kind == "url"]
        intel = await lookup(urls, settings)
        result = analyze_text(content, intel=intel)
        check_id = new_check_id()
        write_event(settings, {
            "check_id": check_id,
            "household": household,
            "verdict": result["verdict"],
            "score": result["score"],
            "source_hint": source_hint[:64],
            "content_sha256": fingerprint(content),
            "indicator_kinds": sorted({i.kind for i in result["indicators"]}),
            "evidence_codes": [e.code for e in result["evidence"]],
            "intel": [{"provider": i.provider, "status": i.status} for i in result["intel"]],
            "injection": bool(result["injection_hits"]),
            "stored_raw": False,
        })
        return CheckResponse(
            check_id=check_id,
            verdict=result["verdict"],
            score=result["score"],
            summary=result["summary"],
            evidence=result["evidence"],
            indicators=result["indicators"],
            actions=result["actions"],
            intel=result["intel"],
            policy={
                "links_opened": False,
                "raw_content_stored": False,
                "unknown_preferred_to_fiction": True,
                "agent_cannot_pay_or_reply": True,
            },
            content_stored=False,
        )

    @app.post("/api/check", response_model=CheckResponse)
    async def check(payload: CheckRequest, request: Request) -> CheckResponse:
        if not payload.content:
            raise HTTPException(status_code=400, detail="Paste the suspicious content first")
        return await _run_check(request, payload.content, payload.source_hint, payload.household_id)

    @app.post("/api/check-upload", response_model=CheckResponse)
    async def check_upload(request: Request, file: UploadFile = File(...), household_id: str = Form("")) -> CheckResponse:
        household = household_hash(household_id, settings)
        limit_check(request, household, settings.rate_limit_uploads_per_minute)
        data = await file.read(settings.max_upload_bytes + 1)
        if len(data) > settings.max_upload_bytes:
            raise HTTPException(status_code=413, detail="File too large")
        name = (file.filename or "upload").lower()
        ctype = (file.content_type or "").lower()
        extra: list[EvidenceItem] = []
        if ctype.startswith("text/") or name.endswith((".txt", ".eml", ".csv")):
            text = data.decode("utf-8", errors="replace")
        else:
            extra.append(EvidenceItem(
                code="binary_upload",
                detail=f"Received {ctype or 'file'} named {name}. ScamShield does not open embedded destinations. Paste the visible words and any raw URL printed in the screenshot.",
                weight=0,
                source="policy",
            ))
            text = f"[binary upload: {name}]"
        result = analyze_text(text, extra_evidence=extra)
        urls = [i.value for i in result["indicators"] if i.kind == "url"]
        if urls:
            intel = await lookup(urls, settings)
            result = analyze_text(text, intel=intel, extra_evidence=extra)
        check_id = new_check_id()
        write_event(settings, {
            "check_id": check_id,
            "household": household,
            "verdict": result["verdict"],
            "score": result["score"],
            "source_hint": "upload",
            "filename": name[:80],
            "content_sha256": fingerprint(text),
            "stored_raw": False,
        })
        return CheckResponse(
            check_id=check_id,
            verdict=result["verdict"],
            score=result["score"],
            summary=result["summary"],
            evidence=result["evidence"],
            indicators=result["indicators"],
            actions=result["actions"],
            intel=result["intel"],
            policy={
                "links_opened": False,
                "raw_content_stored": False,
                "unknown_preferred_to_fiction": True,
                "agent_cannot_pay_or_reply": True,
            },
        )

    @app.exception_handler(HTTPException)
    async def http_exc(_, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    return app


app = create_app()
