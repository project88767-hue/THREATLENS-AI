from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from app.ai.assistant import run_investigation_assistant
from app.analyzers.domain_analyzer import analyze_domain
from app.analyzers.email_analyzer import analyze_email
from app.analyzers.ip_analyzer import analyze_ip
from app.analyzers.url_analyzer import analyze_url
from app.analyzers.vuln_analyzer import analyze_cve
from app.config import Settings, get_settings
from app.schemas import (
    AnalysisResponse,
    AssistantRequest,
    AssistantResponse,
    CveScanRequest,
    DomainScanRequest,
    EmailScanRequest,
    IpScanRequest,
    UrlScanRequest,
)
from app.security.ssrf import SSRFBlockedError

app = FastAPI(
    title="THREATLENS AI - Cybersecurity Analysis Engine",
    description=(
        "Defensive Threat Intelligence, Indicator Forensics, Explainable Risk Scoring, "
        "and AI Investigation Copilot Engine."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4000", "http://127.0.0.1:4000"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def verify_internal_key(
    x_engine_key: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    if settings.environment == "production":
        if not x_engine_key or x_engine_key != settings.internal_engine_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing X-Engine-Key header.",
            )
    elif x_engine_key and x_engine_key != settings.internal_engine_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid X-Engine-Key header.",
        )


@app.get("/health")
async def health_check(settings: Settings = Depends(get_settings)) -> dict:
    return {
        "status": "healthy",
        "service": "threatlens-analysis-engine",
        "version": "1.0.0",
        "authorized_defensive_mode": True,
        "providers": {
            "virustotal": "LIVE_KEY_CONFIGURED" if settings.virustotal_api_key else "DEMO_FALLBACK",
            "google_safe_browsing": (
                "LIVE_KEY_CONFIGURED" if settings.google_safe_browsing_api_key else "DEMO_FALLBACK"
            ),
            "abuseipdb": "LIVE_KEY_CONFIGURED" if settings.abuseipdb_api_key else "DEMO_FALLBACK",
            "alienvault_otx": (
                "LIVE_KEY_CONFIGURED" if settings.alienvault_otx_api_key else "DEMO_FALLBACK"
            ),
            "nvd": (
                "LIVE_KEY_CONFIGURED"
                if settings.nvd_api_key
                else ("PUBLIC_LIVE" if settings.enable_live_public_lookups else "DEMO_FALLBACK")
            ),
            "rdap": "PUBLIC_LIVE" if settings.enable_live_public_lookups else "DEMO_FALLBACK",
            "ai_assistant": "LIVE_LLM_CONFIGURED" if settings.ai_api_key else "SOC_COPILOT_ENGINE",
        },
    }


@app.post(
    "/api/v1/analyze/url",
    response_model=AnalysisResponse,
    dependencies=[Depends(verify_internal_key)],
)
async def scan_url_endpoint(payload: UrlScanRequest) -> AnalysisResponse:
    try:
        return await analyze_url(payload.url)
    except SSRFBlockedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post(
    "/api/v1/analyze/ip",
    response_model=AnalysisResponse,
    dependencies=[Depends(verify_internal_key)],
)
async def scan_ip_endpoint(payload: IpScanRequest) -> AnalysisResponse:
    try:
        return await analyze_ip(payload.ip)
    except SSRFBlockedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post(
    "/api/v1/analyze/domain",
    response_model=AnalysisResponse,
    dependencies=[Depends(verify_internal_key)],
)
async def scan_domain_endpoint(payload: DomainScanRequest) -> AnalysisResponse:
    try:
        return await analyze_domain(payload.domain)
    except SSRFBlockedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post(
    "/api/v1/analyze/email",
    response_model=AnalysisResponse,
    dependencies=[Depends(verify_internal_key)],
)
async def scan_email_endpoint(payload: EmailScanRequest) -> AnalysisResponse:
    if not payload.raw_headers.strip() and not payload.body.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide email headers or message body for analysis.",
        )
    return await analyze_email(payload)


@app.post(
    "/api/v1/analyze/cve",
    response_model=AnalysisResponse,
    dependencies=[Depends(verify_internal_key)],
)
async def scan_cve_endpoint(payload: CveScanRequest) -> AnalysisResponse:
    return await analyze_cve(payload.cve_id)


@app.post(
    "/api/v1/assistant/analyze",
    response_model=AssistantResponse,
    dependencies=[Depends(verify_internal_key)],
)
async def assistant_endpoint(payload: AssistantRequest) -> AssistantResponse:
    return await run_investigation_assistant(payload)
