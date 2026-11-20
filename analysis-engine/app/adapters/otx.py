import time
import httpx
from app.config import get_settings
from app.schemas import EvidenceItem, ProviderStatus, ScoreFactor


async def lookup_otx(
    kind: str, value: str
) -> tuple[EvidenceItem, ScoreFactor, ProviderStatus]:
    """
    Queries AlienVault OTX DirectConnect v1 for IPv4, domain, or url.
    """
    settings = get_settings()
    start = time.perf_counter()

    if settings.alienvault_otx_api_key and settings.enable_live_public_lookups:
        headers = {"X-OTX-API-KEY": settings.alienvault_otx_api_key}
        section_map = {"ip": "IPv4", "domain": "domain", "url": "url"}
        otx_type = section_map.get(kind, "domain")
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{value}/general"
        try:
            async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
                resp = await client.get(endpoint, headers=headers)
            latency = int((time.perf_counter() - start) * 1000)

            if resp.status_code == 429:
                return _otx_fallback(kind, value, "RATE_LIMITED", latency, "OTX rate limit reached.")

            if resp.status_code == 404:
                return (
                    EvidenceItem(
                        provider="ALIENVAULT_OTX",
                        category="Open Threat Exchange Pulses",
                        title="0 OTX threat pulses reference this indicator",
                        verdict="CLEAN",
                        weight=15,
                        details={"pulse_count": 0, "pulses": []},
                        is_simulated=False,
                    ),
                    ScoreFactor(
                        factor="AlienVault OTX Threat Pulses",
                        points=0,
                        max_points=20,
                        reason="No OTX threat intelligence pulses matched.",
                        source="AlienVault OTX",
                        is_simulated=False,
                    ),
                    ProviderStatus(mode="LIVE", latency_ms=latency, message="OTX queried (unseen)"),
                )

            resp.raise_for_status()
            body_json = resp.json()
            pulse_info = body_json.get("pulse_info", {})
            whitelisted = bool(body_json.get("validation"))
            count = int(pulse_info.get("count", 0))
            pulses = [p.get("name", "Unnamed Pulse") for p in pulse_info.get("pulses", [])[:5]]
            if whitelisted:
                points = 0
                verdict = "CLEAN"
            else:
                points = min(20, count * 3)
                verdict = "MALICIOUS" if count >= 10 else ("SUSPICIOUS" if count >= 2 else ("INFO" if count == 1 else "CLEAN"))

            return (
                EvidenceItem(
                    provider="ALIENVAULT_OTX",
                    category="Open Threat Exchange Pulses",
                    title=f"Referenced in {count} AlienVault OTX threat pulses",
                    verdict=verdict,
                    weight=min(90, 20 + points * 3),
                    details={"pulse_count": count, "pulses": pulses},
                    is_simulated=False,
                ),
                ScoreFactor(
                    factor="AlienVault OTX Threat Pulses",
                    points=points,
                    max_points=20,
                    reason=(
                        f"Indicator appears in {count} community threat intelligence pulses."
                        if count > 0
                        else "0 community threat pulses matched."
                    ),
                    source="AlienVault OTX",
                    is_simulated=False,
                ),
                ProviderStatus(mode="LIVE", latency_ms=latency, message="Live OTX pulse lookup"),
            )
        except Exception as exc:
            latency = int((time.perf_counter() - start) * 1000)
            return _otx_fallback(
                kind, value, "ERROR", latency, f"OTX error ({type(exc).__name__}); fallback active."
            )

    latency = int((time.perf_counter() - start) * 1000)
    return _otx_fallback(
        kind,
        value,
        "DEMO_FALLBACK",
        latency,
        "ALIENVAULT_OTX_API_KEY not configured; demo pulse correlation active.",
    )


def _otx_fallback(
    kind: str, value: str, mode: str, latency_ms: int, note: str
) -> tuple[EvidenceItem, ScoreFactor, ProviderStatus]:
    lowered = value.lower()
    suspicious_markers = ("185.220.", "45.95.147.", "91.92.240.", "203.0.113.99", "verify", "login", "phish", ".xyz", ".tk", "stealer", "c2")
    matched = [m for m in suspicious_markers if m in lowered]

    if matched:
        pulse_count = min(7, 2 + len(matched) * 2)
        pulses = [
            "Credential Harvesting & Brand Spoofing Infrastructure 2026",
            "Active C2 & Phishing Redirector Watchlist (Demo Feed)",
        ]
        points = min(20, pulse_count * 3)
        verdict = "MALICIOUS" if pulse_count >= 5 else "SUSPICIOUS"
    else:
        pulse_count = 0
        pulses = []
        points = 0
        verdict = "CLEAN"

    return (
        EvidenceItem(
            provider="ALIENVAULT_OTX",
            category="Open Threat Exchange Pulses (Demo Telemetry)",
            title=f"[DEMO] {pulse_count} OTX pulses correlated",
            verdict=verdict,
            weight=20 + points * 2,
            details={"pulse_count": pulse_count, "pulses": pulses, "note": note},
            is_simulated=True,
        ),
        ScoreFactor(
            factor="AlienVault OTX Pulses (Demo Adapter)",
            points=points,
            max_points=20,
            reason=(
                f"Matched {pulse_count} simulated OTX threat intelligence pulses."
                if pulse_count > 0
                else "No simulated OTX pulse indicators matched."
            ),
            source="AlienVault OTX (Demo Fallback)",
            is_simulated=True,
        ),
        ProviderStatus(mode=mode, latency_ms=latency_ms, message=note),
    )
