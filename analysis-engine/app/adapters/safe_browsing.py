import time
import httpx
from app.config import get_settings
from app.schemas import EvidenceItem, ProviderStatus, ScoreFactor


async def lookup_safe_browsing(
    url: str,
) -> tuple[EvidenceItem, ScoreFactor, ProviderStatus]:
    settings = get_settings()
    start = time.perf_counter()

    if settings.google_safe_browsing_api_key:
        endpoint = (
            "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={settings.google_safe_browsing_api_key}"
        )
        payload = {
            "client": {"clientId": "threatlens-ai", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
                resp = await client.post(endpoint, json=payload)
            latency = int((time.perf_counter() - start) * 1000)

            if resp.status_code == 429:
                return _gsb_fallback(url, "RATE_LIMITED", latency, "Google Safe Browsing quota exceeded.")

            resp.raise_for_status()
            matches = resp.json().get("matches", [])
            if matches:
                threat_types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
                return (
                    EvidenceItem(
                        provider="SAFE_BROWSING",
                        category="Phishing & Malware Blocklist",
                        title=f"Google Safe Browsing Match: {', '.join(threat_types)}",
                        verdict="MALICIOUS",
                        weight=90,
                        details={"matches": matches, "threat_types": threat_types},
                        is_simulated=False,
                    ),
                    ScoreFactor(
                        factor="Google Safe Browsing Blocklist",
                        points=30,
                        max_points=30,
                        reason=f"Listed on Google Safe Browsing for {', '.join(threat_types)}.",
                        source="Google Safe Browsing v4",
                        is_simulated=False,
                    ),
                    ProviderStatus(mode="LIVE", latency_ms=latency, message="Safe Browsing v4 active"),
                )

            return (
                EvidenceItem(
                    provider="SAFE_BROWSING",
                    category="Phishing & Malware Blocklist",
                    title="Not listed on Google Safe Browsing blocklists",
                    verdict="CLEAN",
                    weight=20,
                    details={"matches": []},
                    is_simulated=False,
                ),
                ScoreFactor(
                    factor="Google Safe Browsing Blocklist",
                    points=0,
                    max_points=30,
                    reason="URL did not match active Safe Browsing threat lists.",
                    source="Google Safe Browsing v4",
                    is_simulated=False,
                ),
                ProviderStatus(mode="LIVE", latency_ms=latency, message="Safe Browsing v4 clean"),
            )
        except Exception as exc:
            latency = int((time.perf_counter() - start) * 1000)
            return _gsb_fallback(
                url, "ERROR", latency, f"Safe Browsing API error ({type(exc).__name__}); fallback active."
            )

    latency = int((time.perf_counter() - start) * 1000)
    return _gsb_fallback(
        url,
        "DEMO_FALLBACK",
        latency,
        "GOOGLE_SAFE_BROWSING_API_KEY not configured; demo blocklist heuristic active.",
    )


def _gsb_fallback(
    url: str, mode: str, latency_ms: int, note: str
) -> tuple[EvidenceItem, ScoreFactor, ProviderStatus]:
    lowered = url.lower()
    social_eng = any(
        pattern in lowered
        for pattern in (
            "microsoft-verify",
            "paypal-secure",
            "login-update",
            "account-security-check",
            "auth-session-verify",
            "phish",
            "credential-harvest",
        )
    )
    malware_flag = any(
        pattern in lowered for pattern in (".exe", ".scr", "/payload", "/dropper", "malware")
    )

    if social_eng or malware_flag:
        threat_type = "SOCIAL_ENGINEERING" if social_eng else "MALWARE"
        return (
            EvidenceItem(
                provider="SAFE_BROWSING",
                category="Phishing & Malware Blocklist (Demo Telemetry)",
                title=f"[DEMO] Flagged as {threat_type}",
                verdict="MALICIOUS",
                weight=80,
                details={"threat_type": threat_type, "platform": "ANY_PLATFORM", "note": note},
                is_simulated=True,
            ),
            ScoreFactor(
                factor="Safe Browsing Threat Match (Demo Adapter)",
                points=25,
                max_points=30,
                reason=f"Matched simulated Safe Browsing {threat_type} signature.",
                source="Google Safe Browsing (Demo Fallback)",
                is_simulated=True,
            ),
            ProviderStatus(mode=mode, latency_ms=latency_ms, message=note),
        )

    return (
        EvidenceItem(
            provider="SAFE_BROWSING",
            category="Phishing & Malware Blocklist (Demo Telemetry)",
            title="[DEMO] No Safe Browsing threat list match",
            verdict="CLEAN",
            weight=15,
            details={"matches": [], "note": note},
            is_simulated=True,
        ),
        ScoreFactor(
            factor="Safe Browsing Threat Match (Demo Adapter)",
            points=0,
            max_points=30,
            reason="No social engineering or malware signature triggered in demo blocklist.",
            source="Google Safe Browsing (Demo Fallback)",
            is_simulated=True,
        ),
        ProviderStatus(mode=mode, latency_ms=latency_ms, message=note),
    )
