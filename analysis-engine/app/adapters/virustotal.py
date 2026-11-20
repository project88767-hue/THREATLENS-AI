import base64
import time
import httpx
from app.config import get_settings
from app.schemas import EvidenceItem, ProviderStatus, ScoreFactor

KNOWN_SUSPICIOUS_KEYWORDS = (
    "login",
    "verify",
    "secure",
    "account-update",
    "wallet",
    "confirm",
    "credential",
    "phish",
    "malware",
    "stealer",
    "payload",
    "c2",
    "dropper",
)

KNOWN_BAD_IPS = {
    "185.220.101.45": ("Tor Exit / C2 Relay", 14),
    "45.95.147.22": ("Cobalt Strike C2 Beacon Host", 22),
    "91.92.240.58": ("AsyncRAT Command Server", 19),
    "203.0.113.99": ("Demo Lab Malicious Scanner IP", 16),
}


async def lookup_virustotal(
    kind: str, value: str
) -> tuple[EvidenceItem, ScoreFactor, ProviderStatus]:
    """
    Queries VirusTotal v3 API for url, domain, or ip_address.
    Falls back gracefully to clearly-labelled heuristic demo telemetry if no API key is configured.
    """
    settings = get_settings()
    start = time.perf_counter()

    if settings.virustotal_api_key:
        headers = {"x-apikey": settings.virustotal_api_key}
        if kind == "url":
            url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        elif kind == "domain":
            endpoint = f"https://www.virustotal.com/api/v3/domains/{value}"
        else:
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"

        try:
            async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
                resp = await client.get(endpoint, headers=headers)
            latency = int((time.perf_counter() - start) * 1000)

            if resp.status_code == 429:
                return _vt_fallback(
                    kind,
                    value,
                    mode="RATE_LIMITED",
                    latency_ms=latency,
                    note="VirusTotal API rate limit reached; using heuristic fallback.",
                )

            if resp.status_code == 404:
                return (
                    EvidenceItem(
                        provider="VIRUSTOTAL",
                        category="Multi-Engine Reputation",
                        title="No prior VirusTotal detections on record",
                        verdict="INFO",
                        weight=10,
                        details={"status": "unseen_indicator", "malicious": 0, "suspicious": 0},
                        is_simulated=False,
                    ),
                    ScoreFactor(
                        factor="VirusTotal Reputation",
                        points=0,
                        max_points=30,
                        reason="Indicator has no malicious detections in VirusTotal.",
                        source="VirusTotal v3",
                        is_simulated=False,
                    ),
                    ProviderStatus(mode="LIVE", latency_ms=latency, message="VT v3 queried (404 unseen)"),
                )

            resp.raise_for_status()
            stats = (
                resp.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            points = min(35, malicious * 5 + suspicious * 2)
            verdict = "MALICIOUS" if malicious >= 3 else ("SUSPICIOUS" if (malicious + suspicious) >= 1 else "CLEAN")

            return (
                EvidenceItem(
                    provider="VIRUSTOTAL",
                    category="Multi-Engine Reputation",
                    title=f"VirusTotal Engines: {malicious} malicious, {suspicious} suspicious",
                    verdict=verdict,
                    weight=min(100, 35 + points),
                    details={
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": int(stats.get("undetected", 0)),
                    },
                    is_simulated=False,
                ),
                ScoreFactor(
                    factor="VirusTotal Multi-Engine Hits",
                    points=points,
                    max_points=35,
                    reason=f"{malicious} security vendors flagged this {kind} as malicious ({suspicious} suspicious).",
                    source="VirusTotal v3",
                    is_simulated=False,
                ),
                ProviderStatus(mode="LIVE", latency_ms=latency, message="Live VirusTotal v3 telemetry"),
            )
        except Exception as exc:
            latency = int((time.perf_counter() - start) * 1000)
            return _vt_fallback(
                kind,
                value,
                mode="ERROR",
                latency_ms=latency,
                note=f"VirusTotal live request failed ({type(exc).__name__}); using fallback.",
            )

    latency = int((time.perf_counter() - start) * 1000)
    return _vt_fallback(
        kind,
        value,
        mode="DEMO_FALLBACK",
        latency_ms=latency,
        note="VIRUSTOTAL_API_KEY not configured; simulated demo adapter active.",
    )


def _vt_fallback(
    kind: str, value: str, mode: str, latency_ms: int, note: str
) -> tuple[EvidenceItem, ScoreFactor, ProviderStatus]:
    lowered = value.lower()
    hits = sum(1 for kw in KNOWN_SUSPICIOUS_KEYWORDS if kw in lowered)

    if kind == "ip" and value in KNOWN_BAD_IPS:
        label, engines = KNOWN_BAD_IPS[value]
        points = 28
        return (
            EvidenceItem(
                provider="VIRUSTOTAL",
                category="Multi-Engine Reputation (Demo Telemetry)",
                title=f"[DEMO] {engines}/92 engines flagged IP ({label})",
                verdict="MALICIOUS",
                weight=82,
                details={
                    "malicious": engines,
                    "suspicious": 4,
                    "harmless": 58,
                    "demo_classification": label,
                    "note": note,
                },
                is_simulated=True,
            ),
            ScoreFactor(
                factor="VirusTotal Reputation (Demo Adapter)",
                points=points,
                max_points=35,
                reason=f"Simulated multi-engine match ({engines} vendors): {label}.",
                source="VirusTotal (Demo Fallback)",
                is_simulated=True,
            ),
            ProviderStatus(mode=mode, latency_ms=latency_ms, message=note),
        )

    if hits >= 2 or any(tld in lowered for tld in (".tk", ".xyz", ".top", ".zip", "xn--")):
        malicious = min(18, 4 + hits * 3)
        points = min(30, 12 + hits * 6)
        verdict = "MALICIOUS" if malicious >= 8 else "SUSPICIOUS"
    elif hits == 1:
        malicious = 2
        points = 10
        verdict = "SUSPICIOUS"
    else:
        malicious = 0
        points = 0
        verdict = "CLEAN"

    return (
        EvidenceItem(
            provider="VIRUSTOTAL",
            category="Multi-Engine Reputation (Demo Telemetry)",
            title=f"[DEMO] {malicious}/92 security vendors flagged indicator",
            verdict=verdict,
            weight=25 + points,
            details={
                "malicious": malicious,
                "suspicious": 1 if hits == 1 else 0,
                "harmless": 88 - malicious,
                "note": note,
            },
            is_simulated=True,
        ),
        ScoreFactor(
            factor="VirusTotal Reputation (Demo Adapter)",
            points=points,
            max_points=35,
            reason=(
                f"Demo reputation profile flagged {malicious} engines based on threat pattern signatures."
                if points > 0
                else "No malicious vendor hits in demo reputation baseline."
            ),
            source="VirusTotal (Demo Fallback)",
            is_simulated=True,
        ),
        ProviderStatus(mode=mode, latency_ms=latency_ms, message=note),
    )
