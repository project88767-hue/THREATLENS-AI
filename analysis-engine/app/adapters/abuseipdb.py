import time
import httpx
from app.config import get_settings
from app.schemas import EvidenceItem, ProviderStatus, ScoreFactor

DEMO_ABUSE_PROFILES = {
    "185.220.101.45": {
        "abuseConfidenceScore": 94,
        "totalReports": 418,
        "isp": "Tor Exit Relay Network",
        "countryCode": "DE",
        "usageType": "Data Center/Web Hosting/Transit",
        "categories": ["SSH Brute-Force", "Port Scan", "Web App Attack"],
    },
    "45.95.147.22": {
        "abuseConfidenceScore": 98,
        "totalReports": 612,
        "isp": "Bulletproof Hosting ASN",
        "countryCode": "NL",
        "usageType": "Data Center/Web Hosting/Transit",
        "categories": ["C2 Callback", "Malware Distribution", "Exploit Attempt"],
    },
    "91.92.240.58": {
        "abuseConfidenceScore": 89,
        "totalReports": 193,
        "isp": "Offshore Cloud VPS",
        "countryCode": "BG",
        "usageType": "Data Center/Web Hosting/Transit",
        "categories": ["Phishing Hosting", "Botnet C2"],
    },
    "203.0.113.99": {
        "abuseConfidenceScore": 82,
        "totalReports": 74,
        "isp": "TEST-NET-3 Documentation Lab",
        "countryCode": "US",
        "usageType": "Reserved / Security Lab Demo",
        "categories": ["Credential Stuffing", "Automated Recon"],
    },
    "8.8.8.8": {
        "abuseConfidenceScore": 0,
        "totalReports": 2,
        "isp": "Google LLC",
        "countryCode": "US",
        "usageType": "Content Delivery Network / DNS",
        "categories": [],
    },
    "1.1.1.1": {
        "abuseConfidenceScore": 0,
        "totalReports": 1,
        "isp": "Cloudflare, Inc.",
        "countryCode": "AU",
        "usageType": "Content Delivery Network / DNS",
        "categories": [],
    },
}


async def lookup_abuseipdb(
    ip: str,
) -> tuple[EvidenceItem, ScoreFactor, ProviderStatus]:
    settings = get_settings()
    start = time.perf_counter()

    if settings.abuseipdb_api_key and settings.enable_live_public_lookups:
        headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
        try:
            async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers=headers,
                    params=params,
                )
            latency = int((time.perf_counter() - start) * 1000)

            if resp.status_code == 429:
                return _abuse_fallback(ip, "RATE_LIMITED", latency, "AbuseIPDB daily quota exceeded.")

            resp.raise_for_status()
            data = resp.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            reports = int(data.get("totalReports", 0))
            points = round((score / 100) * 40)
            verdict = "MALICIOUS" if score >= 70 else ("SUSPICIOUS" if score >= 25 else "CLEAN")

            return (
                EvidenceItem(
                    provider="ABUSEIPDB",
                    category="IP Abuse Telemetry",
                    title=f"AbuseIPDB Confidence: {score}% ({reports} community reports)",
                    verdict=verdict,
                    weight=max(15, score),
                    details={
                        "abuseConfidenceScore": score,
                        "totalReports": reports,
                        "isp": data.get("isp") or "Unknown ISP",
                        "countryCode": data.get("countryCode") or "UN",
                        "usageType": data.get("usageType") or "Unknown",
                        "domain": data.get("domain") or "",
                        "isTor": bool(data.get("isTor", False)),
                    },
                    is_simulated=False,
                ),
                ScoreFactor(
                    factor="AbuseIPDB Abuse Confidence",
                    points=points,
                    max_points=40,
                    reason=f"Abuse confidence score is {score}% across {reports} recent reports.",
                    source="AbuseIPDB v2",
                    is_simulated=False,
                ),
                ProviderStatus(mode="LIVE", latency_ms=latency, message="Live AbuseIPDB v2 check"),
            )
        except Exception as exc:
            latency = int((time.perf_counter() - start) * 1000)
            return _abuse_fallback(
                ip, "ERROR", latency, f"AbuseIPDB error ({type(exc).__name__}); using fallback."
            )

    latency = int((time.perf_counter() - start) * 1000)
    return _abuse_fallback(
        ip,
        "DEMO_FALLBACK",
        latency,
        "ABUSEIPDB_API_KEY not configured; simulated SOC telemetry active.",
    )


def _abuse_fallback(
    ip: str, mode: str, latency_ms: int, note: str
) -> tuple[EvidenceItem, ScoreFactor, ProviderStatus]:
    profile = DEMO_ABUSE_PROFILES.get(
        ip,
        {
            "abuseConfidenceScore": 12 if ip.startswith(("185.", "45.", "91.")) else 0,
            "totalReports": 5 if ip.startswith(("185.", "45.", "91.")) else 0,
            "isp": "Global Transit Provider (Demo Profile)",
            "countryCode": "US",
            "usageType": "Commercial / ISP",
            "categories": ["Opportunistic Scan"] if ip.startswith(("185.", "45.", "91.")) else [],
        },
    )
    score = int(profile["abuseConfidenceScore"])
    reports = int(profile["totalReports"])
    points = round((score / 100) * 40)
    verdict = "MALICIOUS" if score >= 70 else ("SUSPICIOUS" if score >= 25 else "CLEAN")

    return (
        EvidenceItem(
            provider="ABUSEIPDB",
            category="IP Abuse Telemetry (Demo Telemetry)",
            title=f"[DEMO] Abuse Confidence: {score}% ({reports} reports)",
            verdict=verdict,
            weight=max(15, score),
            details={**profile, "note": note},
            is_simulated=True,
        ),
        ScoreFactor(
            factor="AbuseIPDB Abuse Confidence (Demo Adapter)",
            points=points,
            max_points=40,
            reason=(
                f"Simulated abuse confidence {score}% with {reports} community abuse reports."
                if score > 0
                else "0% abuse confidence in simulated baseline."
            ),
            source="AbuseIPDB (Demo Fallback)",
            is_simulated=True,
        ),
        ProviderStatus(mode=mode, latency_ms=latency_ms, message=note),
    )
