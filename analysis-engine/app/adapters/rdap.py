from datetime import datetime, timezone
import time
from typing import Any
import httpx
from app.config import get_settings
from app.schemas import EvidenceItem, ProviderStatus, ScoreFactor


async def lookup_rdap(
    kind: str, value: str
) -> tuple[dict[str, Any], EvidenceItem, ScoreFactor, ProviderStatus]:
    """
    Queries public RDAP bootstrap (rdap.org) for domain registration age/registrar or IP network allocation.
    """
    settings = get_settings()
    start = time.perf_counter()

    if settings.enable_live_public_lookups:
        endpoint = f"https://rdap.org/{'domain' if kind == 'domain' else 'ip'}/{value}"
        try:
            async with httpx.AsyncClient(
                timeout=settings.http_timeout_seconds, follow_redirects=True
            ) as client:
                resp = await client.get(endpoint, headers={"Accept": "application/rdap+json, application/json"})
            latency = int((time.perf_counter() - start) * 1000)

            if resp.status_code == 200:
                data = resp.json()
                if kind == "domain":
                    return _parse_domain_rdap(value, data, latency)
                return _parse_ip_rdap(value, data, latency)
        except Exception:
            pass

    latency = int((time.perf_counter() - start) * 1000)
    return _rdap_fallback(kind, value, latency)


def _parse_domain_rdap(
    domain: str, data: dict[str, Any], latency_ms: int
) -> tuple[dict[str, Any], EvidenceItem, ScoreFactor, ProviderStatus]:
    events = data.get("events", [])
    reg_date = None
    exp_date = None
    for event in events:
        action = event.get("eventAction", "")
        dt = event.get("eventDate")
        if action == "registration" and dt:
            reg_date = dt
        elif action == "expiration" and dt:
            exp_date = dt

    age_days: int | None = None
    if reg_date:
        try:
            parsed_dt = datetime.fromisoformat(reg_date.replace("Z", "+00:00"))
            age_days = max(0, (datetime.now(timezone.utc) - parsed_dt).days)
        except Exception:
            age_days = None

    nameservers = [
        ns.get("ldhName", "").lower()
        for ns in data.get("nameservers", [])
        if ns.get("ldhName")
    ][:6]

    registrar = "Unknown Registrar"
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for row in vcard[1]:
                    if isinstance(row, list) and len(row) >= 4 and row[0] == "fn":
                        registrar = str(row[3])
                        break

    statuses = data.get("status", [])
    nrd_risk = age_days is not None and age_days < 45
    points = 22 if (age_days is not None and age_days < 14) else (14 if nrd_risk else 0)
    verdict = "MALICIOUS" if points >= 20 else ("SUSPICIOUS" if points > 0 else "INFO")

    meta = {
        "handle": data.get("handle", ""),
        "registrar": registrar,
        "registered_at": reg_date or "Unknown",
        "expires_at": exp_date or "Unknown",
        "domain_age_days": age_days,
        "nameservers": nameservers,
        "status": statuses,
    }
    title = (
        f"Newly Registered Domain ({age_days} days old) via {registrar}"
        if nrd_risk
        else f"RDAP Registration: {registrar} ({age_days if age_days is not None else '?'} days old)"
    )
    return (
        meta,
        EvidenceItem(
            provider="RDAP",
            category="Domain Registration & WHOIS",
            title=title,
            verdict=verdict,
            weight=30 + points,
            details=meta,
            is_simulated=False,
        ),
        ScoreFactor(
            factor="Domain Age (RDAP Newly Registered Check)",
            points=points,
            max_points=25,
            reason=(
                f"Domain was registered {age_days} days ago (<45 day NRD threshold)."
                if nrd_risk
                else f"Established domain registration ({age_days if age_days is not None else 'verified'} days)."
            ),
            source="RDAP Public Registry",
            is_simulated=False,
        ),
        ProviderStatus(mode="PUBLIC_LIVE", latency_ms=latency_ms, message="Live RDAP registry lookup"),
    )


def _parse_ip_rdap(
    ip: str, data: dict[str, Any], latency_ms: int
) -> tuple[dict[str, Any], EvidenceItem, ScoreFactor, ProviderStatus]:
    meta = {
        "network_name": data.get("name") or "Unknown Network",
        "handle": data.get("handle") or "",
        "country": data.get("country") or "UN",
        "start_address": data.get("startAddress") or "",
        "end_address": data.get("endAddress") or "",
        "type": data.get("type") or "ALLOCATED",
    }
    return (
        meta,
        EvidenceItem(
            provider="RDAP",
            category="IP Network Allocation",
            title=f"RDAP Network Block: {meta['network_name']} ({meta['country']})",
            verdict="INFO",
            weight=20,
            details=meta,
            is_simulated=False,
        ),
        ScoreFactor(
            factor="RDAP Network Allocation",
            points=0,
            max_points=10,
            reason=f"Allocated network block {meta['network_name']} ({meta['handle']}).",
            source="RDAP RIR Registry",
            is_simulated=False,
        ),
        ProviderStatus(mode="PUBLIC_LIVE", latency_ms=latency_ms, message="Live RIR RDAP lookup"),
    )


def _rdap_fallback(
    kind: str, value: str, latency_ms: int
) -> tuple[dict[str, Any], EvidenceItem, ScoreFactor, ProviderStatus]:
    lowered = value.lower()
    if kind == "domain":
        is_suspicious = any(
            marker in lowered
            for marker in (".xyz", ".tk", ".top", "verify", "secure-login", "auth-", "update-")
        )
        age_days = 6 if is_suspicious else 1420
        registrar = "NameCheap / PrivacyGuard (Demo Profile)" if is_suspicious else "CSC Corporate Domains (Demo Profile)"
        points = 20 if is_suspicious else 0
        meta = {
            "registrar": registrar,
            "registered_at": "2026-11-13T09:12:00Z" if is_suspicious else "2022-12-01T00:00:00Z",
            "domain_age_days": age_days,
            "nameservers": ["ns1.fastflux-dns.example", "ns2.fastflux-dns.example"]
            if is_suspicious
            else ["ns1.enterprise-dns.net", "ns2.enterprise-dns.net"],
            "status": ["clientTransferProhibited"],
        }
        return (
            meta,
            EvidenceItem(
                provider="RDAP",
                category="Domain Registration & WHOIS (Demo Telemetry)",
                title=(
                    f"[DEMO] Newly Registered Domain ({age_days} days old)"
                    if is_suspicious
                    else f"[DEMO] Established Domain ({age_days} days old)"
                ),
                verdict="SUSPICIOUS" if is_suspicious else "INFO",
                weight=25 + points,
                details=meta,
                is_simulated=True,
            ),
            ScoreFactor(
                factor="Domain Registration Age (Demo RDAP)",
                points=points,
                max_points=25,
                reason=(
                    f"Simulated NRD profile indicates recent registration ({age_days} days old)."
                    if is_suspicious
                    else "Established registration profile."
                ),
                source="RDAP (Demo Fallback)",
                is_simulated=True,
            ),
            ProviderStatus(
                mode="DEMO_FALLBACK",
                latency_ms=latency_ms,
                message="RDAP registry unreachable or domain TLD unsupported; demo profile returned.",
            ),
        )

    meta = {
        "network_name": "OFFSHORE-HOSTING-NET" if value.startswith(("185.", "45.", "91.")) else "GLOBAL-CLOUD-NET",
        "handle": f"NET-{value.replace('.', '-')}",
        "country": "NL" if value.startswith("45.") else "US",
        "type": "ALLOCATED PA",
    }
    return (
        meta,
        EvidenceItem(
            provider="RDAP",
            category="IP Network Allocation (Demo Telemetry)",
            title=f"[DEMO] Network Block: {meta['network_name']} ({meta['country']})",
            verdict="INFO",
            weight=15,
            details=meta,
            is_simulated=True,
        ),
        ScoreFactor(
            factor="RDAP Network Allocation (Demo)",
            points=0,
            max_points=10,
            reason=f"Network registration block {meta['network_name']}.",
            source="RDAP (Demo Fallback)",
            is_simulated=True,
        ),
        ProviderStatus(
            mode="DEMO_FALLBACK",
            latency_ms=latency_ms,
            message="RDAP offline or unregistered block; demo allocation returned.",
        ),
    )
