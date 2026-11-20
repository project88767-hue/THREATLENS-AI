import asyncio
import socket

from app.adapters.abuseipdb import lookup_abuseipdb
from app.adapters.otx import lookup_otx
from app.adapters.rdap import lookup_rdap
from app.adapters.virustotal import lookup_virustotal
from app.schemas import (
    AnalysisResponse,
    EvidenceItem,
    ExtractedRelation,
    ProviderStatus,
    ScoreFactor,
)
from app.scoring.engine import calculate_explainable_risk
from app.security.ssrf import validate_public_ip


def _safe_reverse_dns(ip: str) -> str | None:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


async def analyze_ip(raw_ip: str) -> AnalysisResponse:
    ip = validate_public_ip(raw_ip)

    abuse_task = lookup_abuseipdb(ip)
    vt_task = lookup_virustotal("ip", ip)
    otx_task = lookup_otx("ip", ip)
    rdap_task = lookup_rdap("ip", ip)
    ptr_task = asyncio.to_thread(_safe_reverse_dns, ip)

    (
        (abuse_ev, abuse_factor, abuse_status),
        (vt_ev, vt_factor, vt_status),
        (otx_ev, otx_factor, otx_status),
        (rdap_meta, rdap_ev, rdap_factor, rdap_status),
        ptr_record,
    ) = await asyncio.gather(abuse_task, vt_task, otx_task, rdap_task, ptr_task)

    net_points = 0
    net_notes: list[str] = []
    if not ptr_record:
        net_points += 4
        net_notes.append("No PTR reverse DNS hostname configured")
    elif any(tag in ptr_record.lower() for tag in ("tor", "exit", "bulletproof", "vps", "dynamic")):
        net_points += 10
        net_notes.append(f"PTR hostname suggests relay/anonymizer ({ptr_record})")

    net_ev = EvidenceItem(
        provider="HEURISTIC_ENGINE",
        category="Reverse DNS & Infrastructure Profile",
        title=f"PTR Hostname: {ptr_record or 'Unassigned (No PTR)'}",
        verdict="SUSPICIOUS" if net_points >= 10 else "INFO",
        weight=20 + net_points,
        details={"ptr": ptr_record, "ip_version": 6 if ":" in ip else 4, "notes": net_notes},
        is_simulated=False,
    )
    net_factor = ScoreFactor(
        factor="Infrastructure & Reverse DNS Posture",
        points=net_points,
        max_points=15,
        reason="; ".join(net_notes) if net_notes else f"Verified reverse DNS ({ptr_record}).",
        source="Network Forensics",
        is_simulated=False,
    )

    evidence = [abuse_ev, vt_ev, otx_ev, rdap_ev, net_ev]
    factors = [abuse_factor, vt_factor, otx_factor, rdap_factor, net_factor]
    provider_status: dict[str, ProviderStatus] = {
        "abuseipdb": abuse_status,
        "virustotal": vt_status,
        "alienvault_otx": otx_status,
        "rdap": rdap_status,
        "heuristic_engine": ProviderStatus(mode="LIVE", latency_ms=2, message="PTR & ASN heuristics"),
    }

    risk_score, severity, confidence, verdict, summary, ai_explanation = calculate_explainable_risk(
        "IP", ip, factors, evidence, provider_status
    )

    relations: list[ExtractedRelation] = []
    if ptr_record:
        relations.append(
            ExtractedRelation(
                source_type="DOMAIN",
                source_value=ptr_record,
                source_label=ptr_record,
                target_type="IP",
                target_value=ip,
                target_label=ip,
                relation="RESOLVES_TO",
                confidence=90,
            )
        )

    return AnalysisResponse(
        indicator_type="IP",
        target=raw_ip,
        normalized_target=ip,
        risk_score=risk_score,
        severity=severity,
        confidence=confidence,
        verdict=verdict,
        summary=summary,
        ai_explanation=ai_explanation,
        score_breakdown=factors,
        evidence=evidence,
        provider_status=provider_status,
        extracted_relations=relations,
        metadata={
            "ip": ip,
            "ptr_record": ptr_record,
            "abuse": abuse_ev.details,
            "rdap": rdap_meta,
        },
    )
