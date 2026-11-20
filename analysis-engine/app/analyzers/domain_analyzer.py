import asyncio
import ipaddress
import socket

from app.adapters.otx import lookup_otx
from app.adapters.rdap import lookup_rdap
from app.adapters.virustotal import lookup_virustotal
from app.analyzers.url_analyzer import RISKY_TLDS, shannon_entropy
from app.schemas import (
    AnalysisResponse,
    EvidenceItem,
    ExtractedRelation,
    ProviderStatus,
    ScoreFactor,
)
from app.scoring.engine import calculate_explainable_risk, enrich_explanation_with_live_llm
from app.security.ssrf import validate_domain

BRAND_TARGETS = ("microsoft", "google", "paypal", "apple", "amazon", "okta", "github", "cloudflare")


def _resolve_public_ips(domain: str) -> list[str]:
    resolved: list[str] = []
    try:
        infos = socket.getaddrinfo(domain, None)
        for info in infos:
            ip_str = info[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
                if ip_str not in resolved:
                    resolved.append(ip_str)
    except Exception:
        pass
    return resolved[:6]


async def analyze_domain(raw_domain: str) -> AnalysisResponse:
    domain = validate_domain(raw_domain)

    vt_task = lookup_virustotal("domain", domain)
    otx_task = lookup_otx("domain", domain)
    rdap_task = lookup_rdap("domain", domain)
    dns_task = asyncio.to_thread(_resolve_public_ips, domain)

    (
        (vt_ev, vt_factor, vt_status),
        (otx_ev, otx_factor, otx_status),
        (rdap_meta, rdap_ev, rdap_factor, rdap_status),
        resolved_ips,
    ) = await asyncio.gather(vt_task, otx_task, rdap_task, dns_task)

    labels = domain.split(".")
    sld = labels[-2] if len(labels) >= 2 else labels[0]
    entropy = shannon_entropy(sld)

    heur_points = 0
    findings: list[str] = []

    if entropy >= 3.85 and len(sld) >= 11:
        heur_points += 18
        findings.append(f"High second-level domain entropy ({entropy} bits) indicative of DGA")

    if "xn--" in domain:
        heur_points += 18
        findings.append("IDN Punycode homograph label (xn--)")

    for tld in RISKY_TLDS:
        if domain.endswith(tld):
            heur_points += 12
            findings.append(f"Elevated-risk top-level domain ({tld})")
            break

    for brand in BRAND_TARGETS:
        if brand in domain and not domain.endswith((f"{brand}.com", f"{brand}.org", f"{brand}.net")):
            heur_points += 22
            findings.append(f"Potential brand typosquat / impersonation of '{brand}'")
            break

    if domain.count("-") >= 3:
        heur_points += 8
        findings.append("Excessive hyphenation typical of combo-squatting domains")

    heur_points = min(35, heur_points)
    verdict_flag = (
        "MALICIOUS" if heur_points >= 22 else ("SUSPICIOUS" if heur_points >= 10 else "CLEAN")
    )

    heur_ev = EvidenceItem(
        provider="HEURISTIC_ENGINE",
        category="Domain Lexical, Brand Spoofing & DNS Analysis",
        title=(
            f"{len(findings)} domain risk indicators found"
            if findings
            else "Standard domain lexical & DNS profile"
        ),
        verdict=verdict_flag,
        weight=25 + heur_points,
        details={
            "domain": domain,
            "sld_entropy": entropy,
            "resolved_ips": resolved_ips,
            "findings": findings,
        },
        is_simulated=False,
    )
    heur_factor = ScoreFactor(
        factor="DGA Entropy & Brand Typosquatting Check",
        points=heur_points,
        max_points=35,
        reason="; ".join(findings) if findings else f"Normal lexical entropy ({entropy} bits) and authentic brand structure.",
        source="Domain Forensics Engine",
        is_simulated=False,
    )

    evidence = [rdap_ev, vt_ev, otx_ev, heur_ev]
    factors = [rdap_factor, vt_factor, otx_factor, heur_factor]
    provider_status: dict[str, ProviderStatus] = {
        "rdap": rdap_status,
        "virustotal": vt_status,
        "alienvault_otx": otx_status,
        "heuristic_engine": ProviderStatus(mode="LIVE", latency_ms=2, message="DNS & DGA analyzer"),
    }

    risk_score, severity, confidence, verdict, summary, base_ai = calculate_explainable_risk(
        "DOMAIN", domain, factors, evidence, provider_status
    )
    ai_explanation = await enrich_explanation_with_live_llm(
        "DOMAIN", domain, risk_score, severity, verdict, factors, evidence, base_ai
    )

    relations = [
        ExtractedRelation(
            source_type="DOMAIN",
            source_value=domain,
            source_label=domain,
            target_type="IP",
            target_value=ip_addr,
            target_label=ip_addr,
            relation="RESOLVES_TO",
            confidence=92,
        )
        for ip_addr in resolved_ips[:4]
    ]

    return AnalysisResponse(
        indicator_type="DOMAIN",
        target=raw_domain,
        normalized_target=domain,
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
            "domain": domain,
            "entropy": entropy,
            "resolved_ips": resolved_ips,
            "findings": findings,
            "rdap": rdap_meta,
        },
    )
