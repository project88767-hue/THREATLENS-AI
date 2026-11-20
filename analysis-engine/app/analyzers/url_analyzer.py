import asyncio
import math
from urllib.parse import urlparse

from app.adapters.otx import lookup_otx
from app.adapters.rdap import lookup_rdap
from app.adapters.safe_browsing import lookup_safe_browsing
from app.adapters.virustotal import lookup_virustotal
from app.schemas import (
    AnalysisResponse,
    EvidenceItem,
    ExtractedRelation,
    ProviderStatus,
    ScoreFactor,
)
from app.scoring.engine import calculate_explainable_risk
from app.security.ssrf import validate_and_normalize_url

RISKY_TLDS = {".xyz", ".top", ".tk", ".zip", ".mov", ".click", ".gq", ".ml", ".cf", ".work"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "cutt.ly"}
PHISH_LURES = (
    "login",
    "signin",
    "verify",
    "secure",
    "update",
    "password",
    "credential",
    "microsoft",
    "paypal",
    "office365",
    "banking",
    "wallet",
    "invoice",
)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 2)


async def analyze_url(raw_url: str) -> AnalysisResponse:
    normalized_url, hostname, ip_literal = validate_and_normalize_url(raw_url)
    parsed = urlparse(normalized_url)

    # Run external intelligence adapters concurrently
    vt_task = lookup_virustotal("url", normalized_url)
    gsb_task = lookup_safe_browsing(normalized_url)
    otx_task = lookup_otx("url", normalized_url)
    rdap_task = lookup_rdap("ip" if ip_literal else "domain", ip_literal or hostname)

    (vt_ev, vt_factor, vt_status), (gsb_ev, gsb_factor, gsb_status), (
        otx_ev,
        otx_factor,
        otx_status,
    ), (rdap_meta, rdap_ev, rdap_factor, rdap_status) = await asyncio.gather(
        vt_task, gsb_task, otx_task, rdap_task
    )

    # Local lexical & structural phishing analysis
    lexical_points = 0
    anomalies: list[str] = []

    if parsed.scheme == "http":
        lexical_points += 8
        anomalies.append("Unencrypted HTTP transport (no TLS)")

    if ip_literal:
        lexical_points += 20
        anomalies.append(f"Raw IP address host ({ip_literal}) instead of domain name")

    if "xn--" in hostname:
        lexical_points += 18
        anomalies.append("Punycode IDN homograph prefix (xn--) detected")

    for tld in RISKY_TLDS:
        if hostname.endswith(tld):
            lexical_points += 12
            anomalies.append(f"High-abuse TLD ({tld})")
            break

    if hostname in SHORTENERS:
        lexical_points += 10
        anomalies.append("URL shortener obscures destination host")

    subdomain_depth = max(0, hostname.count(".") - 1)
    if subdomain_depth >= 3:
        lexical_points += 10
        anomalies.append(f"Deep subdomain nesting ({subdomain_depth} levels)")

    matched_lures = [kw for kw in PHISH_LURES if kw in normalized_url.lower()]
    if len(matched_lures) >= 2:
        lexical_points += 16
        anomalies.append(f"Credential lure keywords ({', '.join(matched_lures[:4])})")
    elif len(matched_lures) == 1:
        lexical_points += 6
        anomalies.append(f"Sensitive path/host keyword ({matched_lures[0]})")

    if "@" in raw_url:
        lexical_points += 20
        anomalies.append("Embedded '@' userinfo obfuscation in URL")

    entropy = shannon_entropy(hostname.split(".")[0])
    if entropy >= 3.9 and len(hostname.split(".")[0]) >= 12:
        lexical_points += 10
        anomalies.append(f"High host label entropy ({entropy} bits - potential DGA/randomization)")

    lexical_points = min(35, lexical_points)
    lexical_verdict = (
        "MALICIOUS" if lexical_points >= 24 else ("SUSPICIOUS" if lexical_points >= 10 else "CLEAN")
    )

    lexical_ev = EvidenceItem(
        provider="HEURISTIC_ENGINE",
        category="Lexical & Structural URL Forensics",
        title=(
            f"{len(anomalies)} structural phishing/URL anomalies detected"
            if anomalies
            else "Clean URL structure and TLS posture"
        ),
        verdict=lexical_verdict,
        weight=25 + lexical_points,
        details={
            "scheme": parsed.scheme,
            "hostname": hostname,
            "path": parsed.path or "/",
            "subdomain_depth": subdomain_depth,
            "host_entropy": entropy,
            "anomalies": anomalies,
            "matched_lures": matched_lures,
        },
        is_simulated=False,
    )

    lexical_factor = ScoreFactor(
        factor="Lexical Phishing & URL Structure",
        points=lexical_points,
        max_points=35,
        reason="; ".join(anomalies[:3]) if anomalies else "Standard HTTPS URL structure with no phishing lures.",
        source="THREATLENS Lexical Engine",
        is_simulated=False,
    )

    evidence = [lexical_ev, vt_ev, gsb_ev, otx_ev, rdap_ev]
    factors = [lexical_factor, vt_factor, gsb_factor, otx_factor, rdap_factor]
    provider_status: dict[str, ProviderStatus] = {
        "heuristic_engine": ProviderStatus(mode="LIVE", latency_ms=1, message="Local lexical engine"),
        "virustotal": vt_status,
        "safe_browsing": gsb_status,
        "alienvault_otx": otx_status,
        "rdap": rdap_status,
    }

    risk_score, severity, confidence, verdict, summary, ai_explanation = calculate_explainable_risk(
        "URL", normalized_url, factors, evidence, provider_status
    )

    relations = [
        ExtractedRelation(
            source_type="URL",
            source_value=normalized_url,
            source_label=normalized_url[:42],
            target_type="IP" if ip_literal else "DOMAIN",
            target_value=ip_literal or hostname,
            target_label=ip_literal or hostname,
            relation="HOSTED_ON",
            confidence=95,
        )
    ]

    return AnalysisResponse(
        indicator_type="URL",
        target=raw_url,
        normalized_target=normalized_url,
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
            "hostname": hostname,
            "scheme": parsed.scheme,
            "path": parsed.path or "/",
            "entropy": entropy,
            "anomalies": anomalies,
            "rdap": rdap_meta,
        },
    )
