from app.adapters.nvd import lookup_nvd
from app.schemas import AnalysisResponse, ExtractedRelation, ProviderStatus
from app.scoring.engine import calculate_explainable_risk


async def analyze_cve(cve_query: str) -> AnalysisResponse:
    cleaned = cve_query.strip()
    record, evidence, factors, nvd_status = await lookup_nvd(cleaned)
    canonical_id = str(record.get("cve_id", cleaned.upper()))

    provider_status: dict[str, ProviderStatus] = {
        "nvd": nvd_status,
        "heuristic_engine": ProviderStatus(mode="LIVE", latency_ms=1, message="CVSS v3.1 & KEV scorer"),
    }

    risk_score, severity, confidence, verdict, summary, ai_explanation = calculate_explainable_risk(
        "CVE", canonical_id, factors, evidence, provider_status
    )

    relations = [
        ExtractedRelation(
            source_type="CVE",
            source_value=canonical_id,
            source_label=canonical_id,
            target_type="ASSET",
            target_value=prod,
            target_label=prod,
            relation="EXPLOITS_CVE",
            confidence=90,
        )
        for prod in record.get("affected_products", [])[:3]
    ]

    return AnalysisResponse(
        indicator_type="CVE",
        target=cleaned,
        normalized_target=canonical_id,
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
        metadata=record,
    )
