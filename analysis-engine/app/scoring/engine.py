import json
import httpx
from app.config import get_settings
from app.schemas import (
    AiExplanation,
    EvidenceItem,
    IndicatorType,
    MitreTechnique,
    ProviderStatus,
    ScoreFactor,
    SeverityLevel,
)


def severity_from_score(score: int) -> SeverityLevel:
    if score >= 85:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def verdict_from_score(score: int) -> str:
    if score >= 65:
        return "MALICIOUS"
    if score >= 30:
        return "SUSPICIOUS"
    return "CLEAN"


def default_mitre_for_indicator(
    indicator_type: IndicatorType, score: int, evidence: list[EvidenceItem]
) -> list[MitreTechnique]:
    if score < 25:
        return []

    techniques: list[MitreTechnique] = []
    titles_blob = " ".join(f"{e.title} {e.category}".lower() for e in evidence)

    if indicator_type == "URL":
        techniques.append(
            MitreTechnique(
                id="T1566.002",
                name="Phishing: Spearphishing Link",
                tactic="Initial Access",
            )
        )
        if "credential" in titles_blob or "login" in titles_blob or "spoof" in titles_blob:
            techniques.append(
                MitreTechnique(
                    id="T1598.003",
                    name="Phishing for Information: Spearphishing Link",
                    tactic="Reconnaissance",
                )
            )
    elif indicator_type == "EMAIL":
        techniques.append(
            MitreTechnique(
                id="T1566.001",
                name="Phishing: Spearphishing Attachment / BEC",
                tactic="Initial Access",
            )
        )
        if "spf" in titles_blob or "dmarc" in titles_blob or "spoof" in titles_blob:
            techniques.append(
                MitreTechnique(
                    id="T1656",
                    name="Impersonation",
                    tactic="Defense Evasion",
                )
            )
    elif indicator_type == "IP":
        techniques.append(
            MitreTechnique(
                id="T1071.001",
                name="Application Layer Protocol: Web Protocols (C2)",
                tactic="Command and Control",
            )
        )
        techniques.append(
            MitreTechnique(
                id="T1595",
                name="Active Scanning / Brute Force Telemetry",
                tactic="Reconnaissance",
            )
        )
    elif indicator_type == "DOMAIN":
        techniques.append(
            MitreTechnique(
                id="T1583.001",
                name="Acquire Infrastructure: Domains",
                tactic="Resource Development",
            )
        )
        if "entropy" in titles_blob or "dga" in titles_blob:
            techniques.append(
                MitreTechnique(
                    id="T1568.002",
                    name="Dynamic Resolution: Domain Generation Algorithms",
                    tactic="Command and Control",
                )
            )
    elif indicator_type == "CVE":
        techniques.append(
            MitreTechnique(
                id="T1190",
                name="Exploit Public-Facing Application",
                tactic="Initial Access",
            )
        )
        if score >= 75:
            techniques.append(
                MitreTechnique(
                    id="T1203",
                    name="Exploitation for Client / Server Execution",
                    tactic="Execution",
                )
            )

    return techniques


def default_recommendations(indicator_type: IndicatorType, score: int, target: str) -> list[str]:
    if score < 30:
        return [
            f"No immediate containment required for {target}; retain telemetry in baseline logs.",
            "Continue routine monitoring via SIEM and DNS/Proxy security policies.",
        ]

    if indicator_type == "URL":
        actions = [
            "Block the URL and parent domain at Secure Web Gateway (SWG) and DNS sinkhole.",
            "Search proxy, browser, and EDR telemetry for any endpoints that requested this URL.",
            "Reset credentials and revoke active OAuth/session tokens for any user who interacted with the link.",
        ]
    elif indicator_type == "EMAIL":
        actions = [
            "Quarantine matching messages across all mailboxes by Message-ID, Sender, and Subject.",
            "Enforce strict DMARC (p=reject) and banner warnings for external display-name impersonation.",
            "Inspect any clicked links or opened attachments inside an isolated sandbox.",
        ]
    elif indicator_type == "IP":
        actions = [
            f"Add {target} to perimeter firewall / WAF deny-lists if unauthorized inbound or outbound traffic is observed.",
            "Query NetFlow, VPN, and authentication logs for historical connections involving this IP.",
            "Correlate associated ASN and SSL certificate fingerprints for sibling infrastructure.",
        ]
    elif indicator_type == "DOMAIN":
        actions = [
            f"Enforce DNS RPZ / protective DNS blocking for {target} and newly registered lookalike domains.",
            "Monitor passive DNS and certificate transparency logs for related subdomains.",
            "Hunt email gateway logs for inbound messages referencing this domain.",
        ]
    else:  # CVE
        actions = [
            f"Inventory all assets running affected software versions linked to {target}.",
            "Prioritize vendor patch deployment within emergency SLA window for internet-facing systems.",
            "Apply virtual patching / WAF signatures and restrict network exposure until patched.",
        ]

    if score >= 80:
        actions.insert(
            0,
            "ESCALATE IMMEDIATELY: Create a High/Critical SOC Incident and initiate containment playbook.",
        )
    return actions


def calculate_explainable_risk(
    indicator_type: IndicatorType,
    target: str,
    factors: list[ScoreFactor],
    evidence: list[EvidenceItem],
    provider_status: dict[str, ProviderStatus],
) -> tuple[int, SeverityLevel, int, str, str, AiExplanation]:
    raw_points = sum(max(0, f.points) for f in factors)
    risk_score = min(100, max(0, raw_points))

    malicious_count = sum(1 for e in evidence if e.verdict == "MALICIOUS")
    if malicious_count >= 2 and risk_score < 75:
        risk_score = 75
    elif malicious_count == 1 and risk_score < 55:
        risk_score = 55

    severity = severity_from_score(risk_score)
    verdict = verdict_from_score(risk_score)

    total_providers = max(1, len(provider_status))
    live_count = sum(
        1 for p in provider_status.values() if p.mode in ("LIVE", "PUBLIC_LIVE")
    )
    error_count = sum(1 for p in provider_status.values() if p.mode == "ERROR")
    base_confidence = 68 + int((live_count / total_providers) * 24) - (error_count * 6)
    if len(evidence) >= 4:
        base_confidence += 5
    confidence = min(98, max(40, base_confidence))

    flagged_reasons = [
        f"{f.factor} (+{f.points} pts): {f.reason}"
        for f in sorted(factors, key=lambda item: item.points, reverse=True)
        if f.points > 0
    ]
    if not flagged_reasons:
        flagged_reasons = [
            "No high-risk signatures, reputation hits, or structural anomalies were detected across active analyzers."
        ]

    summary = (
        f"{indicator_type} indicator '{target}' evaluated as {verdict} "
        f"with an explainable risk score of {risk_score}/100 ({severity} severity, {confidence}% confidence)."
    )

    overview = (
        f"THREATLENS AI correlated {len(evidence)} intelligence artifacts across {len(provider_status)} "
        f"modules for '{target}'. "
    )
    if risk_score >= 70:
        overview += (
            "Multiple high-confidence threat signals indicate active malicious behavior or high exploitation risk. "
            "Immediate analyst triage and defensive containment are recommended."
        )
    elif risk_score >= 30:
        overview += (
            "Moderate risk anomalies or suspicious reputation traits were observed. "
            "Verify business legitimacy before permitting access."
        )
    else:
        overview += (
            "Telemetry indicates benign posture with no known threat intelligence matches at scan time."
        )

    ai_explanation = AiExplanation(
        overview=overview,
        why_flagged=flagged_reasons[:6],
        mitre_techniques=default_mitre_for_indicator(indicator_type, risk_score, evidence),
        recommended_actions=default_recommendations(indicator_type, risk_score, target),
        is_simulated_ai=True,
    )

    return risk_score, severity, confidence, verdict, summary, ai_explanation


async def enrich_explanation_with_live_llm(
    indicator_type: IndicatorType,
    target: str,
    risk_score: int,
    severity: SeverityLevel,
    verdict: str,
    factors: list[ScoreFactor],
    evidence: list[EvidenceItem],
    fallback_ai: AiExplanation,
) -> AiExplanation:
    """
    When AI_API_KEY (e.g., Groq Llama 3.3 70B) is configured and live lookups are enabled,
    synthesizes a real-time Senior SOC Analyst explanation directly from the live provider telemetry.
    """
    settings = get_settings()
    if not settings.ai_api_key or not settings.enable_live_public_lookups:
        return fallback_ai

    evidence_digest = [
        {
            "provider": e.provider,
            "title": e.title,
            "verdict": e.verdict,
            "details": e.details,
        }
        for e in evidence
    ]
    factor_digest = [
        {"factor": f.factor, "points": f.points, "max": f.max_points, "reason": f.reason}
        for f in factors
    ]

    prompt = (
        "You are THREATLENS AI, an elite Defensive SOC Analyst. "
        "Given the live threat intelligence telemetry below, return ONLY valid JSON matching this exact schema:\n"
        "{\n"
        '  "overview": "2-3 sentence crisp technical executive assessment referencing actual vendor findings",\n'
        '  "why_flagged": ["up to 4 concise evidence bullet strings"],\n'
        '  "mitre_techniques": [{"id": "Txxxx", "name": "Technique Name", "tactic": "Tactic"}],\n'
        '  "recommended_actions": ["3-4 concrete defensive SOC containment/hardening steps"]\n'
        "}\n"
        "If risk_score < 25, mitre_techniques can be []. Never include markdown fences outside JSON.\n\n"
        f"Indicator Type: {indicator_type}\n"
        f"Target: {target}\n"
        f"Calculated Score: {risk_score}/100 ({severity} / {verdict})\n"
        f"Score Factors: {json.dumps(factor_digest)[:2500]}\n"
        f"Provider Evidence: {json.dumps(evidence_digest)[:3000]}"
    )

    try:
        async with httpx.AsyncClient(timeout=8.5) as client:
            resp = await client.post(
                f"{settings.ai_base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {settings.ai_api_key}"},
                json={
                    "model": settings.ai_model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "Respond strictly with valid JSON object only.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.15,
                    "response_format": {"type": "json_object"},
                },
            )
        if resp.status_code == 200:
            content = (
                resp.json()
                .get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
                .strip()
            )
            parsed = json.loads(content)
            mitre_list = [
                MitreTechnique(
                    id=str(m.get("id", "T1595")),
                    name=str(m.get("name", "Threat Technique")),
                    tactic=str(m.get("tactic", "Reconnaissance")),
                )
                for m in (parsed.get("mitre_techniques") or [])[:4]
                if isinstance(m, dict) and m.get("id")
            ]
            return AiExplanation(
                overview=str(parsed.get("overview") or fallback_ai.overview),
                why_flagged=[
                    str(x) for x in (parsed.get("why_flagged") or fallback_ai.why_flagged)[:5]
                ],
                mitre_techniques=mitre_list if mitre_list or risk_score < 25 else fallback_ai.mitre_techniques,
                recommended_actions=[
                    str(x)
                    for x in (parsed.get("recommended_actions") or fallback_ai.recommended_actions)[:5]
                ],
                is_simulated_ai=False,
            )
    except Exception:
        pass

    return fallback_ai
