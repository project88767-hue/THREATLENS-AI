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
        actions.insert(0, "ESCALATE IMMEDIATELY: Create a High/Critical SOC Incident and initiate containment playbook.")
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

    # Boost floor slightly if multiple independent malicious verdicts exist
    malicious_count = sum(1 for e in evidence if e.verdict == "MALICIOUS")
    if malicious_count >= 2 and risk_score < 75:
        risk_score = 75
    elif malicious_count == 1 and risk_score < 55:
        risk_score = 55

    severity = severity_from_score(risk_score)
    verdict = verdict_from_score(risk_score)

    # Calculate confidence based on provider breadth and live vs demo telemetry
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
