import json
import httpx
from app.config import get_settings
from app.schemas import AssistantRequest, AssistantResponse, MitreTechnique

OFFENSIVE_BLOCKLIST = (
    "write malware",
    "create ransomware",
    "reverse shell payload",
    "exploit code to hack",
    "ddos script",
    "bypass authentication exploit",
)

SYSTEM_PROMPT = (
    "You are THREATLENS AI, a Senior Defensive SOC Analyst and Threat Intelligence Copilot. "
    "Explain evidence clearly, map indicators to MITRE ATT&CK, provide NIST SP 800-61 incident response "
    "containment steps, and never generate offensive exploits or unauthorized attack payloads."
)


async def run_investigation_assistant(req: AssistantRequest) -> AssistantResponse:
    msg_lower = req.message.lower()
    if any(term in msg_lower for term in OFFENSIVE_BLOCKLIST):
        return AssistantResponse(
            reply=(
                "### Defensive Scope Restriction\n"
                "THREATLENS AI operates strictly within **authorized defensive cybersecurity and incident response** workflows. "
                "I cannot generate exploit payloads, malware, or unauthorized attack scripts.\n\n"
                "However, I can help you:\n"
                "- Analyze indicators of compromise (URLs, IPs, domains, emails, CVEs)\n"
                "- Understand detection signatures & MITRE ATT&CK mappings\n"
                "- Build containment and remediation playbooks"
            ),
            suggested_questions=[
                "How do we defend against this attack vector?",
                "Generate a NIST containment checklist for our SOC team",
                "Map this indicator to MITRE ATT&CK detections",
            ],
            mitre_mappings=[],
            recommended_steps=[
                "Document authorized testing boundaries in Investigation notes.",
                "Focus on detection engineering, log correlation, and patching.",
            ],
            is_simulated_ai=True,
        )

    settings = get_settings()
    if settings.ai_api_key and settings.enable_live_public_lookups:
        try:
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            if req.context:
                messages.append(
                    {
                        "role": "system",
                        "content": f"Active Investigation Context JSON:\n{json.dumps(req.context)[:4000]}",
                    }
                )
            for h in req.history[-6:]:
                messages.append({"role": h.role, "content": h.content})
            messages.append({"role": "user", "content": req.message})

            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{settings.ai_base_url.rstrip('/')}/chat/completions",
                    headers={"Authorization": f"Bearer {settings.ai_api_key}"},
                    json={"model": settings.ai_model, "messages": messages, "temperature": 0.2},
                )
            if resp.status_code == 200:
                reply_text = (
                    resp.json()
                    .get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                )
                if reply_text:
                    return _enrich_assistant_output(reply_text, req, is_simulated=False)
        except Exception:
            pass

    return _deterministic_soc_copilot(req)


def _deterministic_soc_copilot(req: AssistantRequest) -> AssistantResponse:
    q = req.message.lower()
    ctx = req.context or {}
    inv_title = ctx.get("investigationTitle") or ctx.get("title")
    target = ctx.get("targetValue") or ctx.get("indicator")
    risk_score = ctx.get("riskScore")
    severity = ctx.get("severity")

    context_banner = ""
    if inv_title or target:
        context_banner = (
            f"**Context Loaded:** `{inv_title or target}`"
            + (f" — Risk Score **{risk_score}/100 ({severity})**\n\n" if risk_score is not None else "\n\n")
        )

    if "phish" in q or "email" in q or "spf" in q or "dmarc" in q or "bec" in q:
        reply = (
            f"{context_banner}### Phishing & Email Authentication Triage\n"
            "1. **Header Authentication Check**: Verify `Authentication-Results` for **SPF**, **DKIM**, and **DMARC** alignment. A `dmarc=fail` combined with external `Reply-To` mismatch strongly indicates spoofing or Business Email Compromise (BEC).\n"
            "2. **Link & Credential Lure Inspection**: Isolate embedded URLs—check RDAP domain age (<45 days NRD), Punycode (`xn--`), and credential keywords (`verify`, `login`, `secure`).\n"
            "3. **Immediate SOC Containment**:\n"
            "   - Purge matching emails across mailboxes by `Message-ID` and sender domain.\n"
            "   - Block the sender domain and extracted URLs on Secure Email & Web Gateways.\n"
            "   - Revoke active OAuth/session tokens and enforce MFA re-registration for any user who clicked."
        )
        mitre = [
            MitreTechnique(id="T1566.002", name="Phishing: Spearphishing Link", tactic="Initial Access"),
            MitreTechnique(id="T1656", name="Impersonation", tactic="Defense Evasion"),
        ]
        steps = [
            "Search mail logs for all recipients of the sender & Reply-To address.",
            "Sinkhole extracted phishing domains at protective DNS.",
            "Reset credentials & invalidate sessions for impacted users.",
        ]
    elif "cve" in q or "vulnerab" in q or "patch" in q or "log4" in q or "xz" in q:
        reply = (
            f"{context_banner}### Vulnerability Prioritization & Remediation Strategy\n"
            "1. **Exploitability Triage**: Prioritize vulnerabilities with **CVSS >= 8.0**, network attack vector (`AV:N`), low complexity (`AC:L`), and **CISA Known Exploited Vulnerability (KEV)** status.\n"
            "2. **Asset Exposure Discovery**: Cross-reference SBOM / package inventories on internet-facing load balancers, VPN gateways, and production Linux hosts.\n"
            "3. **Compensating Controls**: Where immediate restarts or upgrades require maintenance windows, deploy WAF virtual patches, restrict ingress CIDRs, and monitor EDR process-spawn anomalies."
        )
        mitre = [
            MitreTechnique(id="T1190", name="Exploit Public-Facing Application", tactic="Initial Access"),
            MitreTechnique(id="T1203", name="Exploitation for Client Execution", tactic="Execution"),
        ]
        steps = [
            "Identify exposed hosts running vulnerable versions via asset inventory.",
            "Apply vendor security patch inside critical SLA (<24-48h for KEV).",
            "Deploy WAF / network ACL rules and hunt logs for exploitation artifacts.",
        ]
    elif "executive" in q or "summary" in q or "report" in q:
        reply = (
            f"{context_banner}### Executive Threat Summary (Draft)\n"
            "- **Situation**: Automated and analyst-verified telemetry identified high-priority threat indicators requiring coordinated containment.\n"
            "- **Business Impact**: Potential credential compromise or unauthorized perimeter reconnaissance if left unmitigated; zero confirmed data exfiltration at current triage stage.\n"
            "- **Actions Taken**: Indicators have been normalized, scored via THREATLENS Explainable Risk Engine, and staged for firewall/DNS/email blocklisting.\n"
            "- **Next 24 Hours**: Complete endpoint log sweep, finalize containment checklist in Incident Management, and publish formal compliance report."
        )
        mitre = [
            MitreTechnique(id="T1595", name="Active Scanning", tactic="Reconnaissance"),
        ]
        steps = [
            "Attach latest scan results to the active Investigation case.",
            "Verify all Incident containment playbook items are marked complete.",
            "Export formal Executive PDF/Markdown report from the Reports module.",
        ]
    else:
        reply = (
            f"{context_banner}### SOC Investigation Guidance (NIST SP 800-61 Workflow)\n"
            "1. **Evidence Correlation**: Review the **Score Breakdown** to distinguish independent vendor detections (VirusTotal, AbuseIPDB, Safe Browsing, OTX) from structural heuristics (RDAP age, entropy, header anomalies).\n"
            "2. **Pivot Across Infrastructure**: Open the **Threat Relationship Graph** to inspect connected IPs, resolving domains, phishing senders, and targeted CVEs.\n"
            "3. **Containment & Eradication**:\n"
            "   - Block confirmed malicious IPs/domains at perimeter firewall & DNS.\n"
            "   - Query SIEM/EDR logs over the past 30 days for outbound connections.\n"
            "   - Document analyst findings in the Investigation timeline for auditability."
        )
        mitre = [
            MitreTechnique(id="T1071.001", name="Application Layer Protocol: Web Protocols", tactic="Command and Control"),
            MitreTechnique(id="T1583.001", name="Acquire Infrastructure: Domains", tactic="Resource Development"),
        ]
        steps = [
            "Correlate related indicators in Threat Relationship Graph.",
            "Check 30-day SIEM/Firewall/DNS logs for internal host contact.",
            "Escalate to an Incident if internal asset exposure is confirmed.",
        ]

    return AssistantResponse(
        reply=reply,
        suggested_questions=[
            "Draft an executive summary for leadership",
            "Explain how SPF, DKIM, and DMARC failures affect risk score",
            "What containment playbook steps should we run first?",
            "How should we prioritize CISA KEV vulnerabilities?",
        ],
        mitre_mappings=mitre,
        recommended_steps=steps,
        is_simulated_ai=True,
    )


def _enrich_assistant_output(
    reply_text: str, req: AssistantRequest, is_simulated: bool
) -> AssistantResponse:
    fallback = _deterministic_soc_copilot(req)
    return AssistantResponse(
        reply=reply_text,
        suggested_questions=fallback.suggested_questions,
        mitre_mappings=fallback.mitre_mappings,
        recommended_steps=fallback.recommended_steps,
        is_simulated_ai=is_simulated,
    )
