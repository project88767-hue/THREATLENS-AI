from email import message_from_string
from email.utils import parseaddr
import re

from app.adapters.safe_browsing import lookup_safe_browsing
from app.schemas import (
    AnalysisResponse,
    EmailScanRequest,
    EvidenceItem,
    ExtractedRelation,
    ProviderStatus,
    ScoreFactor,
)
from app.scoring.engine import calculate_explainable_risk

URL_EXTRACT_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
URGENCY_PATTERNS = (
    "urgent action required",
    "wire transfer",
    "immediate payment",
    "account suspended",
    "verify your password",
    "mfa reset",
    "gift cards",
    "overdue invoice",
    "unusual sign-in",
    "confirm your identity",
    "within 24 hours",
)
DANGEROUS_EXTENSIONS = (".exe", ".scr", ".iso", ".img", ".lnk", ".hta", ".vbs", ".js", ".xlsm", ".docm", ".bat")


def _extract_domain(addr: str) -> str:
    _, email_part = parseaddr(addr)
    if "@" in email_part:
        return email_part.split("@", 1)[1].lower().strip()
    return ""


def _parse_auth_status(blob: str, protocol: str) -> str:
    pattern = re.compile(rf"{protocol}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)", re.IGNORECASE)
    match = pattern.search(blob)
    return match.group(1).lower() if match else "missing"


async def analyze_email(payload: EmailScanRequest) -> AnalysisResponse:
    raw_headers = payload.raw_headers.strip()
    body = payload.body.strip()

    msg = message_from_string(f"{raw_headers}\n\n{body}" if raw_headers else body)
    from_header = payload.sender or msg.get("From", "") or "unknown@unverified-sender.example"
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    subject = payload.subject or msg.get("Subject", "(No Subject)")
    auth_results = " ".join(
        [
            msg.get("Authentication-Results", ""),
            msg.get("ARC-Authentication-Results", ""),
            msg.get("Received-SPF", ""),
            raw_headers,
        ]
    )

    spf_status = _parse_auth_status(auth_results, "spf")
    if spf_status == "missing" and "received-spf: pass" in auth_results.lower():
        spf_status = "pass"
    elif spf_status == "missing" and "received-spf: fail" in auth_results.lower():
        spf_status = "fail"

    dkim_status = _parse_auth_status(auth_results, "dkim")
    if dkim_status == "missing" and "dkim-signature:" in raw_headers.lower():
        dkim_status = "present_unverified"

    dmarc_status = _parse_auth_status(auth_results, "dmarc")

    # 1. Authentication Factor (SPF / DKIM / DMARC)
    auth_points = 0
    auth_issues: list[str] = []
    if spf_status in ("fail", "softfail", "permerror"):
        auth_points += 18
        auth_issues.append(f"SPF authentication failed ({spf_status})")
    elif spf_status in ("missing", "none"):
        auth_points += 8
        auth_issues.append("SPF authentication header missing/none")

    if dkim_status in ("fail", "permerror"):
        auth_points += 15
        auth_issues.append(f"DKIM signature verification failed ({dkim_status})")
    elif dkim_status in ("missing", "none"):
        auth_points += 6
        auth_issues.append("No verified DKIM signature result")

    if dmarc_status == "fail":
        auth_points += 20
        auth_issues.append("DMARC alignment policy failed")
    elif dmarc_status in ("missing", "none"):
        auth_points += 6
        auth_issues.append("DMARC policy alignment unverified")

    auth_points = min(40, auth_points)
    auth_verdict = "MALICIOUS" if auth_points >= 28 else ("SUSPICIOUS" if auth_points >= 12 else "CLEAN")

    auth_ev = EvidenceItem(
        provider="EMAIL_AUTH_PARSER",
        category="SPF / DKIM / DMARC Authentication",
        title=(
            f"Email Auth: SPF={spf_status.upper()}, DKIM={dkim_status.upper()}, DMARC={dmarc_status.upper()}"
        ),
        verdict=auth_verdict,
        weight=30 + auth_points,
        details={
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "issues": auth_issues,
        },
        is_simulated=False,
    )
    auth_factor = ScoreFactor(
        factor="Email Authentication Alignment (SPF/DKIM/DMARC)",
        points=auth_points,
        max_points=40,
        reason="; ".join(auth_issues) if auth_issues else "SPF, DKIM, and DMARC all passed alignment.",
        source="RFC 7208/6376/7489 Parser",
        is_simulated=False,
    )

    # 2. Spoofing & Header Anomaly Factor
    from_domain = _extract_domain(from_header)
    reply_domain = _extract_domain(reply_to)
    return_domain = _extract_domain(return_path)

    spoof_points = 0
    spoof_notes: list[str] = []
    if reply_domain and from_domain and reply_domain != from_domain:
        spoof_points += 20
        spoof_notes.append(f"Reply-To domain ({reply_domain}) mismatches From domain ({from_domain})")
    if return_domain and from_domain and return_domain != from_domain:
        spoof_points += 12
        spoof_notes.append(f"Return-Path ({return_domain}) differs from sender domain ({from_domain})")

    display_name, sender_email = parseaddr(from_header)
    if display_name and any(
        vip in display_name.lower() for vip in ("ceo", "cfo", "microsoft", "it support", "security team", "payroll")
    ):
        if any(free in from_domain for free in ("gmail.com", "yahoo.com", "outlook.com", ".xyz", ".top", "unverified")):
            spoof_points += 18
            spoof_notes.append(f"Executive/IT display-name impersonation ('{display_name}') from external domain ({from_domain})")

    spoof_points = min(30, spoof_points)
    spoof_ev = EvidenceItem(
        provider="HEURISTIC_ENGINE",
        category="Sender Alignment & Impersonation Forensics",
        title=(
            f"{len(spoof_notes)} header spoofing anomalies detected"
            if spoof_notes
            else "Consistent From, Reply-To, and Return-Path headers"
        ),
        verdict="MALICIOUS" if spoof_points >= 20 else ("SUSPICIOUS" if spoof_points >= 10 else "CLEAN"),
        weight=20 + spoof_points,
        details={
            "from": from_header,
            "from_domain": from_domain,
            "reply_to": reply_to,
            "return_path": return_path,
            "anomalies": spoof_notes,
        },
        is_simulated=False,
    )
    spoof_factor = ScoreFactor(
        factor="Header Spoofing & BEC Impersonation",
        points=spoof_points,
        max_points=30,
        reason="; ".join(spoof_notes) if spoof_notes else "No Reply-To or display-name spoofing detected.",
        source="Header Anomaly Detector",
        is_simulated=False,
    )

    # 3. Content,BEC Lures, Embedded URLs & Risky Attachments
    combined_text = f"{subject}\n{body}".lower()
    matched_urgency = [p for p in URGENCY_PATTERNS if p in combined_text]
    extracted_urls = list(dict.fromkeys(URL_EXTRACT_RE.findall(body)))[:6]
    risky_attachments = [ext for ext in DANGEROUS_EXTENSIONS if ext in combined_text]

    content_points = min(16, len(matched_urgency) * 6) + (18 if risky_attachments else 0)
    gsb_status = ProviderStatus(mode="DEMO_FALLBACK", latency_ms=0, message="No URLs in email body")
    flagged_urls: list[str] = []

    if extracted_urls:
        gsb_ev, gsb_factor, gsb_status = await lookup_safe_browsing(extracted_urls[0])
        if gsb_factor.points > 0:
            content_points += 15
            flagged_urls.append(extracted_urls[0])
        elif any(k in extracted_urls[0].lower() for k in ("login", "verify", ".xyz", ".tk", "secure")):
            content_points += 12
            flagged_urls.append(extracted_urls[0])

    content_points = min(35, content_points)
    content_reasons: list[str] = []
    if matched_urgency:
        content_reasons.append(f"Social engineering urgency cues ({', '.join(matched_urgency[:3])})")
    if risky_attachments:
        content_reasons.append(f"High-risk executable/macro attachment reference ({', '.join(risky_attachments)})")
    if flagged_urls:
        content_reasons.append(f"Suspicious embedded link ({flagged_urls[0][:60]})")

    content_ev = EvidenceItem(
        provider="HEURISTIC_ENGINE",
        category="Social Engineering, Links & Payload Inspection",
        title=(
            f"Detected {len(matched_urgency)} BEC cues, {len(extracted_urls)} URLs, {len(risky_attachments)} risky file refs"
        ),
        verdict="MALICIOUS" if content_points >= 22 else ("SUSPICIOUS" if content_points >= 10 else "CLEAN"),
        weight=25 + content_points,
        details={
            "subject": subject,
            "urgency_phrases": matched_urgency,
            "extracted_urls": extracted_urls,
            "flagged_urls": flagged_urls,
            "risky_attachment_types": risky_attachments,
        },
        is_simulated=False,
    )
    content_factor = ScoreFactor(
        factor="BEC Social Engineering & Embedded Payloads",
        points=content_points,
        max_points=35,
        reason="; ".join(content_reasons) if content_reasons else "Benign message body with no coercive lures or malicious links.",
        source="Email Content Analyzer",
        is_simulated=False,
    )

    _, normalized_email = parseaddr(from_header)
    target_id = normalized_email or from_header[:80]
    evidence = [auth_ev, spoof_ev, content_ev]
    factors = [auth_factor, spoof_factor, content_factor]
    provider_status = {
        "email_auth_parser": ProviderStatus(mode="LIVE", latency_ms=1, message="SPF/DKIM/DMARC parser"),
        "heuristic_engine": ProviderStatus(mode="LIVE", latency_ms=1, message="BEC & header forensics"),
        "safe_browsing": gsb_status,
    }

    risk_score, severity, confidence, verdict, summary, ai_explanation = calculate_explainable_risk(
        "EMAIL", target_id, factors, evidence, provider_status
    )

    relations: list[ExtractedRelation] = []
    for u in extracted_urls[:3]:
        relations.append(
            ExtractedRelation(
                source_type="EMAIL",
                source_value=target_id,
                source_label=target_id,
                target_type="URL",
                target_value=u,
                target_label=u[:42],
                relation="SENDS_PHISHING",
                confidence=88 if u in flagged_urls else 65,
            )
        )

    return AnalysisResponse(
        indicator_type="EMAIL",
        target=target_id,
        normalized_target=target_id.lower(),
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
            "subject": subject,
            "from": from_header,
            "reply_to": reply_to,
            "return_path": return_path,
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "extracted_urls": extracted_urls,
            "urgency_phrases": matched_urgency,
            "risky_attachments": risky_attachments,
        },
    )
