import re
import time
from typing import Any
import httpx
from app.config import get_settings
from app.schemas import EvidenceItem, ProviderStatus, ScoreFactor

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

CURATED_CVE_CACHE: dict[str, dict[str, Any]] = {
    "CVE-2024-3094": {
        "cve_id": "CVE-2024-3094",
        "title": "XZ Utils liblzma Supply Chain Backdoor",
        "description": (
            "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. "
            "Through complex obfuscations, the liblzma build process extracts a prebuilt object file "
            "that hooks OpenSSH sshd authentication via systemd."
        ),
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-506 (Embedded Malicious Code)",
        "published": "2024-03-29",
        "kev_listed": True,
        "affected_products": ["tukaani:xz:5.6.0", "tukaani:xz:5.6.1"],
        "remediation": "Immediately downgrade xz-utils to 5.4.x or upgrade to clean vendor-verified packages (>=5.6.1+really5.4.5).",
    },
    "CVE-2021-44228": {
        "cve_id": "CVE-2021-44228",
        "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "description": (
            "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, "
            "and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints."
        ),
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-502 / CWE-917 (Improper Neutralization of JNDI Lookup)",
        "published": "2021-12-10",
        "kev_listed": True,
        "affected_products": ["apache:log4j:2.0-2.14.1"],
        "remediation": "Upgrade Apache Log4j2 to 2.17.1+ (Java 8) and remove JndiLookup class from classpath where patching lags.",
    },
    "CVE-2024-6387": {
        "cve_id": "CVE-2024-6387",
        "title": "OpenSSH Server Signal Handler Race Condition (regreSSHion)",
        "description": (
            "A signal handler race condition was found in OpenSSH's server (sshd), where a client does not "
            "authenticate within LoginGraceTime seconds, enabling unauthenticated remote code execution on glibc Linux systems."
        ),
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-364 (Signal Handler Race Condition)",
        "published": "2024-07-01",
        "kev_listed": False,
        "affected_products": ["openbsd:openssh:8.5p1-9.7p1"],
        "remediation": "Upgrade OpenSSH to 9.8p1 or vendor backported security release; set LoginGraceTime 0 as temporary mitigation.",
    },
    "CVE-2024-21762": {
        "cve_id": "CVE-2024-21762",
        "title": "Fortinet FortiOS SSL VPN Out-of-Bounds Write RCE",
        "description": (
            "An out-of-bounds write vulnerability in FortiOS SSL VPN allows a remote unauthenticated attacker "
            "to execute arbitrary code or commands via specially crafted HTTP requests."
        ),
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-787 (Out-of-bounds Write)",
        "published": "2024-02-09",
        "kev_listed": True,
        "affected_products": ["fortinet:fortios:7.4.0-7.4.2", "fortinet:fortios:7.2.0-7.2.6"],
        "remediation": "Upgrade FortiOS to patched maintenance release immediately and disable SSL-VPN if unused.",
    },
    "CVE-2023-4863": {
        "cve_id": "CVE-2023-4863",
        "title": "libwebp Heap Buffer Overflow in Huffman Table Construction",
        "description": (
            "Heap buffer overflow in WebP in Google Chrome and libwebp allowed a remote attacker "
            "to perform an out of bounds memory write via a crafted HTML/image payload."
        ),
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "cwe": "CWE-787 (Heap-based Buffer Overflow)",
        "published": "2023-09-12",
        "kev_listed": True,
        "affected_products": ["webmproject:libwebp:<1.3.2", "google:chrome:<116.0.5845.187"],
        "remediation": "Update libwebp to >= 1.3.2 and rebuild statically linked browsers, Electron apps, and image pipelines.",
    },
}


async def lookup_nvd(
    query: str,
) -> tuple[dict[str, Any], list[EvidenceItem], list[ScoreFactor], ProviderStatus]:
    settings = get_settings()
    cleaned = query.strip().upper()
    start = time.perf_counter()

    is_cve = bool(CVE_PATTERN.match(cleaned))
    if settings.enable_live_public_lookups:
        headers: dict[str, str] = {}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key
        params = {"cveId": cleaned} if is_cve else {"keywordSearch": query.strip(), "resultsPerPage": "1"}

        try:
            async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    headers=headers,
                    params=params,
                )
            latency = int((time.perf_counter() - start) * 1000)
            if resp.status_code == 200:
                vulns = resp.json().get("vulnerabilities", [])
                if vulns:
                    cve_obj = vulns[0].get("cve", {})
                    parsed = _parse_nvd_cve(cve_obj)
                    mode = "LIVE" if settings.nvd_api_key else "PUBLIC_LIVE"
                    ev, factors = _build_cve_evidence(parsed, is_simulated=False)
                    return (
                        parsed,
                        ev,
                        factors,
                        ProviderStatus(mode=mode, latency_ms=latency, message="NIST NVD v2.0 API"),
                    )
        except Exception:
            pass

    latency = int((time.perf_counter() - start) * 1000)
    # Check curated cache by CVE ID or keyword match
    if cleaned in CURATED_CVE_CACHE:
        record = CURATED_CVE_CACHE[cleaned]
        ev, factors = _build_cve_evidence(record, is_simulated=True)
        return (
            record,
            ev,
            factors,
            ProviderStatus(
                mode="DEMO_FALLBACK",
                latency_ms=latency,
                message="Served from curated THREATLENS NVD intelligence dataset.",
            ),
        )

    for cve_key, record in CURATED_CVE_CACHE.items():
        if query.strip().lower() in (
            f"{cve_key} {record['title']} {record['description']}".lower()
        ):
            ev, factors = _build_cve_evidence(record, is_simulated=True)
            return (
                record,
                ev,
                factors,
                ProviderStatus(
                    mode="DEMO_FALLBACK",
                    latency_ms=latency,
                    message=f"Matched '{query}' in curated CVE dataset.",
                ),
            )

    # Synthesize structured baseline for unknown CVE format
    synthetic = {
        "cve_id": cleaned if is_cve else f"QUERY:{query.strip()}",
        "title": f"Vulnerability Advisory Profile for {cleaned if is_cve else query.strip()}",
        "description": (
            "Live NVD lookup returned no direct record or was rate-limited. "
            "Verify exact CVE identifier and vendor security bulletin before deployment changes."
        ),
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
        "cwe": "CWE-Other (Unclassified Advisory)",
        "published": "Unknown",
        "kev_listed": False,
        "affected_products": [query.strip()],
        "remediation": "Consult vendor advisory, apply latest stable security patch, and restrict external service exposure.",
    }
    ev, factors = _build_cve_evidence(synthetic, is_simulated=True)
    return (
        synthetic,
        ev,
        factors,
        ProviderStatus(
            mode="DEMO_FALLBACK",
            latency_ms=latency,
            message="Fallback CVE advisory generated (NVD offline or unseen CVE).",
        ),
    )


def _parse_nvd_cve(cve_obj: dict[str, Any]) -> dict[str, Any]:
    cve_id = cve_obj.get("id", "UNKNOWN-CVE")
    descriptions = cve_obj.get("descriptions", [])
    desc = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "No description provided.",
    )
    metrics = cve_obj.get("metrics", {})
    cvss_score = 5.0
    cvss_vector = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N"

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = float(cvss_data.get("baseScore", 5.0))
            cvss_vector = cvss_data.get("vectorString", cvss_vector)
            break

    weaknesses = cve_obj.get("weaknesses", [])
    cwe = "CWE-Unknown"
    if weaknesses:
        w_desc = weaknesses[0].get("description", [])
        if w_desc:
            cwe = w_desc[0].get("value", cwe)

    kev_listed = bool(cve_obj.get("cisaExploitAdd"))
    return {
        "cve_id": cve_id,
        "title": f"{cve_id} Security Vulnerability",
        "description": desc,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe": cwe,
        "published": (cve_obj.get("published") or "")[:10],
        "kev_listed": kev_listed,
        "affected_products": [cve_id],
        "remediation": (
            "Apply vendor security updates immediately; prioritize internet-facing assets and validate compensating WAF/network controls."
        ),
    }


def _build_cve_evidence(
    record: dict[str, Any], is_simulated: bool
) -> tuple[list[EvidenceItem], list[ScoreFactor]]:
    cvss = float(record.get("cvss_score", 5.0))
    kev = bool(record.get("kev_listed", False))
    vector = str(record.get("cvss_vector", ""))

    cvss_points = min(65, round(cvss * 6.5))
    kev_points = 25 if kev else 0
    network_points = 10 if "AV:N" in vector else 3

    verdict = "MALICIOUS" if (cvss >= 8.0 or kev) else ("SUSPICIOUS" if cvss >= 4.0 else "CLEAN")
    prefix = "[DEMO] " if is_simulated else ""

    evidence = [
        EvidenceItem(
            provider="NVD",
            category="CVSS Base Severity",
            title=f"{prefix}CVSS v3.1 Base Score: {cvss}/10.0 ({record.get('cwe')})",
            verdict=verdict,
            weight=min(100, cvss_points + 20),
            details=record,
            is_simulated=is_simulated,
        ),
        EvidenceItem(
            provider="HEURISTIC_ENGINE",
            category="Exploitability & KEV Status",
            title=(
                f"{prefix}Known Exploited Vulnerability (CISA KEV Active)"
                if kev
                else f"{prefix}Attack Vector Analysis ({vector})"
            ),
            verdict="MALICIOUS" if kev else ("SUSPICIOUS" if "AV:N" in vector else "INFO"),
            weight=90 if kev else 45,
            details={
                "kev_listed": kev,
                "network_reachable": "AV:N" in vector,
                "low_complexity": "AC:L" in vector,
                "no_privileges_required": "PR:N" in vector,
            },
            is_simulated=is_simulated,
        ),
    ]

    factors = [
        ScoreFactor(
            factor="CVSS v3.1 Base Severity",
            points=cvss_points,
            max_points=65,
            reason=f"Base CVSS score is {cvss}/10.0 ({vector}).",
            source="NIST NVD",
            is_simulated=is_simulated,
        ),
        ScoreFactor(
            factor="Known Exploitation (KEV) Status",
            points=kev_points,
            max_points=25,
            reason=(
                "Actively exploited in the wild (CISA KEV catalog)."
                if kev
                else "Not currently flagged in active KEV catalog."
            ),
            source="Exploit Intelligence",
            is_simulated=is_simulated,
        ),
        ScoreFactor(
            factor="Network Attack Surface",
            points=network_points,
            max_points=10,
            reason=(
                "Remotely exploitable over network (AV:N)."
                if "AV:N" in vector
                else "Requires local or adjacent access."
            ),
            source="CVSS Vector Analyzer",
            is_simulated=is_simulated,
        ),
    ]
    return evidence, factors
