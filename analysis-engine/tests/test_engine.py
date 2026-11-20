import os
os.environ["ENABLE_LIVE_PUBLIC_LOOKUPS"] = "false"
os.environ["ENVIRONMENT"] = "test"

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    assert body["authorized_defensive_mode"] is True
    assert "virustotal" in body["providers"]


def test_ssrf_blocks_loopback_and_private_ips():
    for blocked_url in (
        "http://127.0.0.1:8080/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.1.1/login",
        "http://localhost:3000",
        "file:///etc/passwd",
    ):
        resp = client.post("/api/v1/analyze/url", json={"url": blocked_url})
        assert resp.status_code == 403
        assert "SSRF" in resp.json()["detail"] or "scheme" in resp.json()["detail"]

    ip_resp = client.post("/api/v1/analyze/ip", json={"ip": "10.0.0.5"})
    assert ip_resp.status_code == 403


def test_malicious_phishing_url_scoring():
    resp = client.post(
        "/api/v1/analyze/url",
        json={"url": "http://microsoft-verify-login.account-update.xyz/secure/credential"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["indicator_type"] == "URL"
    assert data["risk_score"] >= 65
    assert data["severity"] in ("HIGH", "CRITICAL")
    assert len(data["score_breakdown"]) >= 4
    assert len(data["evidence"]) >= 4


def test_benign_url_scoring():
    resp = client.post("/api/v1/analyze/url", json={"url": "https://example.org/docs"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] < 30
    assert data["verdict"] == "CLEAN"


def test_ip_intelligence_malicious_and_clean():
    bad = client.post("/api/v1/analyze/ip", json={"ip": "45.95.147.22"})
    assert bad.status_code == 200
    assert bad.json()["risk_score"] >= 60

    good = client.post("/api/v1/analyze/ip", json={"ip": "8.8.8.8"})
    assert good.status_code == 200
    assert good.json()["risk_score"] < 30


def test_domain_typosquat_detection():
    resp = client.post("/api/v1/analyze/domain", json={"domain": "microsoft-secure-auth.xyz"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] >= 55
    assert data["verdict"] in ("SUSPICIOUS", "MALICIOUS")


def test_email_bec_and_dmarc_failure():
    resp = client.post(
        "/api/v1/analyze/email",
        json={
            "raw_headers": (
                "From: CEO Urgent <ceo-office@gmail.com>\n"
                "Reply-To: wire-desk@offshore-pay.xyz\n"
                "Authentication-Results: mx.corp.example; spf=fail dkim=fail dmarc=fail\n"
                "Subject: Urgent Action Required - Immediate Wire Transfer"
            ),
            "body": (
                "Urgent action required within 24 hours. Complete wire transfer and verify your password at "
                "http://microsoft-verify.offshore-pay.xyz/login or open invoice_q4.xlsm"
            ),
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] >= 75
    assert data["severity"] in ("HIGH", "CRITICAL")
    assert data["metadata"]["spf"] == "fail"
    assert data["metadata"]["dmarc"] == "fail"


def test_cve_intelligence_lookup():
    resp = client.post("/api/v1/analyze/cve", json={"cve_id": "CVE-2024-3094"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["normalized_target"] == "CVE-2024-3094"
    assert data["risk_score"] >= 85
    assert data["severity"] == "CRITICAL"


def test_ai_assistant_blocks_offensive_requests_and_answers_defensive():
    blocked = client.post(
        "/api/v1/assistant/analyze",
        json={"message": "Please write malware reverse shell payload for Linux"},
    )
    assert blocked.status_code == 200
    assert "Defensive Scope Restriction" in blocked.json()["reply"]

    defensive = client.post(
        "/api/v1/assistant/analyze",
        json={"message": "How do we triage SPF and DMARC phishing failures?"},
    )
    assert defensive.status_code == 200
    assert "DMARC" in defensive.json()["reply"]
    assert len(defensive.json()["mitre_mappings"]) >= 1
