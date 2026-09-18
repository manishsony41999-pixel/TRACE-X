"""
Unit tests for Explainable Threat Scoring Engine
"""

from app.services.threat_score import calculate_threat_score


def test_calculate_threat_score_benign():
    parsed_email = {"attachments": []}
    header_analysis = {"anomalies": [], "sender": {"domain": "legit.com"}}
    auth_analysis = {"spf": {"status": "pass"}, "dkim": {"status": "pass"}, "dmarc": {"status": "pass"}}
    url_analysis = []
    intelligence = {}

    res = calculate_threat_score(parsed_email, header_analysis, auth_analysis, url_analysis, intelligence)
    assert res["score"] == 0
    assert res["risk_level"] == "LOW"
    assert len(res["evidence"]) == 0


def test_calculate_threat_score_critical_anomalies():
    parsed_email = {
        "attachments": [
            {"filename": "payload.exe", "is_suspicious_extension": True, "extension": "exe"}
        ]
    }
    header_analysis = {
        "anomalies": [
            {"type": "reply_to_domain_mismatch", "message": "Reply-To mismatch"}
        ],
        "sender": {"domain": "fake.com"}
    }
    auth_analysis = {"spf": {"status": "fail"}, "dkim": {"status": "fail"}, "dmarc": {"status": "fail"}}
    url_analysis = [
        {"url": "http://bad.com/login", "risk_level": "high_risk", "flags": [{"message": "IP hostname"}]}
    ]
    intelligence = {
        "domains": {
            "fake.com": {"dns": {"has_mx": False}}
        }
    }

    res = calculate_threat_score(parsed_email, header_analysis, auth_analysis, url_analysis, intelligence)
    assert res["score"] >= 80
    assert res["risk_level"] == "CRITICAL"
    assert len(res["evidence"]) >= 4
