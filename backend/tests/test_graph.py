"""
TRACE-X Threat Graph Tests
"""

from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models import Case, Indicator, Investigation
from app.services.graph_service import build_threat_graph

client = TestClient(app)


def test_build_threat_graph_structure():
    investigation_dummy = {
        "email": {
            "headers": {"subject": "Urgent Invoice Attached", "from": "billing@malicious-domain.com"}
        },
        "header_analysis": {
            "sender": {"address": "billing@malicious-domain.com", "domain": "malicious-domain.com", "display_name": "Billing"},
            "originating_ip": "198.51.100.25",
            "spoofing_indicators": {"is_display_name_spoofed": False},
            "hops": [
                {"hop_number": 1, "from_host": "mail.malicious-domain.com", "by_host": "relay.gateway.net", "public_ip": "198.51.100.25"}
            ]
        },
        "authentication": {
            "spf": {"status": "fail"},
            "dkim": {"status": "neutral"},
            "dmarc": {"status": "none"}
        },
        "iocs": {
            "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            "domains": ["malicious-domain.com"],
            "ips": ["198.51.100.25"],
            "urls": ["http://phishing-portal.com/login"]
        },
        "url_analysis": [
            {
                "url": "http://phishing-portal.com/login",
                "risk_level": "high_risk",
                "flags": [{"rule": "suspicious_path", "message": "Credential harvesting path detected"}]
            }
        ],
        "threat_score": {
            "score": 85,
            "risk_level": "HIGH"
        }
    }

    graph = build_threat_graph("TRX-GRAPH01", investigation_dummy, db=None)

    assert graph["case_id"] == "TRX-GRAPH01"
    assert graph["stats"]["node_count"] >= 5
    assert graph["stats"]["edge_count"] >= 4

    node_types = {n["type"] for n in graph["nodes"]}
    assert "case" in node_types
    assert "sender" in node_types
    assert "domain" in node_types
    assert "ip" in node_types
    assert "url" in node_types
    assert "hash" in node_types


def test_cross_case_indicator_correlation():
    db = SessionLocal()
    try:
        db.query(Indicator).filter(Indicator.case_id.in_(["TRX-CASE-A", "TRX-CASE-B"])).delete()
        db.query(Investigation).filter(Investigation.case_id.in_(["TRX-CASE-A", "TRX-CASE-B"])).delete()
        db.query(Case).filter(Case.case_id.in_(["TRX-CASE-A", "TRX-CASE-B"])).delete()
        db.commit()

        case_a = Case(case_id="TRX-CASE-A", status="completed", risk_level="CRITICAL", threat_score=95, source="eml_upload")
        db.add(case_a)
        db.flush()
        db.add(Indicator(case_id="TRX-CASE-A", type="ip", value="203.0.113.88", risk="high_risk"))
        db.commit()

        investigation_b = {
            "header_analysis": {
                "sender": {"address": "attacker@evil.org", "domain": "evil.org"},
                "originating_ip": "203.0.113.88"
            },
            "threat_score": {"score": 90, "risk_level": "CRITICAL"},
            "iocs": {"ips": ["203.0.113.88"], "domains": ["evil.org"], "hashes": [], "urls": []}
        }

        graph_b = build_threat_graph("TRX-CASE-B", investigation_b, db=db)
        
        assert graph_b["stats"]["correlated_cases_count"] >= 1
        assert any(c["case_id"] == "TRX-CASE-A" for c in graph_b["correlated_cases"])
        assert any(e["relationship"] == "SHARES_INDICATOR" for e in graph_b["edges"])

        case_b = Case(case_id="TRX-CASE-B", status="completed", risk_level="CRITICAL", threat_score=90, source="eml_upload")
        db.add(case_b)
        db.flush()
        db.add(Investigation(case_id="TRX-CASE-B", status="completed", result=investigation_b))
        db.commit()

        res = client.get("/api/cases/TRX-CASE-B/graph")
        assert res.status_code == 200
        json_data = res.json()
        assert json_data["success"] is True
        assert json_data["data"]["stats"]["node_count"] > 0
    finally:
        db.close()
