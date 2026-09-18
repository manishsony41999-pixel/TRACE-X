"""
TRACE-X Forensic Report Generator & Chain of Custody Tests
"""

from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models import Case, Investigation, EmailRecord
from app.services.report_generator import (
    compute_evidence_integrity,
    generate_forensic_json_report,
    generate_forensic_pdf_report
)

client = TestClient(app)


def test_evidence_integrity_sha256_checksum():
    db = SessionLocal()
    try:
        db.query(Investigation).filter(Investigation.case_id == "TRX-REP01").delete()
        db.query(EmailRecord).filter(EmailRecord.case_id == "TRX-REP01").delete()
        db.query(Case).filter(Case.case_id == "TRX-REP01").delete()
        db.commit()

        test_case = Case(
            case_id="TRX-REP01",
            status="completed",
            risk_level="CRITICAL",
            threat_score=92,
            source="eml_upload"
        )
        db.add(test_case)
        db.flush()

        email_rec = EmailRecord(
            case_id="TRX-REP01",
            sender="attacker@spoofed.com",
            subject="Urgent Security Verification"
        )
        db.add(email_rec)

        investigation_result = {
            "threat_score": {
                "score": 92,
                "risk_level": "CRITICAL",
                "summary": "Coercive phishing attack.",
                "evidence": [
                    {"category": "Authentication", "reason": "SPF Failed", "points": 15, "severity": "medium"},
                    {"category": "Content NLP", "reason": "High urgency prompts", "points": 25, "severity": "high"}
                ]
            },
            "nlp_analysis": {
                "phishing_probability": 0.95,
                "risk_tier": "CRITICAL",
                "intents_detected": ["urgency_coercion", "credential_harvesting"]
            },
            "authentication": {"spf": {"status": "fail"}, "dkim": {"status": "none"}, "dmarc": {"status": "fail"}},
            "iocs": {"domains": ["spoofed.com"], "ips": ["198.51.100.1"], "urls": ["http://phish.com/login"], "hashes": []},
            "header_analysis": {"originating_ip": "198.51.100.1", "spoofing_indicators": {"reply_to_mismatch": True}}
        }

        db.add(Investigation(case_id="TRX-REP01", status="completed", result=investigation_result))
        db.commit()

        integrity = compute_evidence_integrity(test_case, investigation_result)
        assert integrity["verified"] is True
        assert len(integrity["sha256_hash"]) == 64
        assert integrity["algorithm"] == "SHA-256 (FIPS 180-4)"

        json_report = generate_forensic_json_report("TRX-REP01", db)
        assert json_report["case_overview"]["case_id"] == "TRX-REP01"
        assert json_report["chain_of_custody"]["sha256_hash"] == integrity["sha256_hash"]

        pdf_bytes = generate_forensic_pdf_report("TRX-REP01", db)
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 1000
        assert pdf_bytes.startswith(b"%PDF-")

        res_integrity = client.get("/api/cases/TRX-REP01/integrity")
        assert res_integrity.status_code == 200
        assert res_integrity.json()["data"]["verified"] is True

        res_json = client.get("/api/cases/TRX-REP01/export/json")
        assert res_json.status_code == 200
        assert res_json.json()["success"] is True

        res_pdf = client.get("/api/cases/TRX-REP01/export/pdf")
        assert res_pdf.status_code == 200
        assert res_pdf.headers["content-type"] == "application/pdf"
        assert b"%PDF-" in res_pdf.content

    finally:
        db.close()
