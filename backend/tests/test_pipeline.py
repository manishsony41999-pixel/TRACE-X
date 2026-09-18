"""
Unit tests for Central Investigation Pipeline
"""

from app.services.pipeline import run_investigation_pipeline
from app.database import SessionLocal
from app.models import Case, EmailRecord, Investigation, Indicator


def test_run_investigation_pipeline_clean():
    raw_email = (
        b"From: legitimate@company.com\r\n"
        b"To: user@company.com\r\n"
        b"Subject: Weekly Update\r\n"
        b"Date: Fri, 19 Sep 2026 00:00:00 +0000\r\n"
        b"Message-ID: <clean-123@company.com>\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Team, here is the weekly project update."
    )

    db = SessionLocal()
    try:
        db.query(Indicator).filter(Indicator.case_id == "TRX-PIPE01").delete()
        db.query(Investigation).filter(Investigation.case_id == "TRX-PIPE01").delete()
        db.query(EmailRecord).filter(EmailRecord.case_id == "TRX-PIPE01").delete()
        db.query(Case).filter(Case.case_id == "TRX-PIPE01").delete()
        db.commit()

        res = run_investigation_pipeline(
            raw_email_bytes=raw_email,
            case_id="TRX-PIPE01",
            source="eml_upload",
            db_session=db
        )

        assert res["status"] == "completed"
        assert res["case_id"] == "TRX-PIPE01"
        assert res["threat_score"]["risk_level"] in ["LOW", "MEDIUM"]
        assert "email" in res
        assert "header_analysis" in res
        assert "authentication" in res
        assert "iocs" in res
        assert "url_analysis" in res
        assert "intelligence" in res
        assert "nlp_analysis" in res

        # Verify DB records
        saved_case = db.query(Case).filter(Case.case_id == "TRX-PIPE01").first()
        assert saved_case is not None
        assert saved_case.status == "completed"
    finally:
        db.close()


def test_run_investigation_pipeline_malicious():
    raw_email = (
        b"From: PayPal Billing <support@paypal.com@bad-relay.xyz>\r\n"
        b"Reply-To: stealer@evil.com\r\n"
        b"Subject: URGENT: Account Suspended within 24 hours\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Dear Customer, Click here to verify your password: http://198.51.100.25/login"
    )

    db = SessionLocal()
    try:
        db.query(Indicator).filter(Indicator.case_id == "TRX-PIPE02").delete()
        db.query(Investigation).filter(Investigation.case_id == "TRX-PIPE02").delete()
        db.query(EmailRecord).filter(EmailRecord.case_id == "TRX-PIPE02").delete()
        db.query(Case).filter(Case.case_id == "TRX-PIPE02").delete()
        db.commit()

        res = run_investigation_pipeline(
            raw_email_bytes=raw_email,
            case_id="TRX-PIPE02",
            source="eml_upload",
            db_session=db
        )

        assert res["threat_score"]["risk_level"] in ["HIGH", "CRITICAL"]
        assert res["threat_score"]["score"] >= 50
    finally:
        db.close()
