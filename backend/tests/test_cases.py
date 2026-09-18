"""
Unit tests for Case Management Database Operations & REST APIs
"""

from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models import Case, EmailRecord, Investigation, Indicator

client = TestClient(app)


def test_create_and_query_case():
    db = SessionLocal()
    try:
        # Clean up
        db.query(Indicator).filter(Indicator.case_id == "TRX-TESTCASE01").delete()
        db.query(Investigation).filter(Investigation.case_id == "TRX-TESTCASE01").delete()
        db.query(EmailRecord).filter(EmailRecord.case_id == "TRX-TESTCASE01").delete()
        db.query(Case).filter(Case.case_id == "TRX-TESTCASE01").delete()
        db.commit()

        # Create test case
        c = Case(case_id="TRX-TESTCASE01", status="completed", risk_level="HIGH", threat_score=80, source="eml_upload")
        db.add(c)
        db.flush()

        em = EmailRecord(case_id="TRX-TESTCASE01", sender="attacker@test.com", subject="Test Phish")
        db.add(em)

        inv = Investigation(case_id="TRX-TESTCASE01", status="completed", result={"threat_score": {"score": 80, "risk_level": "HIGH"}})
        db.add(inv)

        ind = Indicator(case_id="TRX-TESTCASE01", type="ip", value="1.2.3.4", risk="suspicious")
        db.add(ind)
        db.commit()

        # Query list
        res = client.get("/api/cases")
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert any(x["case_id"] == "TRX-TESTCASE01" for x in data["data"]["cases"])

        # Query details
        res_det = client.get("/api/cases/TRX-TESTCASE01")
        assert res_det.status_code == 200
        assert res_det.json()["data"]["case_id"] == "TRX-TESTCASE01"
    finally:
        db.close()
