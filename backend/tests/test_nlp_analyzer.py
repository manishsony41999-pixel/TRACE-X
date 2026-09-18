"""
TRACE-X Machine Learning & NLP Phishing Analyzer Tests
"""

from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models import Case, Investigation
from app.services.nlp_analyzer import analyze_nlp_content

client = TestClient(app)


def test_nlp_phishing_detection_high_urgency():
    subject = "URGENT ACTION REQUIRED: Account Suspended"
    body = (
        "Dear Customer, We detected unusual activity on your account. "
        "Your account will be suspended within 24 hours unless you verify your identity. "
        "Please click here to log in and confirm your password immediately!"
    )

    result = analyze_nlp_content(subject=subject, body_text=body)

    assert result["phishing_probability"] >= 0.70
    assert result["risk_tier"] in ["HIGH", "CRITICAL"]
    assert "urgency_coercion" in result["intents_detected"]
    assert "credential_harvesting" in result["intents_detected"]
    assert len(result["matched_keywords"]) >= 3
    assert result["lexical_features"]["word_count"] > 10


def test_nlp_benign_text_low_score():
    subject = "Project Sync Notes and Next Steps"
    body = (
        "Hi Alex, thanks for the great discussion today. "
        "I have drafted the quarterly report and will share the preview tomorrow morning. "
        "Let me know if you need anything else."
    )

    result = analyze_nlp_content(subject=subject, body_text=body)

    assert result["phishing_probability"] < 0.25
    assert result["risk_tier"] == "LOW"
    assert len(result["intents_detected"]) == 0
    assert "normal conversational tone" in result["summary"]


def test_nlp_financial_lure_detection():
    subject = "Unpaid Invoice Remittance"
    body = "Please find the overdue invoice attached. Kindly submit wire transfer or send bitcoin to our security team."

    result = analyze_nlp_content(subject=subject, body_text=body)

    assert "financial_lure" in result["intents_detected"]
    assert any(k["category"] == "financial_lure" for k in result["matched_keywords"])


def test_nlp_empty_content_graceful():
    result = analyze_nlp_content(subject="", body_text="")
    assert result["phishing_probability"] == 0.0
    assert result["risk_tier"] == "LOW"


def test_nlp_api_endpoint():
    db = SessionLocal()
    try:
        db.query(Investigation).filter(Investigation.case_id == "TRX-NLP01").delete()
        db.query(Case).filter(Case.case_id == "TRX-NLP01").delete()
        db.commit()

        mock_nlp = {
            "phishing_probability": 0.88,
            "risk_tier": "CRITICAL",
            "intents_detected": ["urgency_coercion"],
            "summary": "High urgency coercive email."
        }

        test_case = Case(case_id="TRX-NLP01", status="completed", risk_level="CRITICAL", threat_score=85, source="eml_upload")
        db.add(test_case)
        db.flush()
        db.add(Investigation(case_id="TRX-NLP01", status="completed", result={"nlp_analysis": mock_nlp}))
        db.commit()

        res = client.get("/api/cases/TRX-NLP01/nlp")
        assert res.status_code == 200
        json_data = res.json()
        assert json_data["success"] is True
        assert json_data["data"]["phishing_probability"] == 0.88
    finally:
        db.close()
