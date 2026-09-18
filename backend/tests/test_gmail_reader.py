"""
Unit tests for Gmail Message Ingestion & Duplicate Protection
"""

import base64
from unittest.mock import MagicMock
from app.services.gmail_reader import fetch_raw_gmail_message, is_gmail_message_processed
from app.database import SessionLocal
from app.models import EmailRecord, Case


def test_fetch_raw_gmail_message_decoding():
    mock_service = MagicMock()
    raw_rfc = b"From: user@gmail.com\r\nSubject: Test\r\n\r\nBody text"
    raw_b64url = base64.urlsafe_b64encode(raw_rfc).decode("utf-8")
    
    mock_service.users().messages().get().execute.return_value = {
        "id": "msg_12345",
        "raw": raw_b64url
    }

    retrieved_bytes = fetch_raw_gmail_message(mock_service, "msg_12345")
    assert retrieved_bytes == raw_rfc
    assert b"From: user@gmail.com" in retrieved_bytes


def test_is_gmail_message_processed_duplicate_check():
    db = SessionLocal()
    try:
        db.query(EmailRecord).filter(EmailRecord.case_id == "TRX-DUP01").delete()
        db.query(Case).filter(Case.case_id == "TRX-DUP01").delete()
        db.commit()

        test_case = Case(case_id="TRX-DUP01", status="completed", risk_level="LOW", threat_score=0, source="gmail_automatic")
        db.add(test_case)
        db.flush()
        
        email_rec = EmailRecord(case_id="TRX-DUP01", gmail_message_id="gmail_msg_9999", sender="test@test.com")
        db.add(email_rec)
        db.commit()

        found_case = is_gmail_message_processed("gmail_msg_9999", db)
        assert found_case is not None
        assert found_case.case_id == "TRX-DUP01"

        not_found = is_gmail_message_processed("gmail_msg_nonexistent", db)
        assert not_found is None
    finally:
        db.close()
