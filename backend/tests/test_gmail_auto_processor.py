"""
Unit tests for End-to-End Automatic Gmail Ingestion Pipeline
"""

from app.services.gmail_auto_processor import process_gmail_push_notification
from app.database import SessionLocal


def test_process_gmail_push_notification_unregistered_account():
    db = SessionLocal()
    try:
        res = process_gmail_push_notification(
            email_address="unregistered_user@gmail.com",
            incoming_history_id="99999",
            db=db
        )
        assert res["status"] == "ignored"
        assert "not registered" in res["message"]
    finally:
        db.close()
