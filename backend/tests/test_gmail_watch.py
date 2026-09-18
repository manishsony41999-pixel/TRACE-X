"""
Unit tests for Gmail Mailbox Watch Service
"""

from app.services.gmail_watch import start_gmail_watch
from app.database import SessionLocal
from app.models import GmailAccount


def test_gmail_watch_unconfigured_topic():
    db = SessionLocal()
    try:
        db.query(GmailAccount).filter(GmailAccount.email == "watch_test@gmail.com").delete()
        db.commit()

        acc = GmailAccount(email="watch_test@gmail.com", access_token="tok", refresh_token="ref", is_active=True)
        db.add(acc)
        db.commit()

        res = start_gmail_watch("watch_test@gmail.com", db, topic_name="")
        assert res["configured"] is False
        assert "not configured" in res["message"]
    finally:
        db.close()
