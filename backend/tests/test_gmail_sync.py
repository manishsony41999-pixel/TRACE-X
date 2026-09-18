"""
Unit tests for Gmail History Synchronization
"""

from unittest.mock import MagicMock, patch
from app.services.gmail_sync import sync_gmail_history
from app.database import SessionLocal
from app.models import GmailAccount


def test_sync_gmail_history_initial_checkpoint():
    db = SessionLocal()
    try:
        db.query(GmailAccount).filter(GmailAccount.email == "sync_test@gmail.com").delete()
        db.commit()

        acc = GmailAccount(email="sync_test@gmail.com", is_active=True, history_id=None)
        db.add(acc)
        db.commit()

        res = sync_gmail_history("sync_test@gmail.com", db, incoming_history_id="123456")
        assert res["email"] == "sync_test@gmail.com"
        assert res["new_message_ids"] == []

        db.refresh(acc)
        assert acc.history_id == "123456"
    finally:
        db.close()
