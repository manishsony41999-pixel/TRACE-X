"""
Unit tests for Google OAuth 2.0 Integration & Credentials
"""

from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models import GmailAccount
from app.services.gmail_auth import get_authorization_url, get_gmail_connection_status

client = TestClient(app)


def test_gmail_status_unconfigured():
    db = SessionLocal()
    try:
        status = get_gmail_connection_status(db)
        assert "oauth_configured" in status
        assert "connected_accounts_count" in status
    finally:
        db.close()


def test_get_authorization_url_fallback():
    # When GOOGLE_CLIENT_ID not set, returns configured: False
    res = get_authorization_url()
    assert res["configured"] is False
    assert res["auth_url"] is None
