"""
TRACE-X Google OAuth 2.0 Integration Service
Handles OAuth 2.0 authorization URL generation, code-to-token exchange,
token persistence in database, and building authenticated Gmail API service clients.
"""

import os
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from sqlalchemy.orm import Session
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build, Resource

from app.models import GmailAccount


SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/userinfo.email"
]


def get_client_config() -> Optional[Dict[str, Any]]:
    """Loads Google OAuth 2.0 credentials from environment variables."""
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.environ.get(
        "GOOGLE_REDIRECT_URI",
        "http://127.0.0.1:8000/api/gmail/callback"
    )

    if not client_id or not client_secret:
        return None

    return {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [redirect_uri]
        }
    }


def get_authorization_url(
    custom_redirect_uri: Optional[str] = None
) -> Dict[str, Any]:
    """Generates the Google OAuth 2.0 consent URL."""

    config = get_client_config()

    if not config:
        return {
            "configured": False,
            "auth_url": None,
            "message": (
                "Google OAuth is not configured. "
                "Please set GOOGLE_CLIENT_ID and "
                "GOOGLE_CLIENT_SECRET in backend environment."
            )
        }

    redirect_uri = custom_redirect_uri or config["web"]["redirect_uris"][0]

    # Generate one secure value that will be used as both:
    # 1. OAuth state
    # 2. PKCE code verifier
    #
    # token_urlsafe(96) produces a high-entropy value within
    # Google's 43-128 character PKCE verifier requirement.
    state = secrets.token_urlsafe(96)

    flow = Flow.from_client_config(
        config,
        scopes=SCOPES,
        redirect_uri=redirect_uri,
        code_verifier=state,
        autogenerate_code_verifier=False
    )

    auth_url, returned_state = flow.authorization_url(
        state=state,
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )

    return {
        "configured": True,
        "auth_url": auth_url,
        "state": returned_state,
        "message": "Authorization URL generated successfully."
    }


def exchange_code_for_tokens(
    code: str,
    db: Session,
    state: Optional[str] = None,
    custom_redirect_uri: Optional[str] = None
) -> Dict[str, Any]:
    """Exchanges the authorization code for access and refresh tokens."""

    config = get_client_config()

    if not config:
        raise ValueError(
            "Google OAuth credentials are not configured in environment."
        )

    if not state:
        raise ValueError(
            "Missing OAuth state. Please start the Gmail connection again."
        )

    redirect_uri = custom_redirect_uri or config["web"]["redirect_uris"][0]

    # Recreate the OAuth flow using the same PKCE verifier
    # that was sent during the authorization request.
    flow = Flow.from_client_config(
        config,
        scopes=SCOPES,
        redirect_uri=redirect_uri,
        code_verifier=state,
        autogenerate_code_verifier=False
    )

    flow.fetch_token(code=code)

    credentials = flow.credentials

    # Retrieve user's email address
    user_info_service = build(
        "oauth2",
        "v2",
        credentials=credentials
    )

    user_info = user_info_service.userinfo().get().execute()
    email_address = user_info.get("email")

    if not email_address:
        raise ValueError(
            "Could not retrieve email address from authorized Google account."
        )

    # Save or update GmailAccount in database
    account = (
        db.query(GmailAccount)
        .filter(GmailAccount.email == email_address)
        .first()
    )

    if not account:
        account = GmailAccount(email=email_address)
        db.add(account)

    account.access_token = credentials.token
    account.refresh_token = (
        credentials.refresh_token or account.refresh_token
    )
    account.token_uri = credentials.token_uri
    account.client_id = credentials.client_id
    account.client_secret = credentials.client_secret
    account.scopes = credentials.scopes
    account.expiry = credentials.expiry
    account.is_active = True
    account.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(account)

    return {
        "email": account.email,
        "is_active": account.is_active,
        "has_refresh_token": bool(account.refresh_token),
        "created_at": (
            account.created_at.isoformat()
            if account.created_at
            else None
        )
    }


def get_authenticated_gmail_service(
    email_address: str,
    db: Session
) -> Resource:
    """Constructs an authenticated Gmail API service client."""

    account = (
        db.query(GmailAccount)
        .filter(
            GmailAccount.email == email_address,
            GmailAccount.is_active == True
        )
        .first()
    )

    if not account:
        raise ValueError(
            f"No active authorized Gmail account found for email: "
            f"{email_address}"
        )

    credentials = Credentials(
        token=account.access_token,
        refresh_token=account.refresh_token,
        token_uri=account.token_uri,
        client_id=account.client_id,
        client_secret=account.client_secret,
        scopes=account.scopes
    )

    return build("gmail", "v1", credentials=credentials)


def get_gmail_connection_status(
    db: Session
) -> Dict[str, Any]:
    """Returns the current Gmail connection status."""

    config = get_client_config()
    is_configured = config is not None

    active_accounts = (
        db.query(GmailAccount)
        .filter(GmailAccount.is_active == True)
        .all()
    )

    account_list = []

    for acc in active_accounts:
        account_list.append({
            "email": acc.email,
            "connected_at": (
                acc.created_at.isoformat()
                if acc.created_at
                else None
            ),
            "watch_active": bool(
                acc.watch_expiration
                and acc.watch_expiration > datetime.now(timezone.utc)
            ),
            "last_history_id": acc.history_id
        })

    return {
        "oauth_configured": is_configured,
        "connected_accounts_count": len(account_list),
        "accounts": account_list
    }