"""
TRACE-X Gmail Mailbox Watch Service
Configures and manages users.watch requests pushing push notifications to Google Cloud Pub/Sub.
Handles 7-day watch expiration and automated renewal.
"""

import os
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models import GmailAccount
from app.services.gmail_auth import get_authenticated_gmail_service


def start_gmail_watch(
    email_address: str,
    db: Session,
    topic_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Calls users().watch() to register a mailbox for real-time Pub/Sub push notifications.
    """
    pubsub_topic = topic_name or os.environ.get("GOOGLE_PUBSUB_TOPIC")
    if not pubsub_topic:
        return {
            "configured": False,
            "message": "GOOGLE_PUBSUB_TOPIC is not configured in backend .env. Set projects/{project}/topics/{topic}."
        }

    account = db.query(GmailAccount).filter(
        GmailAccount.email == email_address,
        GmailAccount.is_active == True
    ).first()

    if not account:
        raise ValueError(f"No active authorized Gmail account found for email: {email_address}")

    gmail_service = get_authenticated_gmail_service(email_address, db)

    watch_request_body = {
        "topicName": pubsub_topic,
        "labelIds": ["INBOX"]
    }

    watch_response = gmail_service.users().watch(
        userId="me",
        body=watch_request_body
    ).execute()

    history_id = watch_response.get("historyId")
    expiration_ms = int(watch_response.get("expiration", "0"))
    
    if expiration_ms > 0:
        expiration_dt = datetime.fromtimestamp(expiration_ms / 1000.0, tz=timezone.utc)
    else:
        # Default Gmail watch duration is 7 days
        expiration_dt = datetime.now(timezone.utc) + timedelta(days=7)

    account.history_id = str(history_id)
    account.watch_expiration = expiration_dt
    account.updated_at = datetime.now(timezone.utc)
    db.commit()

    return {
        "configured": True,
        "email": email_address,
        "history_id": history_id,
        "watch_expiration": expiration_dt.isoformat(),
        "topic_name": pubsub_topic,
        "message": "Gmail mailbox watch successfully activated."
    }


def stop_gmail_watch(email_address: str, db: Session) -> Dict[str, Any]:
    """Calls users().stop() to cancel the active push subscription."""
    account = db.query(GmailAccount).filter(
        GmailAccount.email == email_address,
        GmailAccount.is_active == True
    ).first()

    if not account:
        raise ValueError(f"No active authorized Gmail account found for email: {email_address}")

    gmail_service = get_authenticated_gmail_service(email_address, db)
    gmail_service.users().stop(userId="me").execute()

    account.watch_expiration = None
    db.commit()

    return {
        "email": email_address,
        "watch_active": False,
        "message": "Gmail watch stopped successfully."
    }


def renew_gmail_watch_if_needed(email_address: str, db: Session, hours_threshold: int = 24) -> Dict[str, Any]:
    """Checks if the watch subscription is expiring soon and renews it."""
    account = db.query(GmailAccount).filter(
        GmailAccount.email == email_address,
        GmailAccount.is_active == True
    ).first()

    if not account:
        raise ValueError(f"Account '{email_address}' not found.")

    now = datetime.now(timezone.utc)
    if not account.watch_expiration or (account.watch_expiration - now) < timedelta(hours=hours_threshold):
        return start_gmail_watch(email_address, db)

    return {
        "email": email_address,
        "renewed": False,
        "watch_expiration": account.watch_expiration.isoformat(),
        "message": "Watch is active and not yet within the renewal threshold window."
    }
