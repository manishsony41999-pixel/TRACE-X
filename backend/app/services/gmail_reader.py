"""
TRACE-X Gmail Message Ingestion Service
Retrieves raw RFC 822 email payloads via users.messages.get(format='raw'),
decodes Base64URL content, enforces duplicate protection, and dispatches to central pipeline.
"""

import base64
import uuid
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from googleapiclient.discovery import Resource

from app.models import EmailRecord, Case
from app.services.pipeline import run_investigation_pipeline


def fetch_raw_gmail_message(gmail_service: Resource, message_id: str, user_id: str = "me") -> bytes:
    """
    Fetches raw RFC 822 email bytes directly from Gmail API using users.messages.get(format='raw').
    """
    message_response = gmail_service.users().messages().get(
        userId=user_id,
        id=message_id,
        format="raw"
    ).execute()

    raw_base64url = message_response.get("raw", "")
    if not raw_base64url:
        raise ValueError(f"Gmail message '{message_id}' returned an empty raw payload.")

    raw_bytes = base64.urlsafe_b64decode(raw_base64url.encode("ASCII"))
    return raw_bytes


def is_gmail_message_processed(gmail_message_id: str, db: Session) -> Optional[Case]:
    """
    Checks if a Gmail message ID has already been investigated to prevent duplicate processing.
    """
    existing_record = db.query(EmailRecord).filter(
        EmailRecord.gmail_message_id == gmail_message_id
    ).first()

    if existing_record and existing_record.case:
        return existing_record.case
    return None


def ingest_gmail_message(
    gmail_service: Resource,
    gmail_message_id: str,
    db: Session,
    account_email: Optional[str] = None
) -> Dict[str, Any]:
    """
    Ingests an email from Gmail API, validates uniqueness, and routes it to the central pipeline.
    """
    existing_case = is_gmail_message_processed(gmail_message_id, db)
    if existing_case:
        return {
            "duplicate": True,
            "case_id": existing_case.case_id,
            "message": f"Gmail message '{gmail_message_id}' already processed in case '{existing_case.case_id}'."
        }

    raw_email_bytes = fetch_raw_gmail_message(gmail_service, gmail_message_id)

    case_id = f"TRX-GMAIL-{uuid.uuid4().hex[:8].upper()}"

    pipeline_result = run_investigation_pipeline(
        raw_email_bytes=raw_email_bytes,
        case_id=case_id,
        source="gmail_automatic",
        gmail_message_id=gmail_message_id,
        filename=f"gmail_{gmail_message_id}.eml",
        db_session=db
    )

    return {
        "duplicate": False,
        "case_id": case_id,
        "pipeline_result": pipeline_result
    }
