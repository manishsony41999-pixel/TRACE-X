"""
TRACE-X Automatic Gmail Pipeline Processor
Coordinates the end-to-end webhook push event:
1. Sync history
2. Fetch newly added messages
3. Enforce duplicate protection
4. Execute central investigation pipeline
5. Store new Cases in the database
"""

from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models import GmailAccount
from app.services.gmail_auth import get_authenticated_gmail_service
from app.services.gmail_sync import sync_gmail_history
from app.services.gmail_reader import ingest_gmail_message


def process_gmail_push_notification(
    email_address: str,
    incoming_history_id: str,
    db: Session
) -> Dict[str, Any]:
    """
    Executes automated Gmail threat investigation on receiving a real-time Pub/Sub push notification.
    """
    account = db.query(GmailAccount).filter(
        GmailAccount.email == email_address,
        GmailAccount.is_active == True
    ).first()

    if not account:
        return {
            "status": "ignored",
            "message": f"Account '{email_address}' is not registered with TRACE-X."
        }

    # 1. Delta Sync
    sync_result = sync_gmail_history(
        email_address=email_address,
        db=db,
        incoming_history_id=incoming_history_id
    )

    new_message_ids: List[str] = sync_result.get("new_message_ids", [])
    if not new_message_ids:
        return {
            "status": "synchronized",
            "new_messages_count": 0,
            "processed_cases": [],
            "message": "Checkpoint updated. No new incoming messages to investigate."
        }

    # 2. Ingest and Investigate each new message
    gmail_service = get_authenticated_gmail_service(email_address, db)
    processed_cases: List[Dict[str, Any]] = []

    for msg_id in new_message_ids:
        try:
            ingest_result = ingest_gmail_message(
                gmail_service=gmail_service,
                gmail_message_id=msg_id,
                db=db,
                account_email=email_address
            )
            processed_cases.append({
                "message_id": msg_id,
                "case_id": ingest_result.get("case_id"),
                "duplicate": ingest_result.get("duplicate", False),
                "threat_score": ingest_result.get("pipeline_result", {}).get("threat_score", {}).get("score", 0),
                "risk_level": ingest_result.get("pipeline_result", {}).get("threat_score", {}).get("risk_level", "UNKNOWN")
            })
        except Exception as exc:
            processed_cases.append({
                "message_id": msg_id,
                "case_id": None,
                "error": str(exc)
            })

    return {
        "status": "processed",
        "email": email_address,
        "new_messages_count": len(new_message_ids),
        "processed_cases": processed_cases,
        "message": f"Successfully investigated {len(processed_cases)} incoming email(s)."
    }
