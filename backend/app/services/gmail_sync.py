"""
TRACE-X Gmail History Synchronization Service
Uses users.history.list to retrieve only changes that occurred since the last historyId checkpoint.
Filters for 'messagesAdded' events to isolate new incoming emails.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models import GmailAccount
from app.services.gmail_auth import get_authenticated_gmail_service


def sync_gmail_history(
    email_address: str,
    db: Session,
    incoming_history_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Performs delta synchronization against Gmail History API using stored startHistoryId checkpoint.
    """
    account = db.query(GmailAccount).filter(
        GmailAccount.email == email_address,
        GmailAccount.is_active == True
    ).first()

    if not account:
        raise ValueError(f"No active authorized Gmail account found for email: {email_address}")

    start_history_id = account.history_id

    if not start_history_id:
        if incoming_history_id:
            account.history_id = incoming_history_id
            db.commit()
        return {
            "email": email_address,
            "new_message_ids": [],
            "message": "First synchronization checkpoint initialized. Stored initial historyId."
        }

    gmail_service = get_authenticated_gmail_service(email_address, db)

    new_message_ids: List[str] = []
    page_token = None
    latest_history_id = start_history_id

    try:
        while True:
            history_response = gmail_service.users().history().list(
                userId="me",
                startHistoryId=start_history_id,
                historyTypes=["messageAdded"],
                pageToken=page_token
            ).execute()

            latest_history_id = history_response.get("historyId", latest_history_id)
            history_records = history_response.get("history", [])

            for record in history_records:
                messages_added = record.get("messagesAdded", [])
                for item in messages_added:
                    msg = item.get("message", {})
                    msg_id = msg.get("id")
                    if msg_id and msg_id not in new_message_ids:
                        new_message_ids.append(msg_id)

            page_token = history_response.get("nextPageToken")
            if not page_token:
                break

    except Exception as exc:
        err_msg = str(exc)
        # If historyId is too old (404 / expired), update checkpoint to incoming_history_id
        if "404" in err_msg or "historyId" in err_msg.lower():
            if incoming_history_id:
                account.history_id = incoming_history_id
                db.commit()
            return {
                "email": email_address,
                "new_message_ids": [],
                "error": "Checkpoint expired. Updated to latest historyId.",
                "resynchronized": True
            }
        raise exc

    # Update checkpoint
    if incoming_history_id:
        account.history_id = incoming_history_id
    elif latest_history_id:
        account.history_id = str(latest_history_id)

    account.updated_at = datetime.now(timezone.utc)
    db.commit()

    return {
        "email": email_address,
        "start_history_id": start_history_id,
        "latest_history_id": account.history_id,
        "new_message_ids": new_message_ids,
        "new_messages_count": len(new_message_ids)
    }
