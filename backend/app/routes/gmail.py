"""
TRACE-X Gmail Watch, Webhook & Synchronization Routes
"""
import json
import base64
from fastapi import APIRouter, Depends, Request, HTTPException, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any

from app.database import get_db
from app.models import GmailAccount
from app.services.gmail_auth import (
    get_authorization_url,
    exchange_code_for_tokens,
    get_gmail_connection_status
)
from app.services.gmail_watch import start_gmail_watch, stop_gmail_watch, renew_gmail_watch_if_needed
from app.services.gmail_sync import sync_gmail_history
from app.services.gmail_auto_processor import process_gmail_push_notification

router = APIRouter(prefix="/gmail", tags=["Gmail"])


def decode_pubsub_payload(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decodes Google Cloud Pub/Sub push notification envelope.
    Extracts base64url message.data containing emailAddress and historyId.
    """
    message = body.get("message")
    if not message:
        if "emailAddress" in body and "historyId" in body:
            return {
                "email_address": body["emailAddress"],
                "history_id": str(body["historyId"])
            }
        raise ValueError("Invalid Google Cloud Pub/Sub payload structure: 'message' missing.")

    data_b64 = message.get("data", "")
    if not data_b64:
        raise ValueError("Pub/Sub message contains empty 'data' field.")

    try:
        decoded_json_str = base64.b64decode(data_b64).decode("utf-8")
        parsed_data = json.loads(decoded_json_str)
    except Exception as exc:
        raise ValueError(f"Failed to decode base64 payload: {str(exc)}")

    email_address = parsed_data.get("emailAddress")
    history_id = parsed_data.get("historyId")

    if not email_address or not history_id:
        raise ValueError("Decoded Pub/Sub payload missing 'emailAddress' or 'historyId'.")

    return {
        "email_address": email_address,
        "history_id": str(history_id)
    }


@router.post("/webhook")
async def gmail_pubsub_webhook(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Google Cloud Pub/Sub Webhook:
    Receives real-time Gmail mailbox push notifications, decodes account and historyId,
    dispatches automatic history synchronization, retrieves newly added emails,
    and runs them through the central investigation pipeline to create Cases automatically.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "data": None, "error": {"message": "Invalid JSON body."}}
        )

    try:
        event = decode_pubsub_payload(body)
    except Exception as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "data": None, "error": {"message": str(exc)}}
        )

    email_address = event["email_address"]
    new_history_id = event["history_id"]

    account = db.query(GmailAccount).filter(
        GmailAccount.email == email_address,
        GmailAccount.is_active == True
    ).first()

    if not account:
        return {
            "success": True,
            "data": {
                "status": "ignored",
                "message": f"Account '{email_address}' is not registered with TRACE-X."
            },
            "error": None
        }

    try:
        auto_result = process_gmail_push_notification(
            email_address=email_address,
            incoming_history_id=new_history_id,
            db=db
        )
        return {
            "success": True,
            "data": {
                "status": "processed",
                "result": auto_result
            },
            "error": None
        }
    except Exception as exc:
        return {
            "success": True,
            "data": {
                "status": "acknowledged_with_error",
                "error_detail": str(exc)
            },
            "error": None
        }


@router.post("/sync")
def trigger_history_sync(
    email: Optional[str] = None,
    history_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Manually triggers Gmail History synchronization to find newly added messages.
    """
    account = db.query(GmailAccount).filter(GmailAccount.email == email if email else True, GmailAccount.is_active == True).first()
    if not account:
        return JSONResponse(status_code=400, content={"success": False, "data": None, "error": {"message": "No active Gmail account found."}})

    try:
        sync_result = sync_gmail_history(
            email_address=account.email,
            db=db,
            incoming_history_id=history_id
        )
        return {"success": True, "data": sync_result, "error": None}
    except Exception as exc:
        return JSONResponse(status_code=500, content={"success": False, "data": None, "error": {"message": str(exc)}})


@router.get("/status")
def gmail_status(db: Session = Depends(get_db)):
    """Returns the current Gmail OAuth connection status and authorized accounts."""
    status_data = get_gmail_connection_status(db)
    return {"success": True, "data": status_data, "error": None}


@router.get("/connect")
def connect_gmail(redirect_uri: Optional[str] = None):
    """Initiates Gmail OAuth 2.0 authorization flow and returns authorization URL."""
    auth_data = get_authorization_url(redirect_uri)
    if not auth_data["configured"]:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "data": None, "error": {"message": auth_data["message"]}}
        )
    return {"success": True, "data": auth_data, "error": None}


@router.get("/callback")
def gmail_callback(
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Handles OAuth 2.0 redirect callback with authorization code."""
    if error:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "data": None, "error": {"message": f"OAuth Error: {error}"}}
        )

    if not code:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "data": None, "error": {"message": "Missing authorization code."}}
        )

    try:
        account_data = exchange_code_for_tokens(
            code,
            db,
            state=state
        )

        return RedirectResponse(
            url="https://trace-x-frontend.onrender.com/?gmail_connected=true"
        )

    except Exception as exc:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "data": None,
                "error": {"message": str(exc)}
            }
        )

@router.post("/watch/start")
def activate_watch(
    email: str,
    topic: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Activates Gmail Mailbox Watch to receive Pub/Sub push notifications."""
    try:
        result = start_gmail_watch(email, db, topic)
        return {"success": True, "data": result, "error": None}
    except Exception as exc:
        return JSONResponse(status_code=400, content={"success": False, "data": None, "error": {"message": str(exc)}})


@router.post("/watch/stop")
def deactivate_watch(
    email: str,
    db: Session = Depends(get_db)
):
    """Deactivates Gmail Mailbox Watch."""
    try:
        result = stop_gmail_watch(email, db)
        return {"success": True, "data": result, "error": None}
    except Exception as exc:
        return JSONResponse(status_code=400, content={"success": False, "data": None, "error": {"message": str(exc)}})


@router.post("/watch/renew")
def renew_watch(
    email: str,
    db: Session = Depends(get_db)
):
    """Checks and renews Gmail watch if expiring within 24 hours."""
    try:
        result = renew_gmail_watch_if_needed(email, db)
        return {"success": True, "data": result, "error": None}
    except Exception as exc:
        return JSONResponse(status_code=400, content={"success": False, "data": None, "error": {"message": str(exc)}})
