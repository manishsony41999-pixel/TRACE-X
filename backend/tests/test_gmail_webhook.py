"""
Unit tests for Gmail Pub/Sub Webhook Endpoint
"""

import json
import base64
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models import GmailAccount

client = TestClient(app)


def test_gmail_webhook_pubsub_envelope():
    db = SessionLocal()
    try:
        db.query(GmailAccount).filter(GmailAccount.email == "webhook_test@gmail.com").delete()
        db.commit()

        acc = GmailAccount(
            email="webhook_test@gmail.com",
            access_token="test_token",
            refresh_token="test_refresh",
            history_id="1000",
            is_active=True
        )
        db.add(acc)
        db.commit()
    finally:
        db.close()

    inner_payload = {
        "emailAddress": "webhook_test@gmail.com",
        "historyId": "1050"
    }
    encoded_data = base64.b64encode(json.dumps(inner_payload).encode("utf-8")).decode("utf-8")
    
    pubsub_body = {
        "message": {
            "data": encoded_data,
            "message_id": "pubsub_msg_98765",
            "publish_time": "2026-09-19T00:55:00.000Z"
        },
        "subscription": "projects/test-project/subscriptions/tracex-sub"
    }

    res = client.post("/api/gmail/webhook", json=pubsub_body)
    assert res.status_code == 200
    json_data = res.json()
    assert json_data["success"] is True
    assert json_data["data"]["status"] in ["processed", "acknowledged_with_error"]


def test_gmail_webhook_direct_json_payload():
    direct_body = {
        "emailAddress": "webhook_test@gmail.com",
        "historyId": "1060"
    }
    res = client.post("/api/gmail/webhook", json=direct_body)
    assert res.status_code == 200
    json_data = res.json()
    assert json_data["success"] is True
    assert json_data["data"]["status"] in ["processed", "acknowledged_with_error"]
