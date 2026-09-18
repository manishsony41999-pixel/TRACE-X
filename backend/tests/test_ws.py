"""
TRACE-X WebSocket Tests
Tests real-time WebSocket connection and broadcasting mechanisms.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.broadcaster import broadcaster


def test_websocket_connection_and_greeting():
    client = TestClient(app)
    with client.websocket_connect("/api/ws/cases") as websocket:
        data = websocket.receive_json()
        assert data["event"] == "connected"
        assert "TRACE-X Real-Time Forensic Stream Connected" in data["data"]["message"]


@pytest.mark.anyio
async def test_broadcaster_async():
    client = TestClient(app)
    with client.websocket_connect("/api/ws/cases") as websocket:
        _ = websocket.receive_json()

        await broadcaster.broadcast("stage_update", {
            "case_id": "WS-TEST-001",
            "stage": "Testing live broadcast...",
            "step": 1,
            "total_steps": 5
        })

        data = websocket.receive_json()
        assert data["event"] == "stage_update"
        assert data["data"]["case_id"] == "WS-TEST-001"
        assert data["data"]["step"] == 1


def test_broadcaster_sync_fallback():
    broadcaster.broadcast_sync("test_sync_event", {"status": "ok"})
    assert True
