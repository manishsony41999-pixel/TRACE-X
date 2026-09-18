"""
TRACE-X WebSocket Routes
Provides real-time event streaming for SOC dashboard updates.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.broadcaster import broadcaster

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/cases")
async def websocket_cases_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time case updates and live investigation progress.
    Clients receive events: 'case_detected', 'stage_update', and 'case_completed'.
    """
    await broadcaster.connect(websocket)
    try:
        await websocket.send_json({
            "event": "connected",
            "data": {"message": "TRACE-X Real-Time Forensic Stream Connected"}
        })
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        broadcaster.disconnect(websocket)
    except Exception:
        broadcaster.disconnect(websocket)
