"""
TRACE-X Real-Time WebSocket Broadcaster
Broadcasts investigation progress and new case notifications to connected frontend clients.
"""

import asyncio
from typing import List, Dict, Any
from fastapi import WebSocket


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts real-time SOC events."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, event_type: str, data: Dict[str, Any]):
        message = {
            "event": event_type,
            "data": data
        }
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

    def broadcast_sync(self, event_type: str, data: Dict[str, Any]):
        """Synchronous wrapper allowing non-async worker functions to broadcast events."""
        try:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                asyncio.create_task(self.broadcast(event_type, data))
            else:
                asyncio.run(self.broadcast(event_type, data))
        except Exception:
            pass


# Global singleton instance
broadcaster = ConnectionManager()
