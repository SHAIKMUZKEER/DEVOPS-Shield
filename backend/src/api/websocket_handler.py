"""
WebSocket Handler for Real-time Pipeline Updates
Provides live updates for CI/CD pipelines, alerts, and fraud detection events
"""

import asyncio
import json
from typing import Set, Dict, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class WebSocketManager:
    """Manages WebSocket connections and broadcasts"""
    
    def __init__(self):
        self.active_connections: Set[Any] = set()
        self.pipeline_states: Dict[str, Dict] = {}
        
    async def connect(self, websocket):
        """Register a new WebSocket connection"""
        self.active_connections.add(websocket)
        logger.info(f"New WebSocket connection. Total: {len(self.active_connections)}")
        
        # Send initial state
        await self.send_personal_message({
            "type": "connection_established",
            "timestamp": datetime.now().isoformat(),
            "message": "Connected to DEVOPS-Shield real-time updates"
        }, websocket)
        
    def disconnect(self, websocket):
        """Remove a WebSocket connection"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: Dict, websocket):
        """Send message to specific connection"""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")
            self.disconnect(websocket)
    
    async def broadcast(self, message: Dict):
        """Broadcast message to all connected clients"""
        disconnected = set()
        
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting to connection: {e}")
                disconnected.add(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            self.disconnect(conn)
    
    async def broadcast_pipeline_update(self, pipeline_id: str, status: str, stage: str = None):
        """Broadcast pipeline status update"""
        message = {
            "type": "pipeline_update",
            "timestamp": datetime.now().isoformat(),
            "data": {
                "pipeline_id": pipeline_id,
                "status": status,
                "stage": stage
            }
        }
        await self.broadcast(message)
    
    async def broadcast_alert(self, alert_data: Dict):
        """Broadcast new security alert"""
        message = {
            "type": "security_alert",
            "timestamp": datetime.now().isoformat(),
            "data": alert_data
        }
        await self.broadcast(message)
    
    async def broadcast_fraud_event(self, event_data: Dict):
        """Broadcast fraud detection event"""
        message = {
            "type": "fraud_event",
            "timestamp": datetime.now().isoformat(),
            "data": event_data
        }
        await self.broadcast(message)
    
    async def broadcast_metrics_update(self, metrics: Dict):
        """Broadcast system metrics update"""
        message = {
            "type": "metrics_update",
            "timestamp": datetime.now().isoformat(),
            "data": metrics
        }
        await self.broadcast(message)

# Global WebSocket manager instance
ws_manager = WebSocketManager()


# FastAPI WebSocket endpoint integration
"""
Add this to your main.py:

from fastapi import WebSocket, WebSocketDisconnect
from src.api.websocket_handler import ws_manager

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    await ws_manager.connect(websocket)
    
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            
            # Echo back for heartbeat
            await ws_manager.send_personal_message({
                "type": "pong",
                "timestamp": datetime.now().isoformat()
            }, websocket)
            
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        ws_manager.disconnect(websocket)

# Example: Broadcast from your fraud detection
async def on_fraud_detected(event_data):
    await ws_manager.broadcast_fraud_event(event_data)
"""
