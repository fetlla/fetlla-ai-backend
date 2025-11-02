from fastapi import Depends, WebSocket, WebSocketDisconnect
from fastapi.routing import APIRouter

from utils.auth_utils import get_current_user, get_token_from_websocket

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/auth-check")
async def auth_check(current_user=Depends(get_current_user)):
    return {"message": "Authenticated"}


@router.websocket("/chat")
async def websocket_endpoint(
    websocket: WebSocket,
    current_user: dict = Depends(get_token_from_websocket)
):
    await websocket.accept()

    await websocket.send_json({
        "type": "auth_success",
        "user_id": current_user["id"],
        "username": current_user["sub"]
    })

    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(f"Echo: {data}")

    except WebSocketDisconnect:
        print(f"User {current_user['sub']} disconnected")
        pass
