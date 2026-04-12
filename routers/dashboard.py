from fastapi import Depends, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.routing import APIRouter
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime
from uuid import UUID
import json
import requests
import os

from utils.auth_utils import get_current_user, get_token_from_websocket, verify_chat_ownership, current_user_dependency
from services.chat_service import ChatService
from llm.llm_rag import process_rag_message
from dependencies import db_dependency

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/auth-check")
async def auth_check(current_user: current_user_dependency):
    return {"message": "Authenticated"}


# In-memory mock for user current models
user_models = {}

@router.get("/models/list")
async def list_available_models(current_user: current_user_dependency):
    """List available LLM models from OpenRouter or local fallback"""
    api_key = os.getenv("OPENROUTER_API_KEY")
    
    # Always include the local model
    local_models = [
        {"id": "tinyllama", "name": "TinyLlama (Local)"}
    ]
    
    models_list = local_models

    if api_key:
        try:
            url = "https://openrouter.ai/api/v1/models"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "HTTP-Referer": "http://localhost:8000",
                "X-Title": "Atlas-0 CTF Lab",
            }
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            openrouter_data = response.json().get("data", [])
            formatted_models = [
                {"id": m["id"], "name": m.get("name", m["id"])}
                for m in openrouter_data
            ]
            
            # Combine local and remote models
            models_list = local_models + formatted_models
        except Exception as e:
            print(f"Error fetching OpenRouter models: {e}")

    current = user_models.get(current_user["id"], "TinyLlama (Local)")
    return {
        "models": [m["name"] for m in models_list],
        "current": current
    }

@router.get("/models/current")
async def get_current_model(current_user: current_user_dependency):
    current = user_models.get(current_user["id"], "TinyLlama (Local)")
    return {"model": current}

@router.post("/models/set")
async def set_model(request: dict, current_user: current_user_dependency):
    model_name = request.get("model_name")
    if model_name:
        user_models[current_user["id"]] = model_name
        return {"success": True, "model": model_name, "message": "Model updated"}
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="model_name is required")


# Chat Management Endpoints
@router.get("/chats/create")
async def create_chat(
    current_user: current_user_dependency,
    db: db_dependency
):
    """Create a new chat for the current user with auto-generated title"""
    title = f"Chat {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    chat = ChatService.create_chat(current_user["id"], title, db)
    return {
        "chat_id": str(chat.id),
        "title": chat.title,
        "created_at": chat.created_at,
        "updated_at": chat.updated_at
    }


@router.get("/chats")
async def list_chats(
    current_user: current_user_dependency,
    db: db_dependency
):
    """List all chats for the current user"""
    chats = ChatService.get_user_chats(current_user["id"], db)
    return [
        {
            "id": str(c.id),
            "title": c.title,
            "created_at": c.created_at,
            "updated_at": c.updated_at,
            "message_count": ChatService.get_message_count(c.id, db)
        }
        for c in chats
    ]


@router.get("/chats/{chat_id}/messages")
async def get_chat_messages(
    chat_id: UUID,
    current_user: current_user_dependency,
    db: db_dependency,
    limit: Optional[int] = None
):
    """Get all messages in a chat"""
    await verify_chat_ownership(chat_id, current_user["id"], db)
    messages = ChatService.get_chat_messages(chat_id, db, limit)
    return [
        {
            "id": m.id,
            "role": m.role,
            "content": m.content,
            "metadata": m.message_metadata,
            "created_at": m.created_at
        }
        for m in messages
    ]



@router.delete("/chats/{chat_id}")
async def delete_chat(
    chat_id: UUID,
    current_user: current_user_dependency,
    db: db_dependency
):
    """Delete a chat and all its messages"""
    await verify_chat_ownership(chat_id, current_user["id"], db)
    success = ChatService.delete_chat(chat_id, db)
    if success:
        return {"message": "Chat deleted successfully"}
    raise HTTPException(status_code=404, detail="Chat not found")


# WebSocket Chat Endpoint
@router.websocket("/chat/{chat_id}")
async def websocket_chat(
    websocket: WebSocket,
    chat_id: UUID,
    db: db_dependency,
    token: Optional[str] = None
):
    """
    WebSocket endpoint for real-time chat with RAG
    Connect with: ws://localhost:8000/dashboard/chat/{chat_id}?token=YOUR_JWT_TOKEN
    """
    
    # Authenticate via token query parameter
    try:
        current_user = await get_token_from_websocket(websocket, token)
    except Exception as e:
        return
    
    # Verify chat ownership
    try:
        await verify_chat_ownership(chat_id, current_user["id"], db)
    except HTTPException:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    await websocket.accept()
    
    # Send connection confirmation
    await websocket.send_json({
        "type": "connected",
        "chat_id": str(chat_id),
        "user_id": current_user["id"],
        "username": current_user.get("username", current_user.get("sub"))
    })
    
    try:
        while True:
            # Receive user message
            data = await websocket.receive_text()
            
            # Parse JSON with error handling
            try:
                message_data = json.loads(data)
                user_message = message_data.get("message", "")
            except json.JSONDecodeError as e:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Invalid JSON format: {str(e)}"
                })
                continue
            
            if not user_message:
                continue
            
            # Save user message to database
            ChatService.add_message(chat_id, "human", user_message, {}, db)
            
            # Get chat history (excluding the message we just added)
            history = ChatService.get_chat_messages(chat_id, db)
            
            # Get user's selected model
            model_name = user_models.get(current_user["id"])
            
            # Process through RAG graph
            try:
                result = await process_rag_message(user_message, history[:-1], model_name=model_name)
            except Exception as e:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Error processing message: {str(e)}"
                })
                continue
            
            # Save AI response to database
            ChatService.add_message(
                chat_id,
                "ai",
                result["ai_response"],
                result["metadata"],
                db
            )
            
            # Send AI response to client
            await websocket.send_json({
                "type": "message",
                "role": "ai",
                "content": result["ai_response"],
                "metadata": result["metadata"]
            })
            
    except WebSocketDisconnect:
        print(f"User {current_user.get('username', current_user.get('sub'))} disconnected from chat {chat_id}")
    except Exception as e:
        print(f"Error in WebSocket chat: {e}")
        try:
            await websocket.send_json({
                "type": "error",
                "message": "An unexpected error occurred"
            })
        except:
            pass
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)

