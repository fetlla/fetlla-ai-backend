from typing import Annotated, Optional
from fastapi import Depends, HTTPException, Query, WebSocket, status
from fastapi_injectable import injectable
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from db.models import Users, Chat
from dependencies import bcrypt_context, db_dependency
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from uuid import UUID

# Dev only
SECRET_KEY = '5cd3e5b6fff276840d7f9a0a974868cd10bf8753bd207d2443238f78c5cd11b8'
TEMP_KEY = 'a1334106e54d68431aa683f6a593df987ade21b58537c7a37332fa7028cf42b8'
ALGORITHM = 'HS256'


def authenticate_user(username: str, password: str, db) -> Users | bool:
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.password):
        return False
    return user


def create_access_token(username: str, user_id: int, role: str, expires_delta: timedelta):
    encode = {'sub': username, 'username': username, 'id': user_id, 'role': role}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


def create_temp_token(username: str, user_id: int, role: str, expires_delta: timedelta):
    encode = {'sub': username, 'username': username, 'id': user_id, 'role': role}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, TEMP_KEY, algorithm=ALGORITHM)


def validate_jwt(token: str, key: str):
    try:
        payload = jwt.decode(token, key, algorithms=[ALGORITHM])
        return {"success": True, "payload": payload}
    except jwt.ExpiredSignatureError:
        return {"success": False, "detail": "Token has expired"}
    except jwt.InvalidTokenError:
        return {"success": False, "detail": "Invalid token"}


@injectable
def inject_db(db: db_dependency):
    return db


security = HTTPBearer()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Get current authenticated user from JWT token"""
    token = credentials.credentials
    result = validate_jwt(token, SECRET_KEY)
    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result["detail"],
            headers={"WWW-Authenticate": "Bearer"},
        )
    return result["payload"]


# Type alias for current user dependency
current_user_dependency = Annotated[dict, Depends(get_current_user)]


async def get_token_from_websocket(
    websocket: WebSocket,
    token: Optional[str] = Query(None)
) -> dict:
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        raise Exception("Token required")

    result = validate_jwt(token, SECRET_KEY)

    if not result["success"]:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        raise Exception(result["detail"])

    return result["payload"]


async def verify_chat_ownership(chat_id: UUID, user_id: int, db: Session) -> Chat:
    """
    Verify that the user owns the specified chat.
    Raises HTTPException if chat not found or user doesn't own it.
    
    Args:
        chat_id: UUID of the chat to verify
        user_id: ID of the user requesting access
        db: Database session
        
    Returns:
        Chat object if verification succeeds
        
    Raises:
        HTTPException: 404 if chat not found or access denied
    """
    chat = db.query(Chat).filter(Chat.id == chat_id, Chat.user_id == user_id).first()
    
    if not chat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat not found or access denied"
        )
    
    return chat
