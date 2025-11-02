from typing import Annotated, Optional
from fastapi import Depends, HTTPException, Query, WebSocket, status
from fastapi_injectable import injectable
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from db.models import Users
from dependencies import bcrypt_context, db_dependency
from datetime import datetime, timezone, timedelta

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
    encode = {'sub': username, 'id': user_id, 'role': role}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


def create_temp_token(username: str, user_id: int, role: str, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id, 'role': role}
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
    token = credentials.credentials
    result = validate_jwt(token, SECRET_KEY)
    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result["detail"],
            headers={"WWW-Authenticate": "Bearer"},
        )

    return result["payload"]


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
