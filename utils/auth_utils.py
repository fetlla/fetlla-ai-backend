import jwt
from fastapi_injectable import injectable

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