import jwt
from models import Users
from dependencies import bcrypt_context
from datetime import datetime, timezone, timedelta

# Dev only
SECRET_KEY = '5cd3e5b6fff276840d7f9a0a974868cd10bf8753bd207d2443238f78c5cd11b8'
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
