from datetime import timedelta, datetime
from fastapi.params import File
from fastapi import Header, Depends
from fastapi.routing import APIRouter
from fastapi import HTTPException, UploadFile, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from starlette import status
from io import BytesIO
from PIL import Image as PILImage
from exif import Image
import uuid
from starlette.responses import Response

from dependencies import bcrypt_context, db_dependency
from llm.langchain_llm import langgraph_agent_login, langgraph_agent_2fa
from llm.llm_logic import  llm_based_login, LoginRequest
from db.models import Users,TwoFactor
from pydantic_models.models import UserResponse, TwoFactorResponse
from utils.auth_utils import authenticate_user, create_access_token, create_temp_token, validate_jwt, TEMP_KEY

router = APIRouter(prefix="/auth", tags=["auth"])

bearer_scheme = HTTPBearer()


class RegisterRequest(BaseModel):
    username: str = Field(
        description="Username length must be 4-32 characters", min_length=4, max_length=32)
    password: str = Field(
        description="Password length must be at least 8 characters", min_length=4)
    first_name: str = Field(
        description="First name must be 1-50 characters", min_length=1, max_length=50)
    last_name: str = Field(
        description="Last name must be 1-50 characters", min_length=1, max_length=50)




@router.post("/login")
async def login_llm(login_request: LoginRequest):
    res = llm_based_login(login_request)
    if not res.success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=res.detail)
    return {"detail":res.detail}

@router.post("/login-lang-graph")
async def login_llm(login_request: LoginRequest):
    print(f"Calling langgraph_agent_login with: {login_request}")
    res = await langgraph_agent_login(login_request)
    print(f"Result from langgraph_agent_login: {res}")
    if not res.success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=res.detail)
    return res


@router.get("/kyc-image")
async def get_kyc_image(*, db: db_dependency, token: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    """Generate a small JPEG with EXIF `user_comment` containing the user's user_hash and return it as a download.
    Marks `TwoFactor.issued_at` when image is generated.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="KYC image request requires a valid session token"
        )
    validation_result = validate_jwt(token.credentials, TEMP_KEY)
    if not validation_result["success"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=validation_result["detail"]
        )

    user_id = validation_result["payload"]["id"]
    user = db.query(Users).filter(Users.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    tf = db.query(TwoFactor).filter(TwoFactor.user_id == user_id).first()
    if not tf:
        # create two factor record if missing
        import uuid as _uuid
        tf = TwoFactor(user_id=user_id, user_hash=_uuid.uuid4().hex)
        db.add(tf)
        db.commit()
        db.refresh(tf)

    # generate simple JPEG
    img = PILImage.new('RGB', (400, 400), color=(73, 109, 137))
    buf = BytesIO()
    img.save(buf, format='JPEG')
    buf.seek(0)
    file_bytes = buf.getvalue()

    try:
        exif_img = Image(file_bytes)
        exif_img.user_comment = f"user_hash={tf.user_hash}"
        new_bytes = exif_img.get_file()
    except Exception:
        # fallback: return original bytes without EXIF (should not happen)
        new_bytes = file_bytes

    tf.issued_at = datetime.utcnow()
    db.commit()

    return Response(content=new_bytes, media_type='image/jpeg', headers={"Content-Disposition": 'attachment; filename="flai-kyc.jpg"'})


class TwoFactorForm(BaseModel):
    image:UploadFile = File(...)
    model_config = {"extra": "forbid"}


@router.post("/kyc-verify")
async def two_factor_auth(*,
                          db: db_dependency,
                          token: HTTPAuthorizationCredentials = Depends(bearer_scheme),
                          twofactor_request: TwoFactorForm = Form(..., media_type="multipart/form-data")):

    print("Token",token)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="KYC verification requires a valid session token"
        )
    validation_result = validate_jwt(token.credentials, TEMP_KEY)

    if not validation_result["success"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=validation_result["detail"]
        )
    print(validation_result["payload"])
    image = twofactor_request.image
    accepted_file_types = ["image/png", "image/jpeg", "image/jpg"]
    if image.content_type not in accepted_file_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="KYC upload: only JPEG/PNG images accepted")
    if image.size> 1*1024*1024 :
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="KYC upload: file must be under 1MB")
    user_id = validation_result["payload"]["id"]
    # Ensure the server issued a verification image before accepting uploads
    tf = db.query(TwoFactor).filter(TwoFactor.user_id == user_id).first()
    if not tf or not getattr(tf, "issued_at", None):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Please request and download your verification image before uploading.")

    res = await  langgraph_agent_2fa(image,user_id)
    if not res.success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail=res.detail)
    return res

# compatibility alias for older tests/clients that expect `/auth/2fa`
router.post("/2fa")(two_factor_auth)

@router.post("/login-normal")
async def login_normal(login_request: LoginRequest, db: db_dependency):
    user = authenticate_user(login_request.username, login_request.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user.')
    token = create_temp_token(
        user.username, user.id, user.role, timedelta(minutes=15))
    return {"detail": {"token":token} }


@router.get("/get_users", response_model=list[UserResponse])
async def get_users(db: db_dependency):
    users = db.query(Users.username, Users.first_name, Users.last_name).all()
    return users

@router.get("/get_kyc_records", response_model=list[TwoFactorResponse])
async def get_kyc_records(db: db_dependency):
    results = db.query(Users.username, TwoFactor.user_hash).join(TwoFactor).all()
    return results