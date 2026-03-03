from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
import os
import hashlib
import secrets
import smtplib
from email.message import EmailMessage
from passlib.context import CryptContext
from jose import jwt, JWTError, ExpiredSignatureError

# Import MongoDB configuration
from modules.database.mongo_config import get_database

router = APIRouter()

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required.")

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Email OTP configuration
REQUIRE_EMAIL_VERIFICATION = os.getenv("REQUIRE_EMAIL_VERIFICATION", "false").strip().lower() in {"1", "true", "yes"}
OTP_TTL_MINUTES = int(os.getenv("OTP_TTL_MINUTES", "10"))
OTP_RESEND_COOLDOWN_SECONDS = int(os.getenv("OTP_RESEND_COOLDOWN_SECONDS", "60"))
OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM = os.getenv("SMTP_FROM")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").strip().lower() in {"1", "true", "yes"}

# Development-only helper: when enabled, OTP is not emailed (printed to logs)
OTP_EMAIL_SENDING_DISABLED = os.getenv("OTP_EMAIL_SENDING_DISABLED", "false").strip().lower() in {"1", "true", "yes"}

# -------------------------
# Models
# -------------------------

class User(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class EmailOtpRequest(BaseModel):
    email: EmailStr

class EmailOtpVerify(BaseModel):
    email: EmailStr
    otp: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserResponse(BaseModel):
    name: str
    email: str


# -------------------------
# Database Helper
# -------------------------

def get_users_collection():
    db = get_database()
    return db["users"]


def get_otp_collection():
    db = get_database()
    return db["email_otps"]


_otp_indexes_ready = False


def _ensure_otp_indexes():
    global _otp_indexes_ready
    if _otp_indexes_ready:
        return
    try:
        otp_collection = get_otp_collection()
        otp_collection.create_index("expires_at", expireAfterSeconds=0)
        otp_collection.create_index([("email", 1), ("purpose", 1), ("created_at", -1)])
        _otp_indexes_ready = True
    except Exception:
        # Index creation failures should not hard-crash the API.
        _otp_indexes_ready = True


def _normalize_otp(otp: str) -> str:
    return "".join(ch for ch in (otp or "") if ch.isdigit())


def _hash_otp(otp: str, salt: str) -> str:
    # OTPs are short; we hash with a secret key + per-otp salt to avoid storing plaintext.
    material = f"{salt}:{otp}:{SECRET_KEY}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _send_email_otp(to_email: str, otp: str):
    if OTP_EMAIL_SENDING_DISABLED:
        print(f"[DEV] OTP for {to_email}: {otp}")
        return

    missing = [k for k, v in {
        "SMTP_HOST": SMTP_HOST,
        "SMTP_USERNAME": SMTP_USERNAME,
        "SMTP_PASSWORD": SMTP_PASSWORD,
        "SMTP_FROM": SMTP_FROM,
    }.items() if not v]

    if missing:
        raise RuntimeError(f"Missing SMTP config: {', '.join(missing)}")

    msg = EmailMessage()
    msg["Subject"] = "Your DarkHook Defense verification code"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(
        "Your verification code is:\n\n"
        f"{otp}\n\n"
        f"This code expires in {OTP_TTL_MINUTES} minutes.\n"
        "If you did not request this code, you can ignore this email.\n"
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
        if SMTP_USE_TLS:
            server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)


# -------------------------
# JWT Utilities
# -------------------------

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user_email(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    return email


# -------------------------
# Routes
# -------------------------

@router.post("/register", response_model=Token)
async def register(user: User):
    try:
        users_collection = get_users_collection()

        # Check if user already exists
        if users_collection.find_one({"email": user.email}):
            raise HTTPException(status_code=400, detail="Email already registered")

        # Hash password (bcrypt handles truncation internally)
        hashed_password = pwd_context.hash(user.password)

        user_doc = {
            "name": user.name,
            "email": user.email,
            "password": hashed_password,
            "email_verified": False,
            "email_verified_at": None,
            "created_at": datetime.utcnow()
        }

        users_collection.insert_one(user_doc)

        access_token = create_access_token(data={"sub": user.email})
        return {"access_token": access_token, "token_type": "bearer"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/login", response_model=Token)
async def login(user_login: UserLogin):
    try:
        users_collection = get_users_collection()

        user = users_collection.find_one({"email": user_login.email})

        if not user:
            raise HTTPException(status_code=401, detail="Incorrect email or password")

        if not pwd_context.verify(user_login.password, user["password"]):
            raise HTTPException(status_code=401, detail="Incorrect email or password")

        if REQUIRE_EMAIL_VERIFICATION and not user.get("email_verified"):
            raise HTTPException(
                status_code=403,
                detail="Email not verified. Request an OTP and verify your email before logging in."
            )

        access_token = create_access_token(data={"sub": user_login.email})
        return {"access_token": access_token, "token_type": "bearer"}

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/me", response_model=UserResponse)
async def get_current_user(current_user: str = Depends(get_current_user_email)):
    users_collection = get_users_collection()
    user = users_collection.find_one({"email": current_user})

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "name": user["name"],
        "email": user["email"]
    }


# -------------------------
# Email OTP (Verification)
# -------------------------


@router.post("/email-otp/request")
async def request_email_otp(payload: EmailOtpRequest):
    """Send a 6-digit OTP to the user's email to verify the account."""
    _ensure_otp_indexes()

    users_collection = get_users_collection()
    otp_collection = get_otp_collection()

    # Avoid account enumeration: always return a generic message.
    user = users_collection.find_one({"email": payload.email})
    if not user:
        return {"message": "If the account exists, an OTP has been sent."}

    # If already verified, no need to send.
    if user.get("email_verified"):
        return {"message": "Email is already verified."}

    now = datetime.utcnow()
    purpose = "verify_email"

    latest = otp_collection.find_one(
        {"email": payload.email, "purpose": purpose, "consumed_at": None},
        sort=[("created_at", -1)],
    )

    if latest and latest.get("last_sent_at"):
        cooldown_until = latest["last_sent_at"] + timedelta(seconds=OTP_RESEND_COOLDOWN_SECONDS)
        if now < cooldown_until:
            return {"message": "OTP recently sent. Please wait a moment and try again."}

    otp_value = f"{secrets.randbelow(1_000_000):06d}"
    salt = secrets.token_hex(16)
    otp_hash = _hash_otp(otp_value, salt)

    otp_doc = {
        "email": payload.email,
        "purpose": purpose,
        "otp_hash": otp_hash,
        "salt": salt,
        "attempts": 0,
        "created_at": now,
        "last_sent_at": now,
        "expires_at": now + timedelta(minutes=OTP_TTL_MINUTES),
        "consumed_at": None,
    }

    insert_result = otp_collection.insert_one(otp_doc)

    try:
        _send_email_otp(payload.email, otp_value)
    except Exception as e:
        # Best-effort cleanup: if email sending fails, we still don't want a usable OTP stored.
        otp_collection.delete_one({"_id": insert_result.inserted_id})
        raise HTTPException(status_code=500, detail=f"Failed to send OTP email: {str(e)}")

    return {"message": "If the account exists, an OTP has been sent."}


@router.post("/email-otp/verify")
async def verify_email_otp(payload: EmailOtpVerify):
    """Verify the OTP and mark the user's email as verified."""
    _ensure_otp_indexes()

    users_collection = get_users_collection()
    otp_collection = get_otp_collection()

    user = users_collection.find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    if user.get("email_verified"):
        return {"message": "Email is already verified."}

    now = datetime.utcnow()
    purpose = "verify_email"
    otp_clean = _normalize_otp(payload.otp)
    if len(otp_clean) != 6:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    challenge = otp_collection.find_one(
        {"email": payload.email, "purpose": purpose, "consumed_at": None},
        sort=[("created_at", -1)],
    )

    if not challenge:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    if challenge.get("expires_at") and now > challenge["expires_at"]:
        raise HTTPException(status_code=400, detail="OTP expired")

    attempts = int(challenge.get("attempts", 0))
    if attempts >= OTP_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many attempts. Request a new OTP.")

    expected_hash = challenge.get("otp_hash")
    salt = challenge.get("salt", "")
    provided_hash = _hash_otp(otp_clean, salt)

    if not secrets.compare_digest(str(expected_hash), str(provided_hash)):
        otp_collection.update_one({"_id": challenge["_id"]}, {"$inc": {"attempts": 1}})
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # OTP no longer needed after successful verification.
    otp_collection.delete_one({"_id": challenge["_id"]})
    users_collection.update_one(
        {"email": payload.email},
        {"$set": {"email_verified": True, "email_verified_at": now}},
    )

    return {"message": "Email verified successfully."}