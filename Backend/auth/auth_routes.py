from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
import os
import hashlib
import secrets
import smtplib
import ssl
import errno
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
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").strip().lower() in {"1", "true", "yes"}
SMTP_SSL_PORT = int(os.getenv("SMTP_SSL_PORT", "465"))
SMTP_TIMEOUT_SECONDS = int(os.getenv("SMTP_TIMEOUT_SECONDS", "5"))
SMTP_FALLBACK_TO_SSL = os.getenv("SMTP_FALLBACK_TO_SSL", "true").strip().lower() in {"1", "true", "yes"}

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

    # Split OTP digits for the styled boxes
    otp_boxes = "".join(
        f'<td style="width:44px;height:52px;background:#f9f9f9;border:2px solid #222;'
        f'border-radius:8px;text-align:center;vertical-align:middle;'
        f'font-size:26px;font-weight:700;color:#111;letter-spacing:2px;'
        f'font-family:\'Courier New\',monospace;">{d}</td>'
        for d in otp
    )

    html_body = f"""\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:'Segoe UI',Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:40px 0;">
  <tr><td align="center">
    <table role="presentation" width="500" cellpadding="0" cellspacing="0"
           style="background:#ffffff;border:1px solid #e0e0e0;
                  border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.06);">

      <!-- Header -->
      <tr><td style="padding:36px 40px 12px;text-align:center;border-bottom:1px solid #eee;">
        <div style="font-size:28px;font-weight:800;color:#111;letter-spacing:0.5px;">
          DarkHook Defense
        </div>
        <div style="margin-top:6px;font-size:12px;color:#999;letter-spacing:1.5px;text-transform:uppercase;">
          Phishing Detection Engine
        </div>
      </td></tr>

      <!-- Greeting -->
      <tr><td style="padding:32px 40px 10px;text-align:center;">
        <div style="font-size:20px;font-weight:600;color:#222;">Verify Your Email</div>
        <div style="margin-top:12px;font-size:14px;color:#666;line-height:1.7;">
          Enter the code below to complete your verification.<br>
          This code expires in <strong style="color:#111;">{OTP_TTL_MINUTES} minutes</strong>.
        </div>
      </td></tr>

      <!-- OTP Code -->
      <tr><td style="padding:24px 40px;" align="center">
        <table role="presentation" cellpadding="0" cellspacing="6">
          <tr>{otp_boxes}</tr>
        </table>
      </td></tr>

      <!-- Inspirational Quote -->
      <tr><td style="padding:16px 48px 20px;text-align:center;">
        <div style="background:#fafafa;border-left:3px solid #333;padding:14px 20px;
                    border-radius:0 8px 8px 0;text-align:left;">
          <div style="font-size:13px;color:#555;font-style:italic;line-height:1.6;">
            &ldquo;The best defense against phishing is awareness. Stay vigilant, stay safe.&rdquo;
          </div>
          <div style="margin-top:6px;font-size:11px;color:#999;font-weight:600;">
            &mdash; DarkHook Defense Team
          </div>
        </div>
      </td></tr>

      <!-- Warning -->
      <tr><td style="padding:4px 40px 28px;text-align:center;">
        <div style="display:inline-block;background:#fff5f5;border:1px solid #fecaca;
                    border-radius:6px;padding:10px 18px;">
          <span style="font-size:12px;color:#b91c1c;">
            &#x26a0;&#xfe0f; Didn&rsquo;t request this? You can safely ignore this email.
          </span>
        </div>
      </td></tr>

      <!-- Footer -->
      <tr><td style="padding:20px 40px 28px;text-align:center;border-top:1px solid #eee;">
        <div style="font-size:12px;color:#aaa;line-height:1.5;">
          This is an automated message from <strong style="color:#888;">DarkHook Defense</strong>.<br>
          Please do not reply to this email.
        </div>
        <div style="margin-top:10px;font-size:11px;color:#ccc;">
          &copy; 2026 DarkHook Defense &mdash; Protecting you from phishing threats.
        </div>
      </td></tr>

    </table>
  </td></tr>
</table>
</body>
</html>"""

    plain_text = (
        "Your DarkHook Defense verification code is:\n\n"
        f"  {otp}\n\n"
        f"This code expires in {OTP_TTL_MINUTES} minutes.\n\n"
        "\"The best defense against phishing is awareness. Stay vigilant, stay safe.\"\n"
        "  — DarkHook Defense Team\n\n"
        "If you did not request this code, you can ignore this email.\n"
    )

    msg = EmailMessage()
    msg["Subject"] = "Your DarkHook Defense Verification Code"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(plain_text)
    msg.add_alternative(html_body, subtype="html")

    # Gmail "App Passwords" are often copied with spaces for readability; strip them.
    smtp_password = (SMTP_PASSWORD or "").replace(" ", "")

    def _try_send(use_ssl: bool, port: int):
        if use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(SMTP_HOST, port, timeout=SMTP_TIMEOUT_SECONDS, context=context) as server:
                server.login(SMTP_USERNAME, smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, port, timeout=SMTP_TIMEOUT_SECONDS) as server:
                server.ehlo()
                if SMTP_USE_TLS:
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                server.login(SMTP_USERNAME, smtp_password)
                server.send_message(msg)

    try:
        # Primary attempt: whatever is configured via env vars.
        primary_port = SMTP_SSL_PORT if SMTP_USE_SSL else SMTP_PORT
        _try_send(SMTP_USE_SSL, primary_port)
        return
    except (OSError, smtplib.SMTPException) as exc:
        # Common on some hosting providers: outbound SMTP is blocked, producing ENETUNREACH.
        # Optionally fall back from STARTTLS/587 to SSL/465.
        should_fallback = (
            SMTP_FALLBACK_TO_SSL
            and not SMTP_USE_SSL
            and isinstance(exc, OSError)
            and getattr(exc, "errno", None) in {errno.ENETUNREACH, errno.EHOSTUNREACH}
        )
        if should_fallback:
            try:
                _try_send(True, SMTP_SSL_PORT)
                return
            except Exception:
                pass

        hint = ""
        if isinstance(exc, OSError) and getattr(exc, "errno", None) in {errno.ENETUNREACH, errno.EHOSTUNREACH}:
            hint = (
                " Outbound SMTP may be blocked in this hosting environment. "
                "On Render/hosted platforms, prefer an email provider API (SendGrid/Mailgun/Resend) "
                "or configure allowed egress."
            )
        raise RuntimeError(
            f"SMTP send failed (host={SMTP_HOST}, port={(SMTP_SSL_PORT if SMTP_USE_SSL else SMTP_PORT)}, ssl={SMTP_USE_SSL}, tls={SMTP_USE_TLS}): {exc}.{hint}"
        )


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

@router.post("/register")
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

        # Return success message without token - user must verify email then login
        return {
            "message": "Registration successful. Please verify your email to complete setup.",
            "email": user.email,
            "requires_verification": REQUIRE_EMAIL_VERIFICATION
        }

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