from fastapi import APIRouter, Depends, Request, HTTPException
from core.config import settings
from core.exceptions import AuthException, OTPException, RateLimitException
from core.rate_limiter import rate_limiter
from api.deps import get_client_ip, get_current_user_email
from schemas.auth import (
    UserCreate,
    UserLogin,
    EmailOtpRequest,
    EmailOtpVerify,
    Token,
    RegisterResponse,
    UserResponse,
)
from services.auth_service import auth_service
from services.otp_service import otp_service

router = APIRouter()

@router.post("/register", response_model=RegisterResponse)
async def register(user: UserCreate, request: Request):
    """Register a new user account with rate-limiting."""
    ip = get_client_ip(request)
    try:
        rate_limiter.enforce("register", ip, user.email, settings.AUTH_REGISTER_MAX_ATTEMPTS)
        return auth_service.register_user(user.name, user.email, user.password)
    except RateLimitException as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except AuthException as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")

@router.post("/login", response_model=Token)
async def login(user_login: UserLogin, request: Request):
    """Authenticate a user and return a JWT access token with rate-limiting."""
    ip = get_client_ip(request)
    try:
        rate_limiter.enforce("login", ip, user_login.email, settings.AUTH_LOGIN_MAX_ATTEMPTS)
        token = auth_service.authenticate_user(user_login.email, user_login.password)
        return {"access_token": token, "token_type": "bearer"}
    except RateLimitException as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except AuthException as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")

@router.get("/me", response_model=UserResponse)
async def get_current_user(current_user: str = Depends(get_current_user_email)):
    """Retrieve the current authenticated user's profile info."""
    try:
        return auth_service.get_user_profile(current_user)
    except AuthException as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")

@router.post("/email-otp/request")
async def request_email_otp(payload: EmailOtpRequest, request: Request):
    """Request a 6-digit email OTP for account verification with rate-limiting."""
    ip = get_client_ip(request)
    try:
        rate_limiter.enforce("otp_request", ip, payload.email, settings.AUTH_OTP_REQUEST_MAX_ATTEMPTS)
        message = otp_service.request_email_otp(payload.email)
        return {"message": message}
    except RateLimitException as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except OTPException as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")

@router.post("/email-otp/verify")
async def verify_email_otp(payload: EmailOtpVerify, request: Request):
    """Verify an email OTP and activate the user's account with rate-limiting."""
    ip = get_client_ip(request)
    try:
        rate_limiter.enforce("otp_verify", ip, payload.email, settings.AUTH_OTP_VERIFY_MAX_ATTEMPTS)
        otp_service.verify_email_otp(payload.email, payload.otp)
        return {"message": "Email verified successfully."}
    except RateLimitException as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except OTPException as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")
