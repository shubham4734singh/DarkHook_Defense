from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from core.security import decode_access_token

# OAuth2 Scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_client_ip(request: Request) -> str:
    """Helper to extract remote client IP address from request headers."""
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    client = getattr(request, "client", None)
    return client.host if client and client.host else "unknown"

def get_current_user_email(token: str = Depends(oauth2_scheme)) -> str:
    """FastAPI dependency to retrieve the current authenticated user's email."""
    try:
        payload = decode_access_token(token)
        email = payload.get("sub")
        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload"
            )
        return email
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        ) from e
