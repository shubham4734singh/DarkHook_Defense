import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from core.config import settings
from core.database import get_client, close_connection
from api.v1.api import api_router

def _cors_headers_for_origin(origin: str | None) -> dict[str, str]:
    headers = {"Access-Control-Allow-Credentials": "true"}
    allowed = settings.get_cors_origins()
    if origin and origin in allowed:
        headers["Access-Control-Allow-Origin"] = origin
    return headers

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("=" * 60)
    print("[*] DarkHook Defense Backend Starting Up (Refactored SoC)")
    print("=" * 60)
    
    # Check critical settings
    required_settings = ["MONGO_URI", "SECRET_KEY", "SMTP_HOST"]
    missing = [var for var in required_settings if not getattr(settings, var, None)]
    if missing:
        print(f"[!] CRITICAL: Missing configuration settings: {', '.join(missing)}")
        print("   Please verify your environment variables or .env file settings")
    else:
        print("[+] All required configuration settings present")
    
    # Test MongoDB connection
    try:
        client = get_client()
        client.admin.command("ping")
        print("[+] MongoDB connection successful!")
    except Exception as e:
        print(f"[!] MongoDB connection warning: {e}")
        print("   App will continue but database operations may fail")

    yield

    # Shutdown
    try:
        close_connection()
        print("[+] MongoDB connection closed")
    except Exception:
        pass

app = FastAPI(
    title="DarkHook Defense API",
    description="Phishing detection engine for URLs, Emails, and Documents (Refactored Modular Architecture)",
    version="1.0.0",
    lifespan=lifespan,
    redirect_slashes=False
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept", "Origin", "X-Requested-With"],
    expose_headers=["Content-Type", "X-Total-Count"],
    max_age=600,
)

# CORS-safe Exception Handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with CORS headers."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=_cors_headers_for_origin(request.headers.get("origin")),
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors with CORS headers."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()},
        headers=_cors_headers_for_origin(request.headers.get("origin")),
    )

# Include consolidating api router
app.include_router(api_router)

@app.get("/")
async def root():
    return {
        "message": "DarkHook Defense API",
        "status": "running",
        "docs": "/docs"
    }

@app.get("/health")
async def health_check():
    try:
        client = get_client()
        client.admin.command("ping")
        return {"status": "healthy", "database": "connected"}
    except Exception:
        return {"status": "unhealthy", "database": "disconnected"}

if __name__ == "__main__":
    import uvicorn
    port = int(settings.PORT)
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
