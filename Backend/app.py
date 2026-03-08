"""
DarkHook Defense - Main Application
Multi-module phishing detection engine built with FastAPI
"""

import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, Request, status, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

# Load environment variables (for local development)
load_dotenv()

# Import modules
from modules.database.mongo_config import get_client, close_connection
from auth.auth_routes import router as auth_router
from modules.url_analysis.link import router as url_router
from modules.document_analysis.document_routes import router as document_router
from modules.email_analysis.email_routes import router as email_router

# Configuration
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")


# -------------------------
# Lifespan Events (Modern Way)
# -------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("=" * 60)
    print("🚀 DarkHook Defense Backend Starting Up")
    print("=" * 60)
    
    # Check critical env vars
    required_vars = ["MONGO_URI", "SECRET_KEY", "SMTP_HOST"]
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        print(f"❌ CRITICAL: Missing env vars: {', '.join(missing)}")
        print("   Please set these in Render dashboard before continuing")
    else:
        print("✓ All required environment variables present")
    
    # Test MongoDB connection
    try:
        client = get_client()
        client.admin.command("ping")
        print("✓ MongoDB connection successful!")
    except Exception as e:
        print(f"⚠️  MongoDB connection warning: {e}")
        print("   App will continue but database operations may fail")

    yield

    # Shutdown
    try:
        close_connection()
        print("✓ MongoDB connection closed")
    except Exception:
        pass


# -------------------------
# FastAPI App
# -------------------------

app = FastAPI(
    title="DarkHook Defense API",
    description="Phishing detection engine for URLs, Emails, and Documents",
    version="1.0.0",
    lifespan=lifespan,
    redirect_slashes=False
)

# -------------------------
# CORS
# -------------------------

# Add CORS middleware BEFORE other routers
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        FRONTEND_URL,
        "https://dark-hook-defense.vercel.app",
        "https://darkhookdefense.online",
        "https://www.darkhookdefense.online",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept", "Origin", "X-Requested-With"],
    expose_headers=["Content-Type", "X-Total-Count"],
    max_age=600,
)


# -------------------------
# Exception Handlers (Ensure CORS headers on all error responses)
# -------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with CORS headers."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers={
            "Access-Control-Allow-Origin": request.headers.get("origin", "*"),
            "Access-Control-Allow-Credentials": "true",
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors with CORS headers."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()},
        headers={
            "Access-Control-Allow-Origin": request.headers.get("origin", "*"),
            "Access-Control-Allow-Credentials": "true",
        }
    )


# -------------------------
# Routers
# -------------------------

app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(url_router, prefix="/scan", tags=["URL Analysis"])
app.include_router(document_router, prefix="/scan", tags=["Document Analysis"])
app.include_router(email_router, prefix="/scan", tags=["Email Analysis"])


# -------------------------
# Routes
# -------------------------

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


# -------------------------
# Local Development Only
# -------------------------

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)