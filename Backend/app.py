"""
DarkHook Defense - Main Application
Multi-module phishing detection engine built with FastAPI
"""

import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Load environment variables (for local development)
load_dotenv()

# Import modules
from modules.database.mongo_config import get_client, close_connection
from auth.auth_routes import router as auth_router
from modules.url_analysis.link import router as url_router
from modules.document_analysis.document_routes import router as document_router

# Configuration
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")


# -------------------------
# Lifespan Events (Modern Way)
# -------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        get_client()
        print("✓ MongoDB connected successfully!")
    except Exception as e:
        print(f"✗ MongoDB connection failed: {e}")

    yield

    # Shutdown
    close_connection()
    print("✓ MongoDB connection closed")


# -------------------------
# FastAPI App
# -------------------------

app = FastAPI(
    title="DarkHook Defense API",
    description="Phishing detection engine for URLs, Emails, and Documents",
    version="1.0.0",
    lifespan=lifespan
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
# Routers
# -------------------------

app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(url_router, prefix="/scan", tags=["URL Analysis"])
app.include_router(document_router, prefix="/scan", tags=["Document Analysis"])


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