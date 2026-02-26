"""
DarkHook Defense - Main Application
Multi-module phishing detection engine built with FastAPI
"""

import os
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient

# Load environment variables
load_dotenv()

# Import modules
from modules.database.mongo_config import get_client, close_connection
from auth.auth_routes import router as auth_router

# Get configuration
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

# Create FastAPI app
app = FastAPI(
    title="DarkHook Defense API",
    description="Phishing detection engine for URLs, Emails, and Documents",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL, "http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])

# MongoDB connection
@app.on_event("startup")
async def startup_event():
    """Initialize MongoDB connection on startup"""
    try:
        client = get_client()
        print("✓ MongoDB connected successfully!")
    except Exception as e:
        print(f"✗ MongoDB connection failed: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    """Close MongoDB connection on shutdown"""
    close_connection()
    print("✓ MongoDB connection closed")

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "DarkHook Defense API",
        "status": "running",
        "docs": "/docs"
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    try:
        client = get_client()
        client.admin.command('ping')
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": "disconnected", "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
