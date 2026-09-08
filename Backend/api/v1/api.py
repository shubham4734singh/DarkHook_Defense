from fastapi import APIRouter
from .endpoints.auth import router as auth_router
from .endpoints.url import router as url_router
from .endpoints.email import router as email_router
from .endpoints.document import router as document_router
from .endpoints.dashboard import router as dashboard_router

api_router = APIRouter()

# Include authentication endpoints under /auth
api_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])

# Include scanning endpoints under /scan
api_router.include_router(url_router, prefix="/scan", tags=["URL Analysis"])
api_router.include_router(email_router, prefix="/scan", tags=["Email Analysis"])
api_router.include_router(document_router, prefix="/scan", tags=["Document Analysis"])

# Include dashboard analytics endpoints under /dashboard
api_router.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard Analytics"])
