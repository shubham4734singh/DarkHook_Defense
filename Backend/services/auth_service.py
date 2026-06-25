from datetime import datetime, timezone
from typing import Dict, Any
from core.config import settings
from core.exceptions import AuthException
from core.security import hash_password, verify_password, create_access_token
from repositories.user_repository import user_repository

class AuthService:
    def register_user(self, name: str, email: str, password: str) -> Dict[str, Any]:
        """
        Register a new user in the database.
        Returns registration result details.
        """
        email_clean = email.strip().lower()
        
        # Check if user already exists
        if user_repository.find_by_email(email_clean):
            raise AuthException("Email already registered")

        # Hash password and insert
        hashed_password = hash_password(password)
        
        user_doc = {
            "name": name.strip(),
            "email": email_clean,
            "password": hashed_password,
            "email_verified": not settings.REQUIRE_EMAIL_VERIFICATION,
            "email_verified_at": datetime.now(timezone.utc) if not settings.REQUIRE_EMAIL_VERIFICATION else None,
            "created_at": datetime.now(timezone.utc)
        }

        user_repository.create_user(user_doc)

        message = (
            "Registration successful. Please verify your email to complete setup."
            if settings.REQUIRE_EMAIL_VERIFICATION
            else "Registration successful. You can now log in."
        )

        return {
            "message": message,
            "email": email_clean,
            "requires_verification": settings.REQUIRE_EMAIL_VERIFICATION
        }

    def authenticate_user(self, email: str, password: str) -> str:
        """
        Authenticate a user and return a JWT access token.
        Raises AuthException on invalid credentials or unverified email.
        """
        email_clean = email.strip().lower()
        user = user_repository.find_by_email(email_clean)

        if not user:
            raise AuthException("Incorrect email or password", status_code=401)

        if not verify_password(password, user["password"]):
            raise AuthException("Incorrect email or password", status_code=401)

        if settings.REQUIRE_EMAIL_VERIFICATION and not user.get("email_verified"):
            raise AuthException(
                "Email not verified. Request an OTP and verify your email before logging in.",
                status_code=403
            )

        # Create JWT token
        return create_access_token(data={"sub": email_clean})

    def get_user_profile(self, email: str) -> Dict[str, str]:
        """Get user name and email."""
        user = user_repository.find_by_email(email)
        if not user:
            raise AuthException("User not found", status_code=404)
            
        return {
            "name": user["name"],
            "email": user["email"]
        }

auth_service = AuthService()
