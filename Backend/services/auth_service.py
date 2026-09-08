from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from core.config import settings
from core.exceptions import AuthException, OTPException
from core.security import hash_password, verify_password, create_access_token
from repositories.user_repository import user_repository
from repositories.pending_user_repository import pending_user_repository

class AuthService:
    def register_user(self, name: str, email: str, password: str) -> Dict[str, Any]:
        """
        Register a new user account.
        When email verification is required, temporarily holds the registration
        in pending_registrations and sends an OTP. The user document is NOT
        created in the MongoDB 'users' collection until the OTP is verified.
        """
        email_clean = email.strip().lower()
        now = datetime.now(timezone.utc)
        
        # Check if user already exists in users collection
        existing_user = user_repository.find_by_email(email_clean)
        if existing_user:
            if existing_user.get("email_verified"):
                raise AuthException("Email already registered")
            else:
                # Remove stale unverified legacy record so user can register cleanly
                user_repository.delete_by_email(email_clean)

        hashed_password = hash_password(password)

        if not settings.REQUIRE_EMAIL_VERIFICATION:
            user_doc = {
                "name": name.strip(),
                "email": email_clean,
                "password": hashed_password,
                "email_verified": True,
                "email_verified_at": now,
                "created_at": now
            }
            user_repository.create_user(user_doc)
            return {
                "message": "Registration successful. You can now log in.",
                "email": email_clean,
                "requires_verification": False
            }

        # Email verification is enabled: store in pending_registrations
        expires_at = now + timedelta(minutes=settings.OTP_TTL_MINUTES)
        pending_user_repository.upsert_pending_user(
            email=email_clean,
            name=name.strip(),
            hashed_password=hashed_password,
            expires_at=expires_at
        )

        # Generate and send verification OTP
        from services.otp_service import otp_service
        try:
            otp_service.send_verification_otp(email_clean)
        except Exception as e:
            # Cleanup pending user if email failed to send (except on cooldown)
            if not (isinstance(e, OTPException) and getattr(e, "status_code", 0) == 429):
                pending_user_repository.delete_by_email(email_clean)
            if isinstance(e, OTPException):
                raise e
            raise AuthException(f"Failed to send verification email: {e}", status_code=500)

        return {
            "message": "Verification code sent to your email. Please verify to complete account creation.",
            "email": email_clean,
            "requires_verification": True
        }

    def authenticate_user(self, email: str, password: str) -> str:
        """
        Authenticate a user and return a JWT access token.
        Raises AuthException on invalid credentials or unverified email.
        """
        email_clean = email.strip().lower()
        user = user_repository.find_by_email(email_clean)

        if not user:
            # Check if registration is pending verification
            pending = pending_user_repository.find_by_email(email_clean)
            if pending and verify_password(password, pending.get("password", "")):
                raise AuthException(
                    "Email not verified. Request an OTP and verify your email before logging in.",
                    status_code=403
                )
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
