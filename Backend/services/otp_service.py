import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from core.config import settings
from core.exceptions import OTPException
from core.security import create_access_token
from repositories.user_repository import user_repository
from repositories.otp_repository import otp_repository
from repositories.pending_user_repository import pending_user_repository
from services.email_sender import send_otp_email

class OtpService:
    def _normalize_otp(self, otp: str) -> str:
        return "".join(ch for ch in (otp or "") if ch.isdigit())

    def _hash_otp(self, otp: str, salt: str) -> str:
        material = f"{salt}:{otp}:{settings.SECRET_KEY}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def send_verification_otp(self, email: str) -> None:
        """
        Generate, store, and email a 6-digit verification OTP.
        Enforces cooldown and cleans up on delivery failure.
        """
        email_clean = email.strip().lower()
        now = datetime.now(timezone.utc)
        purpose = "verify_email"

        latest = otp_repository.find_latest_unconsumed(email_clean, purpose)
        if latest and latest.get("last_sent_at"):
            last_sent = latest["last_sent_at"]
            if last_sent.tzinfo is None:
                last_sent = last_sent.replace(tzinfo=timezone.utc)
            cooldown_until = last_sent + timedelta(seconds=settings.OTP_RESEND_COOLDOWN_SECONDS)
            if now < cooldown_until:
                raise OTPException(
                    "OTP recently sent. Please wait a moment and try again.",
                    status_code=429,
                )

        otp_value = f"{secrets.randbelow(1_000_000):06d}"
        salt = secrets.token_hex(16)
        otp_hash = self._hash_otp(otp_value, salt)

        otp_doc = {
            "email": email_clean,
            "purpose": purpose,
            "otp_hash": otp_hash,
            "salt": salt,
            "attempts": 0,
            "created_at": now,
            "last_sent_at": now,
            "expires_at": now + timedelta(minutes=settings.OTP_TTL_MINUTES),
            "consumed_at": None,
        }

        otp_id = otp_repository.create_otp(otp_doc)

        try:
            send_otp_email(email_clean, otp_value)
        except Exception as e:
            otp_repository.delete_otp(otp_id)
            raise OTPException(
                "Failed to send OTP email. Please try again later.", status_code=500
            ) from e

    def request_email_otp(self, email: str) -> str:
        """
        Generate and send a 6-digit verification OTP for pending registrations or unverified users.
        Returns a user-friendly message.
        """
        email_clean = email.strip().lower()
        verified_user = user_repository.find_by_email(email_clean)

        # If user is already registered and verified, no need to send OTP
        if verified_user and verified_user.get("email_verified"):
            return "Email is already verified."

        pending_user = pending_user_repository.find_by_email(email_clean)
        is_legacy_unverified = verified_user and not verified_user.get("email_verified")

        # Avoid account enumeration: return success even if user not found.
        if not pending_user and not is_legacy_unverified:
            return "If the account exists or registration is pending, an OTP has been sent."

        now = datetime.now(timezone.utc)
        purpose = "verify_email"

        latest = otp_repository.find_latest_unconsumed(email_clean, purpose)
        if latest and latest.get("last_sent_at"):
            last_sent = latest["last_sent_at"]
            if last_sent.tzinfo is None:
                last_sent = last_sent.replace(tzinfo=timezone.utc)
            cooldown_until = last_sent + timedelta(seconds=settings.OTP_RESEND_COOLDOWN_SECONDS)
            if now < cooldown_until:
                return "OTP recently sent. Please wait a moment and try again."

        # If pending registration exists, extend its expiry to match the new OTP TTL
        if pending_user:
            new_expiry = now + timedelta(minutes=settings.OTP_TTL_MINUTES)
            pending_user_repository.extend_expiry(email_clean, new_expiry)

        try:
            self.send_verification_otp(email_clean)
        except OTPException as e:
            if e.status_code == 429:
                return "OTP recently sent. Please wait a moment and try again."
            raise

        return "If the account exists or registration is pending, an OTP has been sent."

    def verify_email_otp(self, email: str, otp_code: str) -> Dict[str, Any]:
        """
        Verify the OTP and create/activate the user account in MongoDB.
        Account is ONLY created in the users collection when OTP is valid.
        """
        email_clean = email.strip().lower()
        now = datetime.now(timezone.utc)
        purpose = "verify_email"
        otp_clean = self._normalize_otp(otp_code)
        if len(otp_clean) != 6:
            raise OTPException("Invalid OTP")

        challenge = otp_repository.find_latest_unconsumed(email_clean, purpose)
        if not challenge:
            raise OTPException("Invalid or expired OTP")

        challenge_expires = challenge.get("expires_at")
        if challenge_expires:
            if challenge_expires.tzinfo is None:
                challenge_expires = challenge_expires.replace(tzinfo=timezone.utc)
            if now > challenge_expires:
                raise OTPException("OTP expired")

        attempts = int(challenge.get("attempts", 0))
        if attempts >= settings.OTP_MAX_ATTEMPTS:
            raise OTPException("Too many attempts. Request a new OTP.", status_code=429)

        expected_hash = challenge.get("otp_hash")
        salt = challenge.get("salt", "")
        provided_hash = self._hash_otp(otp_clean, salt)

        if not secrets.compare_digest(str(expected_hash), str(provided_hash)):
            otp_repository.increment_attempts(challenge["_id"])
            raise OTPException("Invalid OTP")

        # OTP is valid!
        # Check if there is a pending registration
        pending_user = pending_user_repository.find_by_email(email_clean)
        if pending_user:
            # Create user document in users collection
            user_doc = {
                "name": pending_user["name"],
                "email": email_clean,
                "password": pending_user["password"],  # already hashed
                "email_verified": True,
                "email_verified_at": now,
                "created_at": now,
            }
            user_repository.create_user(user_doc)
            pending_user_repository.delete_by_email(email_clean)
            otp_repository.delete_otp(challenge["_id"])

            token = create_access_token(data={"sub": email_clean})
            return {
                "message": "Account created and verified successfully.",
                "access_token": token,
                "token_type": "bearer",
            }

        # Check legacy unverified user
        legacy_user = user_repository.find_by_email(email_clean)
        if legacy_user:
            user_repository.mark_email_verified(email_clean, now)
            otp_repository.delete_otp(challenge["_id"])
            token = create_access_token(data={"sub": email_clean})
            return {
                "message": "Email verified successfully.",
                "access_token": token,
                "token_type": "bearer",
            }

        otp_repository.delete_otp(challenge["_id"])
        raise OTPException(
            "Registration session expired or user not found. Please sign up again.",
            status_code=400,
        )

otp_service = OtpService()
