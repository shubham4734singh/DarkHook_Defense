import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from core.config import settings
from core.exceptions import OTPException
from repositories.user_repository import user_repository
from repositories.otp_repository import otp_repository
from services.email_sender import send_otp_email

class OtpService:
    def _normalize_otp(self, otp: str) -> str:
        return "".join(ch for ch in (otp or "") if ch.isdigit())

    def _hash_otp(self, otp: str, salt: str) -> str:
        material = f"{salt}:{otp}:{settings.SECRET_KEY}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def request_email_otp(self, email: str) -> str:
        """
        Generate and send a 6-digit verification OTP.
        Returns a user-friendly message.
        """
        email_clean = email.strip().lower()
        user = user_repository.find_by_email(email_clean)
        
        # Avoid account enumeration: return success even if user not found.
        if not user:
            return "If the account exists, an OTP has been sent."

        # If already verified, no need to send.
        if user.get("email_verified"):
            return "Email is already verified."

        now = datetime.now(timezone.utc)
        purpose = "verify_email"

        latest = otp_repository.find_latest_unconsumed(email_clean, purpose)
        if latest and latest.get("last_sent_at"):
            # Check resend cooldown
            # Convert naive datetime from DB to aware
            last_sent = latest["last_sent_at"]
            if last_sent.tzinfo is None:
                last_sent = last_sent.replace(tzinfo=timezone.utc)
            cooldown_until = last_sent + timedelta(seconds=settings.OTP_RESEND_COOLDOWN_SECONDS)
            if now < cooldown_until:
                return "OTP recently sent. Please wait a moment and try again."

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
            # Cleanup: if email sending fails, delete the OTP so it's not usable
            otp_repository.delete_otp(otp_id)
            raise OTPException("Failed to send OTP email. Please try again later.", status_code=500) from e

        return "If the account exists, an OTP has been sent."

    def verify_email_otp(self, email: str, otp_code: str) -> None:
        """Verify the OTP and mark the user's email as verified."""
        email_clean = email.strip().lower()
        user = user_repository.find_by_email(email_clean)
        
        if not user:
            raise OTPException("Invalid OTP")

        if user.get("email_verified"):
            return

        now = datetime.now(timezone.utc)
        purpose = "verify_email"
        otp_clean = self._normalize_otp(otp_code)
        if len(otp_clean) != 6:
            raise OTPException("Invalid OTP")

        challenge = otp_repository.find_latest_unconsumed(email_clean, purpose)
        if not challenge:
            raise OTPException("Invalid OTP")

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

        # Mark consumed/delete and verify user email
        otp_repository.delete_otp(challenge["_id"])
        user_repository.mark_email_verified(email_clean, now)

otp_service = OtpService()
