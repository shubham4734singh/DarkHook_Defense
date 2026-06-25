from datetime import datetime
from typing import Any, Dict
from bson.objectid import ObjectId
from core.database import get_collection

class OtpRepository:
    def __init__(self) -> None:
        self.collection = get_collection("email_otps")
        self._indexes_ready = False

    def ensure_indexes(self) -> None:
        """Create TTL and query indexes for OTPs."""
        if self._indexes_ready:
            return
        try:
            self.collection.create_index("expires_at", expireAfterSeconds=0)
            self.collection.create_index([("email", 1), ("purpose", 1), ("created_at", -1)])
            self._indexes_ready = True
        except Exception:
            # Index creation failures should not hard-crash the API.
            self._indexes_ready = True

    def find_latest_unconsumed(self, email: str, purpose: str) -> Dict[str, Any] | None:
        """Find the latest unconsumed OTP for a given email and purpose."""
        self.ensure_indexes()
        return self.collection.find_one(
            {"email": email.strip().lower(), "purpose": purpose, "consumed_at": None},
            sort=[("created_at", -1)],
        )

    def create_otp(self, otp_doc: Dict[str, Any]) -> ObjectId:
        """Insert a new OTP record."""
        self.ensure_indexes()
        result = self.collection.insert_one(otp_doc)
        return result.inserted_id

    def delete_otp(self, otp_id: ObjectId) -> None:
        """Delete an OTP by its document ID."""
        self.collection.delete_one({"_id": otp_id})

    def increment_attempts(self, otp_id: ObjectId) -> None:
        """Increment the attempts count for an OTP."""
        self.collection.update_one({"_id": otp_id}, {"$inc": {"attempts": 1}})

otp_repository = OtpRepository()
