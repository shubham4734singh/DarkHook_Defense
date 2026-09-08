from datetime import datetime, timezone
from typing import Any, Dict, Optional
from core.database import get_collection

class PendingUserRepository:
    def __init__(self) -> None:
        self.collection = get_collection("pending_registrations")
        self._indexes_ready = False

    def ensure_indexes(self) -> None:
        """Create TTL index and email index for pending registrations."""
        if self._indexes_ready:
            return
        try:
            self.collection.create_index("expires_at", expireAfterSeconds=0)
            self.collection.create_index("email", unique=True)
            self._indexes_ready = True
        except Exception:
            self._indexes_ready = True

    def find_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Find a pending registration by email."""
        self.ensure_indexes()
        return self.collection.find_one({"email": email.strip().lower()})

    def upsert_pending_user(
        self, email: str, name: str, hashed_password: str, expires_at: datetime
    ) -> None:
        """Insert or replace a pending registration record."""
        self.ensure_indexes()
        clean_email = email.strip().lower()
        now = datetime.now(timezone.utc)
        self.collection.update_one(
            {"email": clean_email},
            {
                "$set": {
                    "name": name.strip(),
                    "email": clean_email,
                    "password": hashed_password,
                    "created_at": now,
                    "expires_at": expires_at,
                }
            },
            upsert=True,
        )

    def extend_expiry(self, email: str, expires_at: datetime) -> None:
        """Extend expiration time for an existing pending registration."""
        self.ensure_indexes()
        self.collection.update_one(
            {"email": email.strip().lower()},
            {"$set": {"expires_at": expires_at}},
        )

    def delete_by_email(self, email: str) -> None:
        """Delete pending registration record once account is created or cancelled."""
        self.collection.delete_one({"email": email.strip().lower()})

pending_user_repository = PendingUserRepository()
