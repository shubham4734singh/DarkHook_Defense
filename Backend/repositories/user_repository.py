from datetime import datetime
from typing import Any, Dict
from core.database import get_collection

class UserRepository:
    def __init__(self) -> None:
        self.collection = get_collection("users")

    def find_by_email(self, email: str) -> Dict[str, Any] | None:
        """Find a user by their email address."""
        return self.collection.find_one({"email": email.strip().lower()})

    def create_user(self, user_doc: Dict[str, Any]) -> None:
        """Create/Insert a new user document."""
        self.collection.insert_one(user_doc)

    def mark_email_verified(self, email: str, verified_at: datetime) -> None:
        """Mark user email as verified."""
        self.collection.update_one(
            {"email": email.strip().lower()},
            {"$set": {"email_verified": True, "email_verified_at": verified_at}},
        )

user_repository = UserRepository()
