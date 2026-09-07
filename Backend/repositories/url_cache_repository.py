from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from core.database import get_collection

class UrlCacheRepository:
    def __init__(self) -> None:
        self._collection = None
        self._indexes_ready = False

    @property
    def collection(self):
        if self._collection is None:
            try:
                self._collection = get_collection("cached_url_scans")
            except Exception:
                return None
        return self._collection

    def ensure_indexes(self) -> None:
        """Create unique and TTL indexes for cached URL scans."""
        if self._indexes_ready or self.collection is None:
            return
        try:
            # TTL index on expires_at to auto-delete expired documents
            self.collection.create_index("expires_at", expireAfterSeconds=0)
            # Unique index on url to ensure fast lookup and avoid duplicates
            self.collection.create_index("url", unique=True)
            self._indexes_ready = True
        except Exception as e:
            # Log failure but do not crash the application
            print(f"[CACHE] Error creating MongoDB indexes: {e}")
            self._indexes_ready = True

    def get_cached_scan(self, url: str) -> Dict[str, Any] | None:
        """Retrieve a cached scan result by URL."""
        if self.collection is None:
            return None
        self.ensure_indexes()
        try:
            return self.collection.find_one({"url": url})
        except Exception as e:
            print(f"[CACHE] Failed to read from MongoDB cache: {e}")
            return None

    def save_cached_scan(self, url: str, result: dict, ttl_hours: int) -> None:
        """Save or update a scan result in the cache with a TTL."""
        if self.collection is None:
            return
        self.ensure_indexes()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=ttl_hours)
        
        doc = {
            "url": url,
            "result": result,
            "scanned_at": now,
            "expires_at": expires_at
        }
        
        try:
            self.collection.update_one(
                {"url": url},
                {"$set": doc},
                upsert=True
            )
        except Exception as e:
            print(f"[CACHE] Failed to save to MongoDB cache: {e}")

url_cache_repository = UrlCacheRepository()
