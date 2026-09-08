from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from core.database import get_collection

class UrlCacheRepository:
    def __init__(self) -> None:
        self._collection = None
        self._indexes_ready = False
        self._in_memory_scans: list[dict] = []

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
        if self.collection is not None:
            self.ensure_indexes()
            try:
                cached = self.collection.find_one({"url": url})
                if cached:
                    return cached
            except Exception as e:
                print(f"[CACHE] Failed to read from MongoDB cache: {e}")

        # Fallback to in-memory cache
        for scan in self._in_memory_scans:
            if scan.get("url") == url:
                return scan
        return None

    def get_history(self, limit: int = 50) -> list[dict]:
        """Fetch latest scan history from MongoDB or in-memory fallback."""
        if self.collection is not None:
            try:
                scans = list(self.collection.find().sort("scanned_at", -1).limit(limit))
                if scans:
                    return scans
            except Exception as e:
                print(f"[CACHE] Error fetching history from MongoDB: {e}")

        # Fallback to in-memory history sorted by scanned_at desc
        return sorted(self._in_memory_scans, key=lambda x: x.get("scanned_at", datetime.now(timezone.utc)), reverse=True)[:limit]

    def save_cached_scan(self, url: str, result: dict, ttl_hours: int = 720) -> None:
        """Save or update a scan result in the cache with a TTL."""
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=ttl_hours)

        doc = {
            "url": url,
            "result": result,
            "scanned_at": now,
            "expires_at": expires_at
        }

        # 1. Always save to in-memory fallback list
        self._in_memory_scans = [s for s in self._in_memory_scans if s.get("url") != url]
        self._in_memory_scans.insert(0, doc)
        if len(self._in_memory_scans) > 100:
            self._in_memory_scans = self._in_memory_scans[:100]

        # 2. Save to MongoDB if connected
        if self.collection is not None:
            self.ensure_indexes()
            try:
                self.collection.update_one(
                    {"url": url},
                    {"$set": doc},
                    upsert=True
                )
            except Exception as e:
                print(f"[CACHE] Failed to save to MongoDB cache: {e}")


url_cache_repository = UrlCacheRepository()
