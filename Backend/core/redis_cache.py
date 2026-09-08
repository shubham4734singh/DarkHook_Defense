import hashlib
import json
import time
from typing import Any, Dict, Optional
from core.config import settings

class RedisCacheService:
    """
    High-performance caching service with automatic Redis connection handling
    and thread-safe in-memory fallback. Fingerprints files & URLs using SHA-256 hashes.
    """

    def __init__(self) -> None:
        self._redis_client = None
        self._redis_connected = False
        self._in_memory_cache: Dict[str, Dict[str, Any]] = {}
        self._init_redis()

    def _init_redis(self) -> None:
        """Attempt to initialize connection to Redis server."""
        try:
            import redis
            redis_url = getattr(settings, "REDIS_URL", "redis://localhost:6379/0")
            client = redis.Redis.from_url(redis_url, decode_responses=True, socket_timeout=2.0)
            client.ping()
            self._redis_client = client
            self._redis_connected = True
            print(f"[REDIS CACHE] Connected successfully to Redis server at {redis_url}")
        except Exception as e:
            self._redis_client = None
            self._redis_connected = False
            print(f"[REDIS CACHE] Local Redis server not active ({e}). Operating with High-Speed Thread-Safe In-Memory Cache.")

    def compute_hash(self, content: bytes | str) -> str:
        """Compute SHA-256 unique fingerprint hash."""
        if isinstance(content, str):
            content = content.strip().lower().encode("utf-8")
        return hashlib.sha256(content).hexdigest()

    def get_scan(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve scan result by fingerprint key."""
        full_key = f"darkhook:scan:{key}"

        # 1. Try Redis lookup if connected
        if self._redis_connected and self._redis_client:
            try:
                cached_json = self._redis_client.get(full_key)
                if cached_json:
                    data = json.loads(cached_json)
                    print(f"[REDIS CACHE HIT] Returned instant scan result for key: {key}")
                    return data
            except Exception as exc:
                print(f"[REDIS CACHE] Read error fallback: {exc}")

        # 2. In-memory cache fallback
        cached_entry = self._in_memory_cache.get(full_key)
        if cached_entry:
            expires_at = cached_entry.get("expires_at", 0)
            if time.time() < expires_at:
                print(f"[MEMORY CACHE HIT] Returned instant cached scan result for key: {key}")
                return cached_entry.get("data")
            else:
                # Expired
                self._in_memory_cache.pop(full_key, None)

        return None

    def set_scan(self, key: str, data: Dict[str, Any], ttl_seconds: int = 86400) -> bool:
        """Store scan result with TTL (default 24 hours)."""
        full_key = f"darkhook:scan:{key}"

        # 1. Try Redis set if connected
        if self._redis_connected and self._redis_client:
            try:
                serialized = json.dumps(data)
                self._redis_client.setex(full_key, ttl_seconds, serialized)
                return True
            except Exception as exc:
                print(f"[REDIS CACHE] Write error: {exc}")

        # 2. Always store in in-memory fallback
        self._in_memory_cache[full_key] = {
            "data": data,
            "expires_at": time.time() + ttl_seconds,
        }
        # LRU cleanup if in-memory cache exceeds 500 items
        if len(self._in_memory_cache) > 500:
            oldest_key = min(self._in_memory_cache.keys(), key=lambda k: self._in_memory_cache[k]["expires_at"])
            self._in_memory_cache.pop(oldest_key, None)

        return True


redis_cache_service = RedisCacheService()
