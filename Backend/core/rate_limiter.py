from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock
from core.config import settings
from core.exceptions import RateLimitException

class InMemoryRateLimiter:
    """Thread-safe rate limiter storing timestamps in-memory."""
    def __init__(self) -> None:
        self._store: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def enforce(self, bucket: str, client_ip: str, identifier: str, limit: int) -> None:
        """
        Enforce rate limits.
        Raises RateLimitException if the limit is exceeded.
        """
        now_ts = datetime.now(timezone.utc).timestamp()
        key = f"{bucket}:{client_ip}:{identifier}"
        cutoff = now_ts - settings.AUTH_RATE_LIMIT_WINDOW_SECONDS

        with self._lock:
            timestamps = self._store[key]
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()

            if len(timestamps) >= limit:
                raise RateLimitException()

            timestamps.append(now_ts)

# Global instance of the rate limiter
rate_limiter = InMemoryRateLimiter()
