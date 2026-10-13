"""Temporal freshness and anti-replay protection filter for swarm messaging."""

import time
from typing import Dict, Optional, Tuple


class AntiReplayFilter:
    """
    Guards swarm nodes against replay and delay attacks.
    Enforces a strict sliding time window [now - window, now + window]
    and tracks message identifiers/nonces with automatic TTL pruning.
    """

    def __init__(self, window_seconds: float = 5.0):
        self.window_seconds = float(window_seconds)
        self._seen: Dict[str, float] = {}  # identifier -> message_timestamp
        self._replays_detected: int = 0
        self._expired_rejected: int = 0

    def check_freshness(
        self,
        identifier: str,
        timestamp: float,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """
        Check that the message timestamp is fresh and identifier has not been processed.
        Does not record identifier yet (prevents DoS on invalid signatures).
        """
        now = time.time() if current_time is None else float(current_time)

        # 1. Check for timestamps too far in the future
        if timestamp > now + self.window_seconds:
            self._expired_rejected += 1
            skew = timestamp - now
            return False, f"Timestamp in the future (skew: +{skew:.3f}s > {self.window_seconds}s)"

        # 2. Check for stale/expired messages
        if timestamp < now - self.window_seconds:
            self._expired_rejected += 1
            age = now - timestamp
            return False, f"Message expired / stale (age: {age:.3f}s > {self.window_seconds}s)"

        # 3. Check for replay attack
        if identifier in self._seen:
            self._replays_detected += 1
            return False, f"Replay detected: identifier '{identifier}' already processed"

        return True, "OK"

    def record_seen(
        self,
        identifier: str,
        timestamp: float,
        current_time: Optional[float] = None,
    ) -> None:
        """Record an authenticated identifier into seen cache."""
        now = time.time() if current_time is None else float(current_time)
        self._seen[identifier] = timestamp
        if len(self._seen) > 256:
            self.cleanup(current_time=now)

    def forget(self, identifier: str) -> None:
        """Remove identifier from seen cache (e.g. if signature validation subsequently fails)."""
        if identifier in self._seen:
            del self._seen[identifier]

    def validate_and_record(
        self,
        identifier: str,
        timestamp: float,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """
        Validate that the message is fresh and has not been seen before, recording it atomically.
        Returns (is_valid, reason).
        """
        is_fresh, reason = self.check_freshness(identifier, timestamp, current_time=current_time)
        if not is_fresh:
            return False, reason

        self.record_seen(identifier, timestamp, current_time=current_time)
        return True, "OK"

    def cleanup(self, current_time: Optional[float] = None) -> int:
        """
        Prune seen identifiers older than 2 * window_seconds.
        Returns the number of pruned entries.
        """
        now = time.time() if current_time is None else float(current_time)
        cutoff = now - (2 * self.window_seconds)
        to_remove = [k for k, ts in self._seen.items() if ts < cutoff]
        for k in to_remove:
            del self._seen[k]
        return len(to_remove)

    def reset(self) -> None:
        """Clear all cached identifiers."""
        self._seen.clear()
        self._replays_detected = 0
        self._expired_rejected = 0

    @property
    def tracked_count(self) -> int:
        """Number of currently tracked active identifiers."""
        return len(self._seen)

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "tracked_count": len(self._seen),
            "replays_detected": self._replays_detected,
            "expired_rejected": self._expired_rejected,
        }
