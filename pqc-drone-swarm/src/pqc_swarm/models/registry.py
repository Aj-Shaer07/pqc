import threading
from typing import Dict, Optional, Set


class TrustRegistry:
    """Stores active trusted nodes and their corresponding public keys with thread safety."""

    def __init__(self, gs_public_key: Optional[bytes] = None):
        self._registry: Dict[str, bytes] = {}
        self._revocation_list: Set[str] = set()
        self.gs_public_key: Optional[bytes] = None
        self._lock = threading.RLock()
        if gs_public_key is not None:
            self.set_gs_public_key(gs_public_key)

    def set_gs_public_key(self, public_key: bytes) -> None:
        if not isinstance(public_key, bytes) or len(public_key) == 0:
            raise ValueError("Ground Station public key must be non-empty bytes.")
        with self._lock:
            self.gs_public_key = public_key

    def register_drone(self, drone_id: str, public_key: bytes) -> None:
        if not drone_id or not isinstance(drone_id, str):
            raise ValueError("drone_id must be a non-empty string.")
        if not isinstance(public_key, bytes) or len(public_key) == 0:
            raise ValueError("Drone public key must be non-empty bytes.")
        with self._lock:
            if drone_id in self._revocation_list:
                raise ValueError(f"Cannot register revoked drone ID: {drone_id}")
            self._registry[drone_id] = public_key

    def revoke_drone(self, drone_id: str) -> None:
        with self._lock:
            self._revocation_list.add(drone_id)
            self._registry.pop(drone_id, None)

    def is_trusted(self, drone_id: str) -> bool:
        with self._lock:
            return drone_id in self._registry and drone_id not in self._revocation_list

    def get_public_key(self, drone_id: str) -> Optional[bytes]:
        with self._lock:
            if drone_id in self._revocation_list:
                return None
            return self._registry.get(drone_id)

    @property
    def total_nodes(self) -> int:
        with self._lock:
            return len(self._registry)
