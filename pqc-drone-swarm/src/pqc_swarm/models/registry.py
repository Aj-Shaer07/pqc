import threading
from typing import Dict, Optional, Set


class TrustRegistry:
    """Stores active trusted nodes, Ground Station operators, and revocation lists with thread safety."""

    def __init__(self, gs_public_key: Optional[bytes] = None, min_gs_signatures: int = 1):
        self._registry: Dict[str, bytes] = {}
        self._revocation_list: Set[str] = set()
        self.gs_public_key: Optional[bytes] = None
        self.gs_operators: Dict[str, bytes] = {}
        self.min_gs_signatures: int = max(1, min_gs_signatures)
        self._lock = threading.RLock()
        if gs_public_key is not None:
            self.set_gs_public_key(gs_public_key)

    def set_gs_public_key(self, public_key: bytes) -> None:
        if not isinstance(public_key, bytes) or len(public_key) == 0:
            raise ValueError("Ground Station public key must be non-empty bytes.")
        with self._lock:
            self.gs_public_key = public_key
            self.gs_operators["GS_PRIMARY"] = public_key

    def register_gs_operator(self, operator_id: str, public_key: bytes) -> None:
        if not operator_id or not isinstance(operator_id, str):
            raise ValueError("operator_id must be a non-empty string.")
        if not isinstance(public_key, bytes) or len(public_key) == 0:
            raise ValueError("Operator public key must be non-empty bytes.")
        with self._lock:
            self.gs_operators[operator_id] = public_key
            if not self.gs_public_key:
                self.gs_public_key = public_key

    def get_gs_operator_key(self, operator_id: str) -> Optional[bytes]:
        with self._lock:
            return self.gs_operators.get(operator_id)

    def set_min_gs_signatures(self, min_sigs: int) -> None:
        if min_sigs < 1:
            raise ValueError("Minimum GS operator signatures must be >= 1.")
        with self._lock:
            self.min_gs_signatures = min_sigs

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

    def is_revoked(self, drone_id: str) -> bool:
        with self._lock:
            return drone_id in self._revocation_list

    def get_public_key(self, drone_id: str) -> Optional[bytes]:
        with self._lock:
            if drone_id in self._revocation_list:
                return None
            return self._registry.get(drone_id)

    def get_revocation_list(self) -> Set[str]:
        with self._lock:
            return set(self._revocation_list)

    @property
    def total_nodes(self) -> int:
        with self._lock:
            return len(self._registry)
