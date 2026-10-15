"""Shamir's Secret Sharing over finite field GF(PRIME) using CSPRNG."""

import secrets
from typing import List, Tuple

# Mersenne prime 2^521 - 1, large enough to safely contain 256-bit symmetric keys
PRIME = 2**521 - 1


def validate_share(share: Tuple[int, int], prime: int = PRIME) -> bool:
    """Validate that a share coordinate (x, y) is strictly within valid field bounds."""
    if not isinstance(share, (tuple, list)) or len(share) != 2:
        return False
    x, y = share
    if not isinstance(x, int) or not isinstance(y, int):
        return False
    # x must be in [1, prime - 1] (x=0 exposes secret), y in [0, prime - 1]
    return 1 <= x < prime and 0 <= y < prime


def evaluate_polynomial(x: int, coefficients: List[int], prime: int = PRIME) -> int:
    """Evaluate polynomial f(x) = sum(c_p * x^p) mod prime using Horner's rule."""
    if not isinstance(x, int) or x < 0 or x >= prime:
        raise ValueError(f"Evaluation point x must be in field [0, {prime - 1}].")
    result = 0
    # Horner's method for numeric stability & efficiency
    for coeff in reversed(coefficients):
        result = (result * x + coeff) % prime
    return result


def generate_shares(
    secret: int, threshold: int, num_shares: int, prime: int = PRIME
) -> List[Tuple[int, int]]:
    """
    Split a secret into n shares with threshold k.
    Requires 1 <= k <= num_shares.
    Coefficients are chosen via cryptographically secure RNG (secrets.randbelow).
    """
    if threshold < 1:
        raise ValueError(f"Threshold must be at least 1 (got {threshold}).")
    if num_shares < threshold:
        raise ValueError(f"Total shares ({num_shares}) cannot be less than threshold ({threshold}).")
    if secret >= prime or secret < 0:
        raise ValueError(f"Secret must be in range [0, {prime - 1}].")

    # coefficients[0] is the secret constant term
    coefficients = [secret]
    # Intermediate coefficients uniformly from [0, prime - 1]
    for _ in range(threshold - 2):
        coefficients.append(secrets.randbelow(prime))
    # Highest degree coefficient a_{k-1} must be non-zero to guarantee degree k-1
    if threshold > 1:
        coefficients.append(secrets.randbelow(prime - 1) + 1)

    shares: List[Tuple[int, int]] = []
    for x in range(1, num_shares + 1):
        share_y = evaluate_polynomial(x, coefficients, prime)
        shares.append((x, share_y))

    return shares


def reconstruct_secret(shares: List[Tuple[int, int]], prime: int = PRIME) -> int:
    """
    Reconstruct secret from k or more shares using Lagrange interpolation at x=0.
    Enforces distinct x-coordinates and valid prime field bounds.
    """
    if not shares:
        raise ValueError("Cannot reconstruct secret from empty share list.")

    # Validate coordinate types and field bounds
    x_seen = set()
    for s in shares:
        if not validate_share(s, prime):
            raise ValueError(f"Invalid share coordinate: {s}. x must be in [1, {prime-1}], y in [0, {prime-1}].")
        if s[0] in x_seen:
            raise ValueError(f"Duplicate x-coordinate ({s[0]}) detected in share set.")
        x_seen.add(s[0])

    secret = 0
    for j, (xj, yj) in enumerate(shares):
        num = 1
        den = 1
        for m, (xm, _) in enumerate(shares):
            if m != j:
                num = (num * (-xm % prime)) % prime
                den = (den * ((xj - xm) % prime)) % prime

        lagrange_weight = (num * pow(den, -1, prime)) % prime
        secret = (secret + (yj * lagrange_weight) % prime) % prime

    return secret
