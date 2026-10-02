"""Shamir's Secret Sharing over finite field GF(PRIME) using CSPRNG."""

import secrets
from typing import List, Tuple

# Mersenne prime 2^521 - 1, large enough to safely contain 256-bit symmetric keys
PRIME = 2**521 - 1


def evaluate_polynomial(x: int, coefficients: List[int], prime: int = PRIME) -> int:
    """Evaluate polynomial f(x) = sum(c_p * x^p) mod prime using Horner's rule."""
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
    Requires k <= num_shares.
    Coefficients are chosen via cryptographically secure RNG (secrets.randbelow).
    """
    if threshold > num_shares:
        raise ValueError(f"Threshold ({threshold}) cannot exceed total shares ({num_shares}).")
    if secret >= prime or secret < 0:
        raise ValueError(f"Secret must be in range [0, {prime - 1}].")

    # coefficients[0] is the secret
    coefficients = [secret]
    for _ in range(threshold - 1):
        coefficients.append(secrets.randbelow(prime - 1) + 1)

    shares: List[Tuple[int, int]] = []
    for x in range(1, num_shares + 1):
        share_y = evaluate_polynomial(x, coefficients, prime)
        shares.append((x, share_y))

    return shares


def reconstruct_secret(shares: List[Tuple[int, int]], prime: int = PRIME) -> int:
    """Reconstruct secret from k or more shares using Lagrange interpolation at x=0."""
    if not shares:
        raise ValueError("Cannot reconstruct secret from empty share list.")

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
