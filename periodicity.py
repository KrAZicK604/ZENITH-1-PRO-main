"""Deterministic period estimation for bounded orbits."""

from math import isfinite
from numbers import Real
from typing import Sequence


def estimate_period(
    orbit: Sequence[float],
    *,
    tolerance: float = 1e-6,
    max_period: int = 64,
) -> int | None:
    """Return the shortest repeating cycle length in a finite orbit.

    A value of ``1`` indicates a fixed point; ``None`` means no stable short cycle
    was detected within the bounded search window.
    """

    if isinstance(orbit, (str, bytes)):
        raise TypeError("orbit must be a sequence of real values")
    if not orbit:
        raise ValueError("orbit must not be empty")
    if isinstance(tolerance, bool) or not isinstance(tolerance, Real):
        raise TypeError("tolerance must be a real number")
    if isinstance(max_period, bool) or not isinstance(max_period, int):
        raise TypeError("max_period must be an integer")

    tolerance = float(tolerance)
    max_period = int(max_period)
    if not isfinite(tolerance) or tolerance <= 0.0:
        raise ValueError("tolerance must be finite and greater than zero")
    if max_period < 1 or max_period > len(orbit):
        raise ValueError("max_period must be between 1 and len(orbit)")

    window = list(orbit)
    for period in range(1, max_period + 1):
        cycle = window[-period:]
        if len(cycle) < period:
            continue
        if all(abs(window[index] - cycle[(index - len(window)) % period]) <= tolerance for index in range(len(window))):
            return period

    return None
