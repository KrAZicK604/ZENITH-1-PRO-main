"""Deterministic logistic-map simulation with bounded inputs."""

from math import isfinite
from numbers import Real

MAX_ITERATIONS = 1_000


def logistic_orbit(
    rate: float,
    initial_state: float,
    iterations: int,
) -> list[float]:
    """Return the initial state followed by ``iterations`` logistic-map steps.

    The logistic map is defined as ``x[n + 1] = rate * x[n] * (1 - x[n])``.
    Inputs are deliberately restricted to the map's standard real interval so
    callers cannot request unbounded work or propagate non-finite values.
    """

    if isinstance(rate, bool) or not isinstance(rate, Real):
        raise TypeError("rate must be a real number")
    if isinstance(initial_state, bool) or not isinstance(initial_state, Real):
        raise TypeError("initial_state must be a real number")
    if isinstance(iterations, bool) or not isinstance(iterations, int):
        raise TypeError("iterations must be an integer")

    rate = float(rate)
    initial_state = float(initial_state)

    if not isfinite(rate) or not 0.0 <= rate <= 4.0:
        raise ValueError("rate must be finite and between 0 and 4")
    if not isfinite(initial_state) or not 0.0 < initial_state < 1.0:
        raise ValueError("initial_state must be finite and strictly between 0 and 1")
    if not 1 <= iterations <= MAX_ITERATIONS:
        raise ValueError(f"iterations must be between 1 and {MAX_ITERATIONS}")

    orbit = [initial_state]
    state = initial_state
    for _ in range(iterations):
        state = rate * state * (1.0 - state)
        orbit.append(state)

    return orbit
