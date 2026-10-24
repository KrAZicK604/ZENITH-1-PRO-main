"""Deterministic logistic-map simulation with bounded inputs."""

from math import fsum, isfinite, log
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


def lyapunov_exponent(
    rate: float,
    initial_state: float,
    iterations: int,
    *,
    discard: int = 0,
) -> float:
    """Return a bounded finite-time Lyapunov exponent estimate.

    ``discard`` removes an initial transient from the estimate while keeping
    the total work bounded by :data:`MAX_ITERATIONS`. A zero derivative means
    complete local contraction and is represented by negative infinity.
    """

    if isinstance(discard, bool) or not isinstance(discard, int):
        raise TypeError("discard must be an integer")

    orbit = logistic_orbit(rate, initial_state, iterations)
    if not 0 <= discard < iterations:
        raise ValueError("discard must be between 0 and iterations - 1")

    rate = float(rate)
    logarithms: list[float] = []
    for state in orbit[discard:-1]:
        derivative_magnitude = abs(rate * (1.0 - 2.0 * state))
        if derivative_magnitude == 0.0:
            return float("-inf")
        logarithms.append(log(derivative_magnitude))

    return fsum(logarithms) / len(logarithms)
