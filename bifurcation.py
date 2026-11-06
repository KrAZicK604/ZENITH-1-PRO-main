"""Bounded parameter sweeps for logistic-map bifurcation diagrams."""

from math import isfinite
from numbers import Real

from logistic_map import logistic_orbit

MAX_RATE_SAMPLES = 100
MAX_ITERATIONS = 1_000
MAX_POINTS_PER_RATE = 100


def bifurcation_points(
    rate_min: float,
    rate_max: float,
    *,
    rate_samples: int = 80,
    iterations: int = 400,
    discard: int = 300,
    points_per_rate: int = 50,
) -> list[tuple[float, float]]:
    """Return bounded ``(rate, state)`` samples for a logistic-map sweep.

    Each rate is simulated independently from the same initial state. The
    returned states are the final ``points_per_rate`` values after discarding
    the requested transient. Total work is capped at 100,000 map iterations
    and output is capped at 10,000 points.
    """

    for name, value in (("rate_min", rate_min), ("rate_max", rate_max)):
        if isinstance(value, bool) or not isinstance(value, Real):
            raise TypeError(f"{name} must be a real number")
        if not isfinite(float(value)) or not 0.0 <= float(value) <= 4.0:
            raise ValueError(f"{name} must be finite and between 0 and 4")

    rate_min = float(rate_min)
    rate_max = float(rate_max)
    if rate_min >= rate_max:
        raise ValueError("rate_min must be less than rate_max")

    integer_options = (
        ("rate_samples", rate_samples, 2, MAX_RATE_SAMPLES),
        ("iterations", iterations, 2, MAX_ITERATIONS),
        ("points_per_rate", points_per_rate, 1, MAX_POINTS_PER_RATE),
    )
    for name, value, minimum, maximum in integer_options:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")
        if not minimum <= value <= maximum:
            raise ValueError(f"{name} must be between {minimum} and {maximum}")

    if isinstance(discard, bool) or not isinstance(discard, int):
        raise TypeError("discard must be an integer")
    if not 0 <= discard < iterations:
        raise ValueError("discard must be between 0 and iterations - 1")

    initial_state = 0.5
    points: list[tuple[float, float]] = []
    for sample_index in range(rate_samples):
        rate = rate_min + (rate_max - rate_min) * sample_index / (rate_samples - 1)
        orbit = logistic_orbit(rate, initial_state, iterations)
        retained = orbit[discard:]
        for state in retained[-points_per_rate:]:
            points.append((rate, state))

    return points
