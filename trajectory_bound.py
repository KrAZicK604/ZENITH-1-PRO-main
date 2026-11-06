"""Bounded exact-rational global error envelope; research authority NONE."""
from fractions import Fraction

from rational_oracle import verify_recurrence

# Round bounds upward to this fixed grid to prevent denominator growth.
GRID = 2**1074


def trajectory_error_bounds(rate, initial_state, orbit_hex):
    """Return (status, reason, tuple of rational absolute-error bounds).

    The reference is the ideal real logistic orbit with the exact binary64
    rate and initial state. PASS validates an enclosure, not its usefulness.
    A bound of one conveys only the invariant interval [0, 1]. Input limits
    and arithmetic-assumption checks are inherited from verify_recurrence.
    """
    status, reason = verify_recurrence(rate, initial_state, orbit_hex)
    if status != "PASS":
        return status, reason, ()
    r = Fraction.from_float(float(rate))
    states = [Fraction.from_float(float.fromhex(x)) for x in orbit_hex]
    bounds = [Fraction(0)]
    for prior, following in zip(states, states[1:]):
        residual = abs(following - r * prior * (1 - prior))
        propagated = min(Fraction(1), r * bounds[-1] + residual)
        numerator = propagated.numerator * GRID
        units = (numerator + propagated.denominator - 1) // propagated.denominator
        bounds.append(Fraction(units, GRID))
    return "PASS", "global absolute-error enclosure; unit bounds may be uninformative", tuple(bounds)
