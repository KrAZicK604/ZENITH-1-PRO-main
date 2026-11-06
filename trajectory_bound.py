"""Bounded exact-rational global error envelope; research authority NONE."""
from fractions import Fraction

from rational_oracle import MAX_STEPS, verify_recurrence

# Round bounds upward to this fixed grid to prevent denominator growth.
GRID = 2**1074


def trajectory_error_bounds(rate, initial_state, orbit_hex):
    """Return (status, reason, tuple of rational absolute-error bounds).

    The reference is the ideal real logistic orbit with the exact binary64
    rate and initial state. PASS validates an enclosure, not its usefulness.
    A bound of one conveys only the invariant interval [0, 1]. Input limits
    and arithmetic-assumption checks are inherited from verify_recurrence.
    """
    # Validate and calculate from the same private snapshot. The public API
    # accepts a mutable list, so a later caller edit must not bypass checks.
    if type(orbit_hex) is not list or not 2 <= len(orbit_hex) <= MAX_STEPS + 1:
        return "FAIL", "invalid orbit length", ()
    orbit = orbit_hex.copy()
    status, reason = verify_recurrence(rate, initial_state, orbit)
    if status != "PASS":
        return status, reason, ()
    r = Fraction.from_float(float(rate))
    states = [Fraction.from_float(float.fromhex(x)) for x in orbit]
    bounds = [Fraction(0)]
    for prior, following in zip(states, states[1:]):
        residual = abs(following - r * prior * (1 - prior))
        propagated = min(Fraction(1), r * bounds[-1] + residual)
        numerator = propagated.numerator * GRID
        units = (numerator + propagated.denominator - 1) // propagated.denominator
        bounds.append(Fraction(units, GRID))
    return "PASS", "global absolute-error enclosure; unit bounds may be uninformative", tuple(bounds)
