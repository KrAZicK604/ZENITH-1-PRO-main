"""Outward-rounded rational interval propagation; research authority NONE."""
from fractions import Fraction

from rational_oracle import MAX_STEPS, verify_recurrence

GRID = 2**1074
HALF = Fraction(1, 2)


def _image(rate, lower, upper):
    """Exact quadratic range on a trusted subinterval of [0, 1]."""
    left = rate * lower * (1 - lower)
    right = rate * upper * (1 - upper)
    low, high = min(left, right), max(left, right)
    if lower <= HALF <= upper:
        high = rate / 4
    low_units = low.numerator * GRID // low.denominator
    high_units = -(-(high.numerator * GRID) // high.denominator)
    return Fraction(low_units, GRID), Fraction(high_units, GRID)


def ideal_orbit_intervals(rate, initial_state, orbit_hex):
    """Return (status, reason, tuple of exact rational endpoint pairs).

    Enclose the ideal real orbit of the binary64 parameters. Observed states
    gate local validity; interval propagation never recenters on observations.
    PASS does not promise narrow intervals or independently verified science.
    """
    if type(orbit_hex) is not list or not 2 <= len(orbit_hex) <= MAX_STEPS + 1:
        return "FAIL", "invalid orbit length", ()
    orbit = orbit_hex.copy()
    status, reason = verify_recurrence(rate, initial_state, orbit)
    if status != "PASS":
        return status, reason, ()
    r = Fraction.from_float(float(rate))
    initial = Fraction.from_float(float(initial_state))
    intervals = [(initial, initial)]
    for _ in range(len(orbit) - 1):
        intervals.append(_image(r, *intervals[-1]))
    return "PASS", "ideal-orbit enclosure; interval width must be assessed", tuple(intervals)
