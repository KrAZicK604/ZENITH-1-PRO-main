"""Independent exact-rational residual oracle for bounded logistic-map records.

This checks each observed step against the algebraic real recurrence, using
Fraction rather than the simulator's floating-point update implementation.
The allowance is a conservative IEEE-754 three-operation *local* roundoff
bound; it is not a bound on global shadowing or real-world physics.
"""
from __future__ import annotations

from fractions import Fraction
import math
import sys

MAX_STEPS = 1000
MAX_HEX_CHARS = 40
UNIT_ROUNDOFF = Fraction(1, 2**53)
GAMMA_3 = (3 * UNIT_ROUNDOFF) / (1 - 3 * UNIT_ROUNDOFF)
MIN_SUBNORMAL = Fraction(1, 2**1074)
ABSOLUTE_SLACK = 16 * MIN_SUBNORMAL


def verify_recurrence(rate, initial_state, orbit_hex):
    """Return (PASS|FAIL|ABSTAIN, reason) without calling logistic_orbit.

    Rate and initial state denote their *actual binary64* values, not decimal
    ideals. For a single step, the bound is gamma_3*abs(f(x)) + 16*2**(-1074),
    with f(x) evaluated by exact rational arithmetic. This assumes three
    correctly rounded elementary float operations under round-to-nearest.
    """
    if (sys.float_info.radix != 2 or sys.float_info.mant_dig != 53
            or sys.float_info.rounds != 1):
        return "ABSTAIN", "unsupported binary64 arithmetic assumptions"
    try:
        if type(rate) not in (int, float) or type(initial_state) not in (int, float):
            return "FAIL", "invalid scalar types"
        r, x0 = float(rate), float(initial_state)
        if (not math.isfinite(r) or not 0.0 <= r <= 4.0
                or not math.isfinite(x0) or not 0.0 < x0 < 1.0):
            return "FAIL", "parameters outside bounded logistic world"
        if (type(orbit_hex) is not list
                or not 2 <= len(orbit_hex) <= MAX_STEPS + 1):
            return "FAIL", "invalid orbit length"
        observed = []
        for raw in orbit_hex:
            if type(raw) is not str or len(raw) > MAX_HEX_CHARS:
                return "FAIL", "malformed orbit value"
            value = float.fromhex(raw)
            if (not math.isfinite(value) or value.hex() != raw
                    or not 0.0 <= value <= 1.0):
                return "FAIL", "noncanonical, nonfinite, or out-of-range state"
            observed.append(value)
        if observed[0].hex() != x0.hex():
            return "FAIL", "initial condition mismatch"
        r_exact = Fraction.from_float(r)
        for step, (prior, following) in enumerate(zip(observed, observed[1:]), 1):
            x_exact = Fraction.from_float(prior)
            exact_next = r_exact * x_exact * (1 - x_exact)
            residual = abs(Fraction.from_float(following) - exact_next)
            allowance = GAMMA_3 * abs(exact_next) + ABSOLUTE_SLACK
            if residual > allowance:
                return "FAIL", f"mathematical recurrence mismatch at step {step}"
        return "PASS", "exact-rational per-step residuals within binary64 bound"
    except (ValueError, TypeError, OverflowError, ZeroDivisionError, MemoryError):
        return "FAIL", "malformed or unbounded recurrence"
