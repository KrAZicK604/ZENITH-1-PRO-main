"""Synthetic decision-tolerance pilot; no customer or production authority."""
from fractions import Fraction
import json
import re

from interval_oracle import ideal_orbit_intervals
from logistic_map import logistic_orbit
from rational_oracle import MAX_STEPS


def _classify(observed, lower, upper, tolerance):
    """Trusted exact rationals: return decision and error interval."""
    minimum = max(lower - observed, observed - upper, Fraction(0))
    maximum = max(abs(observed - lower), abs(observed - upper))
    if maximum <= tolerance:
        decision = "WITHIN_TOLERANCE"
    elif minimum > tolerance:
        decision = "OUTSIDE_TOLERANCE"
    else:
        decision = "ABSTAIN"
    return decision, minimum, maximum


def assess_prediction(rate, initial_state, orbit_hex, tolerance="1/1000000"):
    """Return a bounded summary; tolerance is a small positive rational string.

    The report is conditional on the model and the interval oracle's trusted
    arithmetic/source assumptions. OUTSIDE requires a lower error bound above
    tolerance; an upper bound above tolerance alone only supports ABSTAIN.
    """
    if (type(tolerance) is not str or len(tolerance) > 19
            or re.fullmatch(r"[0-9]{1,9}/[0-9]{1,9}", tolerance) is None):
        return {"status": "FAIL", "reason": "invalid tolerance"}
    numerator, denominator = map(int, tolerance.split("/"))
    if denominator == 0 or not 0 < numerator <= denominator:
        return {"status": "FAIL", "reason": "tolerance must be in (0, 1]"}
    threshold = Fraction(numerator, denominator)
    if type(orbit_hex) is not list or not 2 <= len(orbit_hex) <= MAX_STEPS + 1:
        return {"status": "FAIL", "reason": "invalid orbit length"}
    orbit = orbit_hex.copy()
    status, reason, intervals = ideal_orbit_intervals(rate, initial_state, orbit)
    if status != "PASS":
        return {"status": status, "reason": reason}
    counts = {key: 0 for key in ("WITHIN_TOLERANCE", "OUTSIDE_TOLERANCE", "ABSTAIN")}
    first_abstain = first_outside = None
    final = None
    for step, (raw, (lower, upper)) in enumerate(zip(orbit, intervals)):
        decision, minimum, maximum = _classify(
            Fraction.from_float(float.fromhex(raw)), lower, upper, threshold
        )
        counts[decision] += 1
        if decision == "ABSTAIN" and first_abstain is None:
            first_abstain = step
        if decision == "OUTSIDE_TOLERANCE" and first_outside is None:
            first_outside = step
        final = {"decision": decision, "absolute_error_lower": str(minimum),
                 "absolute_error_upper": str(maximum)}
    return {"status": "PASS", "scope": "SYNTHETIC_MODEL_ONLY",
            "productionAuthority": "NONE", "promotion": "PROMOTION_BLOCKED",
            "mode": "PAPER_ONLY", "tolerance": str(threshold),
            "state_count": len(orbit), "counts": counts,
            "first_abstain_step": first_abstain, "first_outside_step": first_outside,
            "final": final}


def demonstration():
    """Two fixed synthetic cases; no customer data, external calls or writes."""
    cases = []
    for name, rate, initial in (("chaotic_float_drift", 3.9, 0.2),
                                ("stable_periodic_control", 3.2, 0.2)):
        orbit = [x.hex() for x in logistic_orbit(rate, initial, 1000)]
        cases.append({"case": name, "rate_hex": rate.hex(),
                      "initial_hex": initial.hex(),
                      "assessment": assess_prediction(rate, initial, orbit)})
    return {"pilot": "ZENITH synthetic prediction-tolerance pilot v1",
            "customer_validation": "NOT_PERFORMED", "cases": cases}


if __name__ == "__main__":
    print(json.dumps(demonstration(), sort_keys=True, indent=2))
