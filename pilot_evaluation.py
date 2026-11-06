"""Fixed synthetic exact-reference evaluation, not customer validation."""
from fractions import Fraction as Q
import hashlib
import json

from interval_oracle import ideal_orbit_intervals
from logistic_map import logistic_orbit
from prediction_pilot import _classify


def _record(counts, decision, actual_outside):
    """Accumulate raw outcomes without hiding undecided violations."""
    if decision == "ABSTAIN":
        key = "abstain_outside" if actual_outside else "abstain_within"
    elif decision == "OUTSIDE_TOLERANCE":
        key = "true_alert" if actual_outside else "false_alert"
    elif decision == "WITHIN_TOLERANCE":
        key = "missed_violation" if actual_outside else "true_within"
    else:
        raise ValueError("unknown decision")
    counts[key] += 1


def _widen(lower, upper):
    """Experimental uncertainty control: outward rounding to a coarse grid."""
    grid = 256
    lo = (lower.numerator * grid) // lower.denominator
    hi = -(-(upper.numerator * grid) // upper.denominator)
    return Q(lo, grid), Q(hi, grid)


def evaluate():
    """16 fixed worlds, 8 steps each, exact references, two precision arms.

    No supplied data/seed/budget can expand work. Thresholds are trusted
    research constants; the tiny threshold is not the public pilot API.
    """
    reports = []
    for tolerance in (Q(1, 10**6), Q(1, 2**55)):
        for arm in ("native_interval", "deliberately_widened_interval"):
            counts = dict.fromkeys(("true_alert", "false_alert", "missed_violation",
                                    "true_within", "abstain_outside", "abstain_within"), 0)
            for case in range(16):
                digest = hashlib.sha256(f"zenith-pilot-evaluation-v1:{case}".encode("ascii")).digest()
                rate = float(Q(1, 2) + Q(7, 2)*Q(int.from_bytes(digest[:2], "big"), 65536))
                initial = float(Q(1, 4) + Q(1, 2)*Q(int.from_bytes(digest[2:4], "big"), 65536))
                states = logistic_orbit(rate, initial, 8)
                status, reason, intervals = ideal_orbit_intervals(
                    rate, initial, [z.hex() for z in states]
                )
                if status != "PASS":
                    return {"status": status, "reason": reason, "results": []}
                exact, r = Q.from_float(initial), Q.from_float(rate)
                for observed, (lower, upper) in zip(states, intervals):
                    if not lower <= exact <= upper:
                        return {"status": "FAIL", "reason": "reference outside enclosure", "results": []}
                    if arm == "deliberately_widened_interval":
                        lower, upper = _widen(lower, upper)
                    z = Q.from_float(observed)
                    decision = _classify(z, lower, upper, tolerance)[0]
                    _record(counts, decision, abs(z-exact) > tolerance)
                    # Separate exact polynomial expansion, no interval propagation.
                    exact = r*exact - r*exact*exact
            total = sum(counts.values())
            abstentions = counts["abstain_outside"] + counts["abstain_within"]
            reports.append({"tolerance": str(tolerance), "arm": arm,
                            "counts": counts, "state_count": total,
                            "decision_coverage": str(Q(total-abstentions, total))})
    return {"status": "PASS", "scope": "FIXED_SYNTHETIC_EXACT_REFERENCE",
            "customer_validation": "NOT_PERFORMED", "independent_review": "NOT_PERFORMED",
            "mode": "PAPER_ONLY", "promotion": "PROMOTION_BLOCKED",
            "productionAuthority": "NONE", "worlds": 16, "steps_per_world": 8,
            "results": reports}


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2, sort_keys=True))
