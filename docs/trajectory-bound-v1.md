# Global trajectory error envelope — research v1

Research realm: numerical dynamics / accumulated uncertainty.
Research date: 2026-11-06; host clock UNATTESTED.
PAPER_ONLY / ABSTAIN / PROMOTION_BLOCKED / productionAuthority NONE.

`trajectory_error_bounds` first requires the existing exact-rational local
recurrence oracle to PASS. It then bounds distance to the ideal real orbit
starting from the exact binary64 initial value with the exact binary64 rate.
It does not certify decimal ideals or an external physical system.

Let observed states be z_n, ideal states x_n, and exact residuals
d_n = |z_(n+1) - r*z_n*(1-z_n)|. Both sequences stay in [0,1]: observed
values are validated and the ideal map preserves the interval for 0 <= r <= 4.
For a,b in that interval,

    |f(a)-f(b)| = r*|a-b|*|1-a-b| <= r*|a-b|.

Starting at E_0=0, the triangle inequality therefore gives

    |z_(n+1)-x_(n+1)| <= min(1, r*E_n + d_n).

The implementation rounds this expression UP to a multiple of 2^-1074,
using integer arithmetic only. Induction proves each returned bound contains
the true error. Upward rounding preserves that conclusion and limits each
stored denominator to 2^1074; it does not round an enclosure downward.
At most 1,001 states are accepted. Exact residual denominators have fixed
binary64-derived size, so repeated propagation cannot grow rational
denominators without bound. The existing bounded-input limits still apply.

The API accepts only a built-in list within the length budget before making
a shallow private snapshot. The validator checks that snapshot, including
its length and immutable string elements; calculation uses the same copy.
Edits to the caller's list after validation therefore cannot change the
calculation or expand its work. Tests inject deterministic edits between
validation and calculation. This is not process isolation or a guarantee
against arbitrary interpreter/memory tampering or concurrent resource use.

PASS means an enclosure was constructed. A bound of one is uninformative
beyond the invariant interval, and is expected after enough chaotic steps.
The bound is conservative and need not increase monotonically: contraction
can reduce it. No shadowing, precision of long chaotic trajectories, new
discovery, authenticated provenance, or production authority is claimed.

Validation compares short trajectories against separately iterated exact
rational ideal orbits, checks an exact fixed point, full-budget contraction
and chaotic saturation, malformed inputs, and arithmetic ABSTAIN. These are
assistant-developed tests, not independent scientific review. The new API is
research-only and is not wired into application or evidence acceptance.
