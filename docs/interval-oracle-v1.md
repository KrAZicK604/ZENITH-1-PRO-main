# Ideal-orbit interval enclosure — research v1

Realm: numerical dynamics / validated interval propagation.
Research date: 2026-11-06; host clock UNATTESTED.
PAPER_ONLY / ABSTAIN / PROMOTION_BLOCKED / productionAuthority NONE.

The global Lipschitz bound uses the worst derivative on the entire invariant
interval. This separate API instead propagates a containing interval for the
ideal real orbit, starting from the exact binary64 initial value and rate.
It does not propagate a decimal ideal or estimate physical measurement error.

For f(x)=r*x*(1-x), r in [0,4], the minimum on [a,b] is the smaller endpoint
image. The maximum is the larger endpoint image unless [a,b] includes 1/2;
then the maximum is r/4. Ignoring this interior critical point is unsound.
`_image` computes those extrema with rational arithmetic, then rounds the
lower endpoint DOWN and upper endpoint UP onto the 2^-1074 grid. Endpoints
remain in [0,1]. By induction each interval contains the corresponding ideal
real state. Grid rounding bounds denominator growth across 1,000 steps.

The API snapshots and validates at most 1,001 observed states using the local
recurrence oracle, then propagates ideal-state intervals independently of
the observations. It never intersects with, or recenters on, the observed
trajectory: either action would require another proof. Private `_image`
assumes trusted rational inputs in the stated domain; it is not a public
untrusted-input endpoint. The public API inherits arithmetic ABSTAIN checks.

To bound the error of an observed state z against an interval [a,b], use
max(|z-a|, |z-b|), evaluated exactly. A narrow interval alone does not prove
that an arbitrary observation lies inside it. Wide intervals are valid but
uninformative. Improvement over the Lipschitz bound is case-dependent;
chaotic trajectories can still lose useful precision. No guarantee of a
longer horizon for every input, global shadowing, physical-law discovery,
authenticated provenance or independent scientific review is claimed.

Tests cover exact ideal orbits, critical-point inclusion, outward rounding
at subnormal scale, a full-budget exact fixed point, deterministic caller
mutation and malformed inputs. Source, interpreter and memory are trusted;
these checks are not process isolation. Application and evidence acceptance
remain unchanged. PR #60 separately repairs snapshot handling in the older
global-bound API; this API does not depend on that PR's implementation.

## Deterministic comparison, not a universal horizon claim

For binary64 r=3.9 and x0=0.2, 1,000 steps: the binary64 observed final
state is approximately 0.9625366845774258, while the ideal-orbit enclosure
is near 0.4050761232136955 with width about 3.34e-105. These decimal displays
are rounded illustrations; the API retains exact rational endpoints. The
test checks an exact separation greater than 1/2 and width below 10^-100.

With absolute-error threshold 10^-6, the global Lipschitz error bound first
exceeds the threshold at step 18; the observed-to-interval error enclosure
first exceeds it at step 41. For r=3.2, x0=0.2, the corresponding results
are step 21 versus no exceedance through step 1,000. These are two synthetic
cases, not a benchmark establishing a universal improvement. The observed
orbit is gated by the same local-roundoff checks in both comparisons.

There is no paradox in a narrow ideal interval far from the observed orbit:
interval propagation uses a roughly 1,074-bit grid rather than 53-bit float
updates. This spends more precision/computation. It does not make chaotic
prediction stable, prove the observed float simulation accurate, or show an
equal-compute algorithmic advantage. Reproduce with the interval test suite
and evaluate max(|z-a|, |z-b|) exactly for each reported state and interval.
