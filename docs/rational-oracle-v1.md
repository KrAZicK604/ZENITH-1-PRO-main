# Exact-rational logistic recurrence oracle — research v1

Research realm: numerical-dynamics mathematical verification
Research date: 2026-11-02 (host date, not an attested clock)
Status: PAPER_ONLY / PROMOTION_BLOCKED / productionAuthority NONE

## Question and method

Does each reported finite-precision point satisfy the mathematical logistic
recurrence independently of the Python simulator and its replay function?

The verifier converts each recorded binary64 float into an exact rational
number via Fraction.from_float and independently evaluates

    f_r(x) = r * x * (1 - x)

using exact integer-ratio arithmetic, not logistic_orbit. For each pair of
consecutive *reported* states x_n and x_(n+1), it measures exactly

    residual_n = |Fraction(x_(n+1)) - f_r(Fraction(x_n))|.

Under the assumptions of binary64 round-to-nearest and the simulator's two
multiplications plus one subtraction, a conservative local-operation bound is

    u = 2^-53
    gamma_3 = 3*u / (1 - 3*u)
    allowable_n = gamma_3*|f_r(x_n)| + 16*2^-1074.

Values violating this bound are rejected. The additive term conservatively
allows subnormal-rounding effects. The verifier also rejects noncanonical float
hex, NaN/infinity, altered initial conditions, out-of-range states, oversized
input, and unsupported float arithmetic (ABSTAIN).

The accepted numerical parameters are the exact rational values represented
by the binary64 inputs. This does not certify the ideal mathematical behavior
of the decimal string "3.9", whose binary64 representation differs slightly.

## Adversarial controls and reproducibility

Run from the stacked candidate branch:

    uv run --locked --group security python -m unittest discover -s tests -v
    uv run --locked --group security bandit -q -r . -x ./.venv,./.git

The deterministic test suite derives 40 bounded input pairs from SHA-256 of
ASCII labels `logistic-fraction-v1:20261102:<case>` and runs 1,000 steps
per input, without pseudo-random-generator exemptions. It also includes
long-underflow cases, nonfinite and noncanonical
inputs, modified-state attacks, and a patched local simulator that emits
self-consistent but mathematically incorrect replay data.

Independent local preflight: 40/40 SHA-256-derived trajectories and 40,000
step checks passed. An earlier deliberately modified step was rejected.
This preflight was run outside the repository integration and is not CI.

## What a PASS does and does not show

PASS means the observed states satisfy a **per-step local residual bound** and
the existing deterministic replay also matches. It does not bound accumulated
trajectory error against a real-number orbit over 1,000 chaotic iterations.
For example, sensitive dependence can amplify small local errors exponentially.
It also does not authenticate the sender, host clock, checkout, verifier binary,
GitHub identity, or an external physical measurement.

The rational oracle is a distinct numerical implementation, **not an
independently developed external scientific evaluator**. Its roundoff model
assumes conventional binary64 operations and is not a validated guarantee
for arbitrary alternate runtimes or nonstandard floating-point environments.
A malicious actor able to rewrite all source and evidence may also replace
the oracle. No new mathematical discovery or production authorization is claimed.
