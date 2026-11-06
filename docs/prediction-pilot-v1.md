# Prediction-tolerance pilot v1

Research date: 2026-11-06. PAPER_ONLY / PROMOTION_BLOCKED /
productionAuthority NONE. Synthetic demonstration; customer validation NOT
PERFORMED. Depends on PR #61's interval oracle; keep this stacked PR in draft
until its dependency and its own independent reviews are complete.

Run from the repository root:

    uv run --locked --group security python prediction_pilot.py

The fixed demonstration returns JSON for a chaotic logistic trajectory and
a stable periodic control, each of 1,000 steps. It does not read customer
files, contact external services, write reports or change the application.
Reports retain exact rational error bounds and an explicit tolerance.
Status PASS means the assessment ran; inspect the final decision separately.

Given observed value z and a containing interval [a,b] for the ideal model
state, the absolute error lies between

    d_min = max(a-z, z-b, 0)
    d_max = max(|z-a|, |z-b|).

For tolerance t: d_max <= t proves WITHIN_TOLERANCE; d_min > t proves
OUTSIDE_TOLERANCE; all remaining cases ABSTAIN. Equality is permitted by the
tolerance. A large upper bound is not evidence of a large actual error.
These conclusions follow directly from distances to points in an interval,
conditional on the interval containing the ideal state. Counts include the
initial state at step zero. First-outside is the first demonstrated violation,
not necessarily the first actual violation; decisions may later recover.

The tolerance input is a bounded ASCII numerator/denominator string, with
at most nine digits each and value in (0,1]. The observed built-in list is
length-checked and snapshotted before validation. The underlying oracle
limits work to 1,001 states. The report stores only counts and the final
exact error bounds, not a growing history. No arbitrary-precision user
integers, exponent strings or customer file ingestion are supported.

## First customer validation protocol

Start with one prospective simulation user and a historical, non-production
case they are authorized to share. Before evaluating it, agree on:

- The model equations, parameter meanings and source/data provenance.
- A specific decision and its acceptable absolute-error tolerance.
- An independently checked reference and known acceptable/unacceptable cases.
- Runtime/memory budget, comparison baseline and blinded held-out cases.
- Success criteria: demonstrated violations, uncertainty/abstention rate,
  false alerts, missed violations against the reference and reviewer effort.

This logistic prototype cannot assess arbitrary customer simulations. Porting
to another model requires a justified containing oracle, input/resource
validation and independent domain review. Freeze those criteria before the
held-out evaluation. Record failures and abstentions, and separate blinded
evaluation from tuning. Pricing, savings, willingness to pay and commercial
fitness are unvalidated; do not describe these as measured customer outcomes.

Proposed pilot offer: evaluate one bounded simulation case and deliver an
auditable tolerance report identifying what can be concluded and where the
evidence requires abstention. Nothing is sent to a customer by this code.
