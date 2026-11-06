# Fixed exact-reference pilot evaluation

2026-11-06 research date; host clock UNATTESTED. PAPER_ONLY /
ABSTAIN / PROMOTION_BLOCKED / productionAuthority NONE.

Run `uv run --locked --group security python pilot_evaluation.py`.
Sixteen fixed SHA-256-derived worlds each run eight steps. Separately
iterated exact rationals supply reference states. This short budget is
essential: ideal logistic iterates can double denominator bit-length per
step; the evaluator has no user-controlled iteration/seed/count input.
Each ideal state is checked against the containing interval before scoring.

Two predeclared thresholds (10^-6 and 2^-55) and two arms (native containing
interval and deliberately widened outward 1/256 grid) produce four reports.
The tiny threshold exercises demonstrated violations on short exact orbits;
it is an internal research constant, not a tolerance accepted by the public
pilot API. The widened arm tests information loss rather than a competing
solver. States include step zero, giving 144 per report. Reports are paired,
correlated views of the same worlds; do not count them as independent trials.

Raw counts distinguish true alerts, false alerts, missed violations and true
within-tolerance decisions. Abstentions retain their reference truth label:
an undecided actual violation is not silently counted as a correct negative.
Coverage is the exact fraction of states receiving a definite decision.
No confidence intervals or population reliability claims are inferred from
these fixed, correlated synthetic samples. PASS means scoring completed,
not zero errors; inspect counts. Tests deliberately replace the classifier
with always-alert and always-accept controls to demonstrate metric sensitivity.

The classifier and interval implementation are shared with the pilot, while
the reference uses direct exact polynomial expansion. This checks numerical
agreement; it is not independently developed external validation. Worlds
are public and fixed, not blinded held-out customer cases. No customer or
commercial fitness is established. Follow docs/prediction-pilot-v1.md before
collecting authorized historical customer data or making commercial claims.

This branch is stacked on PR #61's current research head, which includes
merged PR #62. Main, workflows, dependencies, application behavior and
production authority are unchanged. Fresh main-target checks and qualified
review are still required before advancement.
