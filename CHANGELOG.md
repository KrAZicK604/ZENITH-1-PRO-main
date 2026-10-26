## [Unreleased]

### Added
- Bounded finite-time Lyapunov analysis and logarithmic divergence diagnostics.
- Coordinated vulnerability-disclosure guidance.
- A reproducible release checklist for the first versioned release.

### Security
- Expanded Bandit to scan every repository Python file and strengthened the
  configuration tests to reject unpinned external GitHub Actions.

## [0.1.0] - Unreleased

### Added
- Bounded finite-time Lyapunov analysis and logarithmic divergence diagnostics.
- Deterministic logistic-map evolution with bounded inputs.
- Primary and shadow-orbit comparison with visualized divergence.
- Streamlit entry-point and boundary smoke tests.
- Strict configuration tests for the development container and Streamlit
  security settings.

### Security

- Streamlit `1.66.1` runtime enforcement while retaining the declared
  `streamlit>=1.61.1,<2` compatibility policy.
- Lock-managed Bandit `1.9.4` and pip-audit `2.10.1` checks.
- Immutable GitHub Action revisions, read-only workflow permissions, and
  disabled checkout credential persistence.
- Locked dependency validation through `uv lock --check` and `uv run --locked`.

`0.1.0` remains unreleased until the release checklist is completed against a
specific protected-branch commit.
