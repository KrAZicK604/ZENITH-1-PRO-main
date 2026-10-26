# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and version numbers follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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
- Immutable GitHub Action revisions, read-only workflow permissions, and
  disabled checkout credential persistence.
- Locked dependency validation through `uv lock --check` and `uv run --locked`.

`0.1.0` remains unreleased until the release checklist is completed against a
specific protected-branch commit.
